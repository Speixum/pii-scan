"""命令行入口：`scan` / `mask` / `rules list` / `rules check`。

控制台只用 ASCII 表格符号；打印前统一把 stdout 重配为 UTF-8，避免 Windows
控制台在 GBK 代码页下抛 UnicodeEncodeError。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .classify import CONFIDENCE_ORDER
from .mask import ACTIONS, MaskReport, mask_file
from .report import FORMATS, ascii_grid, render, write_report
from .rules import RuleError, RuleSet, load_rules
from .scanner import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, MIN_OVERLAP, ScanResult, Scanner

__all__ = ["build_parser", "main"]

#: 退出码：0 成功；1 参数/IO/规则错误；2 命中达到 --fail-on 阈值。
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FOUND = 2

FAIL_ON_CHOICES: tuple[str, ...] = ("none", "medium", "high")


def _configure_stream(stream: object) -> None:
    """把标准流重配为 UTF-8（Windows 控制台安全）；不支持时静默跳过。"""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        return


def _say(text: str = "") -> None:
    print(text)


def _fail(message: str) -> int:
    print("piiscan: error: " + message, file=sys.stderr)
    return EXIT_ERROR


def _load_ruleset(path: str | None) -> RuleSet:
    return load_rules(path)


def _build_scanner(args: argparse.Namespace, ruleset: RuleSet) -> Scanner:
    return Scanner(
        ruleset,
        chunk_size=args.chunk_size,
        overlap=args.overlap,
        context_window=args.context_window,
        min_confidence=args.min_confidence,
        types=args.types,
    )


def _read_input(target: str) -> tuple[str, str]:
    """读取扫描输入，返回 (文本, 展示用 source)。

    异常:
        OSError: 文件不可读。
    """
    if target == "-":
        data = sys.stdin.buffer.read()
        return data.decode("utf-8", "surrogateescape"), "<stdin>"
    path = Path(target)
    return path.read_text(encoding="utf-8", errors="surrogateescape", newline=""), str(path)


def _threshold_exit(result: ScanResult, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    return EXIT_FOUND if result.count(fail_on) > 0 else EXIT_OK


# ---------------------------------------------------------------- subcommands


def _cmd_scan(args: argparse.Namespace) -> int:
    ruleset = _load_ruleset(args.rules)
    scanner = _build_scanner(args, ruleset)
    if args.target == "-":
        text, source = _read_input("-")
        result = scanner.scan_text(text, source=source)
    else:
        try:
            result = scanner.scan_file(args.target)
        except OSError as error:
            return _fail("cannot read input: " + str(error))
    if args.out:
        try:
            path = write_report(result, args.out, args.format)
        except OSError as error:
            return _fail("cannot write report: " + str(error))
        _say("report written: " + str(path) + " (" + args.format + ")")
    else:
        _say(render(result, args.format))
    return _threshold_exit(result, args.fail_on)


def _load_policy(path: str | None) -> dict[str, str] | None:
    if not path:
        return None
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuleError("policy must be a JSON object")
    policy: dict[str, str] = {}
    for key, value in document.items():
        if not isinstance(value, str) or value not in ACTIONS:
            raise RuleError("policy action must be one of mask/hash/redact: " + str(key))
        policy[str(key)] = value
    return policy


def _default_target(source: Path) -> Path:
    suffix = source.suffix
    return source.with_name(source.stem + ".masked" + suffix) if suffix else source.with_name(source.name + ".masked")


def _cmd_mask(args: argparse.Namespace) -> int:
    ruleset = _load_ruleset(args.rules)
    scanner = _build_scanner(args, ruleset)
    try:
        policy = _load_policy(args.policy)
    except (OSError, ValueError) as error:
        return _fail("cannot load policy: " + str(error))
    if args.action:
        policy = dict(policy or {})
        policy["*"] = args.action
    try:
        source = Path(args.target)
        if not source.is_file():
            return _fail("input is not a file: " + args.target)
        target = Path(args.out) if args.out else _default_target(source)
        if target.resolve() == source.resolve() and not args.in_place:
            return _fail("output would overwrite input; pass --in-place or choose another --out")
        report: MaskReport = mask_file(
            source,
            None if args.dry_run else target,
            scanner=scanner,
            policy=policy,
            head=args.head,
            tail=args.tail,
            salt=args.salt,
            keep_prefix=args.keep_prefix,
            redact_mode=args.redact_mode,
        )
    except OSError as error:
        return _fail("cannot mask file: " + str(error))
    _say("mask summary")
    _say("source: " + report.source)
    _say("target: " + (report.target or "(dry-run, nothing written)"))
    _say(
        "total: "
        + str(report.total)
        + " | replaced: "
        + str(report.replaced)
        + " | skipped: "
        + str(report.skipped)
    )
    if report.by_action:
        _say("by_action: " + ", ".join(name + "=" + str(count) for name, count in report.by_action.items()))
    return EXIT_OK


def _cmd_rules_list(args: argparse.Namespace) -> int:
    ruleset = _load_ruleset(args.rules)
    if args.format == "json":
        payload = ruleset.meta()
        payload["rules"] = [
            {
                "name": rule.name,
                "type": rule.type,
                "weight": rule.weight,
                "level": rule.level,
                "validators": list(rule.validators),
                "context_keywords": list(rule.context_keywords),
                "preview": rule.preview,
                "regex": rule.regex,
            }
            for rule in ruleset.rules
        ]
        _say(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK
    lines = ["ruleset: " + ruleset.name + " " + ruleset.version + " (" + (ruleset.file or "builtin") + ")"]
    headers = ["NAME", "TYPE", "WEIGHT", "LEVEL", "VALIDATORS", "PREVIEW", "REGEX"]
    rows = []
    for rule in ruleset.rules:
        rows.append(
            [
                rule.name,
                rule.type,
                format(rule.weight, ".2f"),
                rule.level,
                ",".join(rule.validators) or "-",
                rule.preview,
                rule.regex if len(rule.regex) <= 46 else rule.regex[:43] + "...",
            ]
        )
    lines.append(ascii_grid(headers, rows, ["left", "left", "right", "left", "left", "left", "left"]))
    lines.append("rules: " + str(len(ruleset.rules)))
    _say("\n".join(lines))
    return EXIT_OK


def _cmd_rules_check(args: argparse.Namespace) -> int:
    try:
        ruleset = _load_ruleset(args.rules)
    except RuleError as error:
        print("piiscan: invalid ruleset: " + str(error), file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        return _fail("cannot read rules: " + str(error))
    _say("ruleset: " + ruleset.name + " " + ruleset.version)
    _say("file: " + (ruleset.file or "builtin"))
    _say("rules: " + str(len(ruleset.rules)))
    for rule in ruleset.rules:
        _say("  - " + rule.name + " type=" + rule.type + " level=" + rule.level + " weight=" + format(rule.weight, ".2f"))
    _say("OK: ruleset is valid")
    return EXIT_OK


# ------------------------------------------------------------------- parser


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rules", metavar="PATH", help="custom rules file (.json or .toml); default: builtin")
    parser.add_argument(
        "--min-confidence",
        choices=list(CONFIDENCE_ORDER),
        default="low",
        help="drop findings below this confidence (default: low)",
    )
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, metavar="N", help="streaming chunk size in chars")
    parser.add_argument("--overlap", type=int, default=DEFAULT_OVERLAP, metavar="N", help="chunk overlap in chars (>= 64)")
    parser.add_argument("--context-window", type=int, default=20, metavar="N", help="context keyword window in chars")
    parser.add_argument("--type", dest="types", action="append", metavar="TYPE", help="only scan these types (repeatable)")
    parser.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_CHOICES),
        default="none",
        help="exit 2 when a finding reaches this confidence (default: none)",
    )


def build_parser() -> argparse.ArgumentParser:
    """构造 argparse 解析器。"""
    parser = argparse.ArgumentParser(
        prog="piiscan",
        description="Zero-dependency PII scanner and masking tool (CN ID, bank card, mobile, email, USCC, IPv4).",
        epilog="examples: piiscan scan notes.txt --format json | piiscan mask notes.txt --salt demo",
    )
    parser.add_argument("--version", action="version", version="piiscan " + __version__)
    subparsers = parser.add_subparsers(dest="command", metavar="{scan,mask,rules}")

    scan_parser = subparsers.add_parser("scan", help="scan a file or stdin and print findings")
    scan_parser.add_argument("target", help="file path, or - for stdin")
    scan_parser.add_argument("--format", choices=list(FORMATS), default="table", help="output format (default: table)")
    scan_parser.add_argument("--out", "-o", metavar="PATH", help="write the report to a file instead of stdout")
    _add_scan_options(scan_parser)
    scan_parser.set_defaults(func=_cmd_scan)

    mask_parser = subparsers.add_parser("mask", help="mask hits in a whole file")
    mask_parser.add_argument("target", help="file to mask")
    mask_parser.add_argument("--out", "-o", metavar="PATH", help="output path (default: <name>.masked<ext>)")
    mask_parser.add_argument("--in-place", action="store_true", help="allow writing back to the input file")
    mask_parser.add_argument(
        "--action",
        "--strategy",
        dest="action",
        choices=list(ACTIONS),
        help="force one action for every hit (mask/hash/redact; --strategy is an alias)",
    )
    mask_parser.add_argument("--policy", metavar="PATH", help="JSON map of type -> action (mask/hash/redact)")
    mask_parser.add_argument("--head", type=int, default=3, metavar="N", help="mask: keep N leading chars")
    mask_parser.add_argument("--tail", type=int, default=4, metavar="N", help="mask: keep N trailing chars")
    mask_parser.add_argument("--salt", default="", metavar="TEXT", help="hash: salt")
    mask_parser.add_argument("--keep-prefix", type=int, default=0, metavar="N", help="hash: keep N leading chars")
    mask_parser.add_argument("--redact-mode", choices=["stars", "remove"], default="stars", help="redact: stars or remove")
    mask_parser.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    _add_scan_options(mask_parser)
    mask_parser.set_defaults(func=_cmd_mask)

    rules_parser = subparsers.add_parser("rules", help="inspect or validate a ruleset")
    rules_sub = rules_parser.add_subparsers(dest="rules_command", metavar="{list,check}")
    list_parser = rules_sub.add_parser("list", help="list rules of a ruleset")
    list_parser.add_argument("--rules", metavar="PATH", help="rules file; default: builtin")
    list_parser.add_argument("--format", choices=["table", "json"], default="table", help="output format")
    list_parser.set_defaults(func=_cmd_rules_list)
    check_parser = rules_sub.add_parser("check", help="validate a ruleset file")
    check_parser.add_argument("--rules", metavar="PATH", help="rules file; default: builtin")
    check_parser.set_defaults(func=_cmd_rules_check)
    rules_parser.set_defaults(func=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI 主入口，返回进程退出码。"""
    _configure_stream(sys.stdout)
    _configure_stream(sys.stderr)
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return EXIT_ERROR if args.command is None else EXIT_OK
    try:
        return int(handler(args))
    except RuleError as error:
        return _fail("invalid ruleset: " + str(error))
    except ValueError as error:
        return _fail(str(error))
    except BrokenPipeError:
        return EXIT_OK
