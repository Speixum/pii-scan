"""规则文件加载：内置 `rules/builtin.json`，支持自定义 JSON 与 TOML。

规则字段（SPEC 3/E 约定）：

- `name`: 规则名（唯一，写进 findings.reasons 的 `regex:<name>`）
- `type`: 命中类型，如 `cn_id_card`
- `regex`: 正则（必须能编译，且不得匹配空串）
- `validators`: 校验器名列表，见 :mod:`piiscan.validators`
- `context_keywords`: 命中前后 20 字符窗口内的关键词
- `weight`: 基础分 0..1
- `level`: `high_sensitive|sensitive|general`
- `preview`: 预览模式，见 :data:`PREVIEW_MODES`
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

from .classify import LEVELS
from .mask import PREVIEW_SPANS
from .validators import VALIDATORS

__all__ = [
    "PREVIEW_MODES",
    "Rule",
    "RuleError",
    "RuleSet",
    "builtin_rule_path",
    "load_rules",
    "parse_rules",
]

#: 预览模式 -> (保留头字符数, 保留尾字符数)；`email`/`ipv4` 为特殊模式。
PREVIEW_MODES: Final[dict[str, tuple[int, int]]] = dict(PREVIEW_SPANS)

_RULE_DIR: Final[Path] = Path(__file__).resolve().parent / "rules"
_REQUIRED_FIELDS: Final[tuple[str, ...]] = ("name", "type", "regex")
_OPTIONAL_FIELDS: Final[tuple[str, ...]] = (
    "validators",
    "context_keywords",
    "weight",
    "level",
    "preview",
)
_ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(_REQUIRED_FIELDS + _OPTIONAL_FIELDS)


class RuleError(ValueError):
    """规则文件不合法（错误信息保持 ASCII，可直接打印到控制台）。"""


@dataclass(frozen=True)
class Rule:
    """一条已校验、已编译的规则。"""

    name: str
    type: str
    regex: str
    validators: tuple[str, ...] = ()
    context_keywords: tuple[str, ...] = ()
    weight: float = 0.5
    level: str = "sensitive"
    preview: str = "head3_tail4"
    pattern: re.Pattern[str] | None = field(default=None, compare=False, repr=False)

    def compiled(self) -> re.Pattern[str]:
        """返回编译后的正则。

        异常:
            RuleError: 规则未经 :func:`parse_rules` / :func:`load_rules` 构造。
        """
        if self.pattern is None:
            raise RuleError("rule is not compiled: " + self.name)
        return self.pattern


@dataclass(frozen=True)
class RuleSet:
    """一组规则及其来源信息（来源信息会写进 JSON 的 `ruleset` 字段）。"""

    name: str
    version: str
    file: str | None
    rules: tuple[Rule, ...]

    def meta(self) -> dict[str, Any]:
        """返回 JSON 契约要求的 `ruleset` 对象。"""
        return {"name": self.name, "version": self.version, "file": self.file}

    def by_name(self, name: str) -> Rule:
        """按名字取规则。

        异常:
            KeyError: 不存在该规则。
        """
        for rule in self.rules:
            if rule.name == name:
                return rule
        raise KeyError("unknown rule: " + str(name))


def builtin_rule_path() -> Path:
    """返回内置规则文件路径。"""
    return _RULE_DIR / "builtin.json"


def _require_str(raw: Mapping[str, Any], key: str, where: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleError(where + ": field '" + key + "' must be a non-empty string")
    return value.strip()


def _str_list(raw: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, (list, tuple)):
        raise RuleError(where + ": field '" + key + "' must be a list of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise RuleError(where + ": field '" + key + "' must contain non-empty strings")
        items.append(item)
    return tuple(items)


def _parse_rule(raw: Any, index: int, source: str) -> Rule:
    where = source + ": rules[" + str(index) + "]"
    if not isinstance(raw, Mapping):
        raise RuleError(where + ": must be an object")
    unknown = sorted(set(raw.keys()) - _ALLOWED_FIELDS)
    if unknown:
        raise RuleError(where + ": unknown field(s): " + ", ".join(unknown))
    name = _require_str(raw, "name", where)
    type_name = _require_str(raw, "type", where)
    regex = _require_str(raw, "regex", where)

    validators = _str_list(raw, "validators", where)
    for validator_name in validators:
        if validator_name not in VALIDATORS:
            raise RuleError(where + ": unknown validator '" + validator_name + "'")
    keywords = _str_list(raw, "context_keywords", where)

    weight_raw = raw.get("weight", 0.5)
    if isinstance(weight_raw, bool) or not isinstance(weight_raw, (int, float)):
        raise RuleError(where + ": field 'weight' must be a number")
    weight = float(weight_raw)
    if not 0.0 <= weight <= 1.0:
        raise RuleError(where + ": field 'weight' must be within 0..1")

    level = raw.get("level", "sensitive")
    if not isinstance(level, str) or level not in LEVELS:
        raise RuleError(where + ": field 'level' must be one of " + ", ".join(LEVELS))

    preview = raw.get("preview", "head3_tail4")
    if not isinstance(preview, str) or preview not in PREVIEW_MODES:
        raise RuleError(
            where + ": field 'preview' must be one of " + ", ".join(sorted(PREVIEW_MODES))
        )

    if len(regex) > 500:
        raise RuleError(where + ": regex longer than 500 chars")
    try:
        pattern = re.compile(regex)
    except re.error as exc:
        raise RuleError(where + ": invalid regex: " + str(exc)) from None
    if pattern.search(""):
        raise RuleError(where + ": regex must not match an empty string")

    return Rule(
        name=name,
        type=type_name,
        regex=regex,
        validators=validators,
        context_keywords=keywords,
        weight=weight,
        level=level,
        preview=preview,
        pattern=pattern,
    )


def parse_rules(document: Any, source: str = "<memory>") -> RuleSet:
    """解析已加载的规则文档。

    参数:
        document: `{"schema":...,"name":...,"version":...,"rules":[...]}`
            或直接是规则列表。
        source: 出现在错误信息里的来源标识。
    """
    if isinstance(document, Mapping):
        raw_rules = document.get("rules")
        name = str(document.get("name") or "custom")
        version = str(document.get("version") or "0")
    elif isinstance(document, (list, tuple)):
        raw_rules = list(document)
        name = "custom"
        version = "0"
    else:
        raise RuleError(source + ": rules document must be an object or a list")
    if not isinstance(raw_rules, (list, tuple)) or not raw_rules:
        raise RuleError(source + ": 'rules' must be a non-empty list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules):
        rule = _parse_rule(raw, index, source)
        if rule.name in seen:
            raise RuleError(source + ": duplicate rule name '" + rule.name + "'")
        seen.add(rule.name)
        rules.append(rule)
    return RuleSet(name=name, version=version, file=None, rules=tuple(rules))


def _read_document(path: Path) -> Any:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError("cannot read rules file: " + path.name + " (" + str(exc) + ")") from None
    suffix = path.suffix.lower()
    if suffix == ".toml":
        import tomllib

        try:
            return tomllib.loads(raw_text)
        except tomllib.TOMLDecodeError as exc:
            raise RuleError(str(path.name) + ": invalid TOML: " + str(exc)) from None
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuleError(
            str(path.name) + ": invalid JSON at line " + str(exc.lineno) + ": " + exc.msg
        ) from None


def load_rules(path: str | Path | None = None) -> RuleSet:
    """加载规则集。

    参数:
        path: `None` 表示内置 `builtin.json`；否则读 `.json` 或 `.toml`。

    异常:
        RuleError: 文件不可读、格式不支持或内容不合法。
    """
    if path is None:
        target = builtin_rule_path()
        ruleset = parse_rules(_read_document(target), source="builtin.json")
        return RuleSet(
            name="builtin" if ruleset.name == "builtin" else ruleset.name,
            version=ruleset.version,
            file=None,
            rules=ruleset.rules,
        )
    target = Path(path)
    if target.suffix.lower() not in (".json", ".toml"):
        raise RuleError("unsupported rules file: expect .json or .toml")
    if not target.is_file():
        raise RuleError("rules file not found: " + target.name)
    ruleset = parse_rules(_read_document(target), source=target.name)
    return RuleSet(
        name=ruleset.name,
        version=ruleset.version,
        file=str(target),
        rules=ruleset.rules,
    )


def describe_rules(ruleset: RuleSet) -> list[dict[str, str]]:
    """把规则集摊平成适合打表格的字符串行。"""
    rows: list[dict[str, str]] = []
    for rule in ruleset.rules:
        rows.append(
            {
                "name": rule.name,
                "type": rule.type,
                "level": rule.level,
                "weight": "%.2f" % rule.weight,
                "validators": ",".join(rule.validators) or "-",
                "preview": rule.preview,
            }
        )
    return rows


def rule_names(ruleset: RuleSet) -> Sequence[str]:
    """返回规则名元组。"""
    return tuple(rule.name for rule in ruleset.rules)
