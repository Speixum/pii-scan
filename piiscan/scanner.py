"""流式扫描引擎：分块读取、块间重叠、重叠区去重、上下文关键词加权。

设计要点:
- 文件按 `chunk_size`（默认 1 MB）分块读取，块与块之间保留 `overlap`
  （默认 512，最小 64）字符的重叠，避免命中被块边界切断。
- 每个命中带字符 offset/end（全文坐标）与 line/col（按 \n 计数，1 起）。
- 重叠区产生的重复命中按 (规则名, offset, end) 去重，冲突时保留分数更高者。
- 同一批候选按 (起点升序, 分数降序) 做非重叠消解，短命中优先于它的外层长命中。
- 上下文加权：命中前后各 `context_window`（默认 20）字符内出现规则关键词则加分。
"""

from __future__ import annotations

import bisect
import io
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, TextIO

from . import SCHEMA, classify
from .mask import preview_value
from .rules import Rule, RuleSet, load_rules
from .validators import run_validators

__all__ = [
    "CHECKSUM_BONUS",
    "CHECKSUM_PENALTY",
    "CONTEXT_BONUS",
    "CONTEXT_WINDOW",
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_OVERLAP",
    "LOOKAHEAD",
    "MIN_OVERLAP",
    "Finding",
    "ScanResult",
    "Scanner",
    "scan_file",
    "scan_text",
]

#: 默认分块大小（1 MB 字符）。
DEFAULT_CHUNK_SIZE = 1_048_576
#: 默认块间重叠字符数，需 >= MIN_OVERLAP。
DEFAULT_OVERLAP = 512
#: 重叠下限（SPEC 要求 >= 64）。
MIN_OVERLAP = 64
#: 分块下限，防止把重叠挤掉。
MIN_CHUNK_SIZE = 64
#: 上下文窗口半径（前后各 20 字符）。
CONTEXT_WINDOW = 20
#: 命中尾部被块边界切断时向后多看多少个字符。
LOOKAHEAD = 64
#: 校验位通过 / 失败的分数调整。
#: 失败时降到 "正则命中 - 0.25"：有上下文关键词时约 0.45（medium），
#: 无上下文时约 0.30（low），永远不会因为正则命中就被判 high。
CHECKSUM_BONUS = 0.30
CHECKSUM_PENALTY = 0.25
#: 命中附近出现关键词的加分。
CONTEXT_BONUS = 0.15


def utc_now() -> str:
    """返回当前 UTC 时间，形如 `2026-11-08T01:35:00Z`（ISO8601，秒精度）。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Finding:
    """一条命中。字段名与 SPEC 3.2 的 JSON 契约一致。"""

    type: str
    rule: str
    offset: int
    end: int
    line: int
    col: int
    score: float
    confidence: str
    level: str
    checksum: bool | None
    preview: str
    reasons: tuple[str, ...] = ()

    @property
    def length(self) -> int:
        """命中长度（字符数）。"""
        return self.end - self.offset

    def to_dict(self) -> dict[str, Any]:
        """返回 JSON 契约要求的对象（preview 已掩码）。"""
        return {
            "type": self.type,
            "level": self.level,
            "confidence": self.confidence,
            "score": self.score,
            "offset": self.offset,
            "end": self.end,
            "line": self.line,
            "col": self.col,
            "length": self.length,
            "preview": self.preview,
            "checksum": self.checksum,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class ScanResult:
    """一次扫描的完整结果。"""

    source: str
    findings: tuple[Finding, ...]
    ruleset: RuleSet
    scanned_chars: int = 0
    chunks: int = 0
    elapsed_ms: float = 0.0

    def summary(self) -> dict[str, Any]:
        """统计：total / by_type / by_confidence / by_level / by_action。

        附加字段 `by_action` 表示按级别建议动作的条数，兼容 SPEC 而不改动
        既定字段。
        """
        by_type: dict[str, int] = {}
        by_confidence = {name: 0 for name in classify.CONFIDENCE_ORDER}
        by_level = {name: 0 for name in classify.LEVEL_ORDER}
        by_action: dict[str, int] = {}
        for item in self.findings:
            by_type[item.type] = by_type.get(item.type, 0) + 1
            by_confidence[item.confidence] = by_confidence.get(item.confidence, 0) + 1
            by_level[item.level] = by_level.get(item.level, 0) + 1
            action = classify.action_for(item.level)
            by_action[action] = by_action.get(action, 0) + 1
        return {
            "total": len(self.findings),
            "by_type": dict(sorted(by_type.items())),
            "by_confidence": by_confidence,
            "by_level": by_level,
            "by_action": dict(sorted(by_action.items())),
        }

    def to_payload(self, generated_at: str | None = None) -> dict[str, Any]:
        """返回可直接 JSON 化的完整报告（含 `schema` 字段）。"""
        return {
            "schema": SCHEMA,
            "source": self.source,
            "generated_at": generated_at or utc_now(),
            "findings": [item.to_dict() for item in self.findings],
            "summary": self.summary(),
            "ruleset": self.ruleset.meta(),
        }

    def count(self, minimum: str = "low") -> int:
        """返回达到 `minimum` 置信度的命中数。"""
        return sum(1 for item in self.findings if classify.meets_minimum(item.confidence, minimum))


@dataclass
class _Candidate:
    """扫描过程中的一条候选命中（尚未定级）。"""

    rule: Rule
    start: int
    end: int
    value: str
    score: float
    checksum: bool | None
    reasons: list[str]


class Scanner:
    """规则驱动的流式扫描器。"""

    def __init__(
        self,
        ruleset: RuleSet | None = None,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        overlap: int = DEFAULT_OVERLAP,
        context_window: int = CONTEXT_WINDOW,
        min_confidence: str = "low",
        types: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        """
        参数:
            ruleset: 规则集；省略则加载内置规则。
            chunk_size: 分块字符数，>= 64 且 > overlap。
            overlap: 块间重叠字符数，>= 64。
            context_window: 上下文窗口半径（字符）。
            min_confidence: 最低置信度（low/medium/high），用它过滤结果。
            types: 只保留这些 type；None 表示全部。

        异常:
            ValueError: 参数越界或 min_confidence 非法。
        """
        if int(chunk_size) < MIN_CHUNK_SIZE:
            raise ValueError("chunk_size must be >= " + str(MIN_CHUNK_SIZE))
        if int(overlap) < MIN_OVERLAP:
            raise ValueError("overlap must be >= " + str(MIN_OVERLAP))
        if int(overlap) >= int(chunk_size):
            raise ValueError("overlap must be smaller than chunk_size")
        if int(context_window) < 0:
            raise ValueError("context_window must be >= 0")
        if min_confidence not in classify.CONFIDENCE_ORDER:
            raise ValueError("unknown confidence level: " + str(min_confidence))
        self.ruleset = ruleset if ruleset is not None else load_rules()
        self.chunk_size = int(chunk_size)
        self.overlap = int(overlap)
        self.context_window = int(context_window)
        self.min_confidence = min_confidence
        wanted = list(types) if types else None
        self.rules: tuple[Rule, ...] = tuple(
            rule for rule in self.ruleset.rules if wanted is None or rule.type in wanted
        )
        #: 尾部保留区上限：重叠的 8 倍且不小于 8 KiB，保证跨块命中可被拼接。
        self._max_carry = max(self.overlap * 8, 8192)

    # ------------------------------------------------------------------ public

    def scan_text(self, text: str, source: str = "<text>") -> ScanResult:
        """扫描一段内存中的文本。"""
        return self._scan_stream(io.StringIO(text), source)

    def scan_file(self, path: str | Path) -> ScanResult:
        """扫描一个 UTF-8 文件（`newline=""` 保持 \r\n 不被改写）。

        异常:
            FileNotFoundError: 文件不存在。
        """
        file_path = Path(path)
        with file_path.open("r", encoding="utf-8", errors="surrogateescape", newline="") as handle:
            return self._scan_stream(handle, str(file_path))

    # ---------------------------------------------------------------- internal

    def _scan_stream(self, handle: TextIO, source: str) -> ScanResult:
        started = time.perf_counter()
        carry = ""
        scanned = 0
        chunks = 0
        candidates: dict[tuple[str, int, int], _Candidate] = {}
        line_starts: list[int] = [0]
        eof = False
        while not eof:
            block = handle.read(self.chunk_size)
            eof = block == ""
            scanned += len(block)
            if block:
                chunks += 1
            if not eof:
                text = carry + block
                base = scanned - len(text)
            else:
                # 收尾时把剩下的 carry 再扫一遍，得到真实末尾的上下文。
                text = carry
                base = scanned - len(carry)
            if text:
                self._record_newlines(line_starts, text, base)
                for item in self._match(text, base, eof):
                    self._evaluate(item, text, base, candidates)
            if eof:
                break
            keep = max(self.overlap, min(len(text), self._max_carry))
            carry = text[-keep:] if keep else ""
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return self._finalize(candidates, line_starts, source, scanned, chunks, elapsed_ms)

    def _record_newlines(self, line_starts: list[int], text: str, base: int) -> None:
        last = line_starts[-1]
        found = text.find("\n")
        while found != -1:
            absolute = base + found
            if absolute > last:
                # 记录下一行的起始位置（换行符之后），
                # 这样 _line_col 用 offset - start + 1 得到的列号才是 1 起。
                line_starts.append(absolute + 1)
                last = absolute + 1
            found = text.find("\n", found + 1)

    def _line_col(self, offset: int, line_starts: list[int]) -> tuple[int, int]:
        index = bisect.bisect_right(line_starts, offset) - 1
        return index + 1, offset - line_starts[index] + 1

    def _match(self, text: str, base: int, eof: bool) -> Iterator[_Candidate]:
        length = len(text)
        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                start = match.start()
                end = match.end()
                if end <= start:
                    continue
                if not eof and end > length - LOOKAHEAD:
                    # 尾部 LOOKAHEAD 字符内的命中可能被块边界截断，留给下一块。
                    # 重叠已保证下一个块能重新看到它的起点。
                    continue
                value = match.group(0)
                if not value:
                    continue
                yield _Candidate(
                    rule=rule,
                    start=base + start,
                    end=base + end,
                    value=value,
                    score=rule.weight,
                    checksum=None,
                    reasons=["regex:" + rule.name],
                )

    def _evaluate(
        self,
        candidate: _Candidate,
        text: str,
        base: int,
        candidates: dict[tuple[str, int, int], _Candidate],
    ) -> None:
        rule = candidate.rule
        local_start = candidate.start - base
        local_end = candidate.end - base
        reasons = list(candidate.reasons)
        score = candidate.score
        checksum: bool | None = None
        if rule.validators:
            results = run_validators(rule.validators, candidate.value)
            failed = next((item for item in results if not item.ok), None)
            if results and failed is None:
                checksum = True
                score = min(1.0, score + CHECKSUM_BONUS)
                reasons.extend("checksum:" + item.code for item in results)
            else:
                checksum = False
                score = max(0.0, score - CHECKSUM_PENALTY)
                reasons.append("checksum_fail:" + (failed.code if failed is not None else "unknown"))
        window = self.context_window
        if window > 0 and rule.context_keywords:
            before = text[max(0, local_start - window) : local_start]
            after = text[local_end : min(len(text), local_end + window)]
            haystack = (before + after).lower()
            hit = next((keyword for keyword in rule.context_keywords if keyword.lower() in haystack), None)
            if hit is not None:
                score = min(1.0, score + CONTEXT_BONUS)
                reasons.append("context:" + hit)
        candidate.score = round(score, 4)
        candidate.checksum = checksum
        candidate.reasons = reasons
        key = (rule.name, candidate.start, candidate.end)
        previous = candidates.get(key)
        if previous is None or candidate.score > previous.score:
            candidates[key] = candidate

    def _finalize(
        self,
        candidates: dict[tuple[str, int, int], _Candidate],
        line_starts: list[int],
        source: str,
        scanned: int,
        chunks: int,
        elapsed_ms: float = 0.0,
    ) -> ScanResult:
        ordered = sorted(candidates.values(), key=lambda item: (item.start, -item.score, -(item.end - item.start)))
        kept: list[_Candidate] = []
        for item in ordered:
            if kept and item.start < kept[-1].end:
                continue
            kept.append(item)
        findings: list[Finding] = []
        for item in kept:
            confidence = classify.confidence_for(item.score)
            if not classify.meets_minimum(confidence, self.min_confidence):
                continue
            line, col = self._line_col(item.start, line_starts)
            level = classify.level_for(item.rule.level, confidence)
            findings.append(
                Finding(
                    type=item.rule.type,
                    rule=item.rule.name,
                    offset=item.start,
                    end=item.end,
                    line=line,
                    col=col,
                    score=item.score,
                    confidence=confidence,
                    level=level,
                    checksum=item.checksum,
                    preview=preview_value(item.value, item.rule.preview),
                    reasons=tuple(item.reasons),
                )
            )
        return ScanResult(
            source=source,
            findings=tuple(findings),
            ruleset=self.ruleset,
            scanned_chars=scanned,
            chunks=chunks,
            elapsed_ms=round(elapsed_ms, 3),
        )


def scan_text(text: str, *, ruleset: RuleSet | None = None, source: str = "<text>", **options: Any) -> ScanResult:
    """便捷函数：用默认（或指定）规则扫描一段文本。"""
    return Scanner(ruleset, **options).scan_text(text, source=source)


def scan_file(path: str | Path, *, ruleset: RuleSet | None = None, **options: Any) -> ScanResult:
    """便捷函数：用默认（或指定）规则扫描一个文件。"""
    return Scanner(ruleset, **options).scan_file(path)
