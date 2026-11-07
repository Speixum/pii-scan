"""脱敏策略：mask（首尾保留）、hash（sha256+salt）、redact（等长星号或删除）。

脱敏只替换命中的字符区间，不碰其余字符；文件级脱敏用
`utf-8 + surrogateescape` 编解码，保证其他字节（含换行、BOM、非法 UTF-8）
原样保留。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence

from . import classify

__all__ = [
    "MaskReport",
    "MaskResult",
    "PREVIEW_SPANS",
    "Spannable",
    "apply_action",
    "apply_mask",
    "hash_value",
    "mask_file",
    "mask_value",
    "preview_value",
    "redact_value",
    "resolve_action",
]

MASK_CHAR = "*"
HASH_PREFIX = "sha256:"
ACTIONS: tuple[str, ...] = ("mask", "hash", "redact")
REDACT_MODES: tuple[str, ...] = ("stars", "remove")

#: 预览模式 -> 保留的 (head, tail)；`email`/`ipv4` 走特殊分支。
PREVIEW_SPANS: dict[str, tuple[int, int]] = {
    "head4_tail4": (4, 4),
    "head3_tail4": (3, 4),
    "head1_tail1": (1, 1),
    "star_all": (0, 0),
    "email": (1, 0),
    "ipv4": (0, 0),
}


class Spannable(Protocol):
    """能被脱敏的最小信息（`Finding` 自动满足）。"""

    offset: int
    end: int
    type: str
    level: str


@dataclass(frozen=True)
class MaskResult:
    """一段文本脱敏后的结果。"""

    text: str
    replaced: int
    skipped: int
    by_action: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """返回可 JSON 序列化的摘要。"""
        return {
            "replaced": self.replaced,
            "skipped": self.skipped,
            "by_action": dict(sorted(self.by_action.items())),
        }


@dataclass(frozen=True)
class MaskReport:
    """文件级脱敏结果。"""

    source: str
    target: str | None
    replaced: int
    skipped: int
    total: int
    by_action: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """返回可 JSON 序列化的摘要。"""
        return {
            "source": self.source,
            "target": self.target,
            "total": self.total,
            "replaced": self.replaced,
            "skipped": self.skipped,
            "by_action": dict(sorted(self.by_action.items())),
        }


def _span_mask(value: str, head: int, tail: int, char: str = MASK_CHAR) -> str:
    head = max(0, int(head))
    tail = max(0, int(tail))
    if len(value) <= head + tail:
        return char * len(value)
    return value[:head] + char * (len(value) - head - tail) + value[len(value) - tail :]


def mask_value(value: str, head: int = 3, tail: int = 4, char: str = MASK_CHAR) -> str:
    """保留首 `head` 与尾 `tail` 个字符，中间用 `char` 填充。

    长度不足 `head + tail` 时整串掩掉（掩码长度等于原长度）。
    """
    return _span_mask(value, head, tail, char)


def hash_value(value: str, salt: str = "", keep_prefix: int = 0) -> str:
    """返回 `sha256:<hex>`，可用 `salt` 加盐、`keep_prefix` 保留若干原字符。

    参数:
        value: 原始值。
        salt: 拼在原文前一起哈希的盐（不写进结果）。
        keep_prefix: 结果前保留的原文字符数，默认 0（不泄露任何原文）。
    """
    keep = max(0, min(int(keep_prefix), len(value)))
    digest = hashlib.sha256((salt + value).encode("utf-8")).hexdigest()
    return value[:keep] + HASH_PREFIX + digest


def redact_value(value: str, mode: str = "stars") -> str:
    """redact：`stars` 返回等长星号，`remove` 返回空串。"""
    if mode not in REDACT_MODES:
        raise ValueError("unknown redact mode: " + str(mode))
    if mode == "remove":
        return ""
    return MASK_CHAR * len(value)


def preview_value(value: str, mode: str = "head3_tail4") -> str:
    """按规则里的 `preview` 模式生成掩码预览（用于报告，绝不输出原文）。"""
    if mode not in PREVIEW_SPANS:
        raise ValueError("unknown preview mode: " + str(mode))
    if mode == "email":
        local, separator, domain = value.rpartition("@")
        if not separator:
            return _span_mask(value, 1, 1)
        return (local[:1] or MASK_CHAR) + MASK_CHAR * 3 + "@" + domain
    if mode == "ipv4":
        parts = value.split(".")
        if len(parts) != 4:
            return _span_mask(value, 1, 1)
        return ".".join([parts[0], parts[1], MASK_CHAR, MASK_CHAR])
    head, tail = PREVIEW_SPANS[mode]
    return _span_mask(value, head, tail)


def normalize_action(action: str) -> str:
    """校验动作名。

    异常:
        ValueError: 不是 `mask|hash|redact`。
    """
    if action not in ACTIONS:
        raise ValueError("unknown action: " + str(action))
    return action


def resolve_action(level: str, type_name: str, policy: dict[str, str] | None = None) -> str:
    """决定一条命中用哪种动作。

    优先级：`policy[type]` > `policy["*"]` > 级别默认动作。
    """
    if policy:
        override = policy.get(type_name) or policy.get("*")
        if override:
            return normalize_action(override)
    return classify.action_for(level)


def apply_action(
    value: str,
    action: str,
    *,
    head: int = 3,
    tail: int = 4,
    salt: str = "",
    keep_prefix: int = 0,
    redact_mode: str = "stars",
) -> str:
    """按动作脱敏单个值。

    异常:
        ValueError: 动作名非法。
    """
    chosen = normalize_action(action)
    if chosen == "mask":
        return mask_value(value, head, tail)
    if chosen == "hash":
        return hash_value(value, salt=salt, keep_prefix=keep_prefix)
    return redact_value(value, redact_mode)


def apply_mask(
    text: str,
    findings: Sequence[Spannable],
    *,
    policy: dict[str, str] | None = None,
    head: int = 3,
    tail: int = 4,
    salt: str = "",
    keep_prefix: int = 0,
    redact_mode: str = "stars",
) -> MaskResult:
    """按命中区间替换文本，返回新文本与统计。

    命中区间按 offset 升序处理；互相重叠的区间只替换第一个，其余计入
    `skipped`（扫描器已做重叠消解，这里的保护是给外部传入的 findings 兜底）。
    """
    items = sorted(findings, key=lambda item: (item.offset, item.end))
    parts: list[str] = []
    cursor = 0
    replaced = 0
    skipped = 0
    by_action: dict[str, int] = {}
    for item in items:
        start = max(0, int(item.offset))
        end = min(len(text), int(item.end))
        if end <= start or start < cursor:
            skipped += 1
            continue
        action = resolve_action(item.level, item.type, policy)
        parts.append(text[cursor:start])
        parts.append(
            apply_action(
                text[start:end],
                action,
                head=head,
                tail=tail,
                salt=salt,
                keep_prefix=keep_prefix,
                redact_mode=redact_mode,
            )
        )
        by_action[action] = by_action.get(action, 0) + 1
        cursor = end
        replaced += 1
    parts.append(text[cursor:])
    return MaskResult(
        text="".join(parts),
        replaced=replaced,
        skipped=skipped,
        by_action=dict(sorted(by_action.items())),
    )


def mask_file(
    source: str | Path,
    target: str | Path | None = None,
    *,
    scanner: Any = None,
    policy: dict[str, str] | None = None,
    head: int = 3,
    tail: int = 4,
    salt: str = "",
    keep_prefix: int = 0,
    redact_mode: str = "stars",
) -> MaskReport:
    """对整文件脱敏，返回统计；`target` 为 None 时不落盘。

    参数:
        source: 输入文件。
        target: 输出文件；省略则只计算不写。
        scanner: :class:`piiscan.scanner.Scanner` 实例；省略时用默认规则新建。

    异常:
        FileNotFoundError: 输入文件不存在。
        ValueError: 动作名非法。
    """
    from .scanner import Scanner  # 局部导入，避免与 scanner 循环依赖

    engine = scanner if scanner is not None else Scanner()
    path = Path(source)
    data = path.read_bytes()
    text = data.decode("utf-8", "surrogateescape")
    result = engine.scan_text(text, source=str(path))
    masked = apply_mask(
        text,
        result.findings,
        policy=policy,
        head=head,
        tail=tail,
        salt=salt,
        keep_prefix=keep_prefix,
        redact_mode=redact_mode,
    )
    out_path = Path(target) if target is not None else None
    if out_path is not None:
        out_path.write_bytes(masked.text.encode("utf-8", "surrogateescape"))
    return MaskReport(
        source=str(path),
        target=str(out_path) if out_path is not None else None,
        replaced=masked.replaced,
        skipped=masked.skipped,
        total=len(result.findings),
        by_action=masked.by_action,
    )
