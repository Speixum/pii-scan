"""置信度与敏感级别：把 0..1 的分数映射成 high/medium/low 与三级定级。"""

from __future__ import annotations

from typing import Final

__all__ = [
    "CONFIDENCE_ORDER",
    "HIGH_SCORE",
    "LEVELS",
    "LEVEL_ACTIONS",
    "LEVEL_ORDER",
    "MEDIUM_SCORE",
    "action_for",
    "confidence_for",
    "downgrade_level",
    "explain",
    "level_for",
    "meets_minimum",
]

#: 置信度分档阈值（分数 >= 阈值即进入该档）。
HIGH_SCORE: Final[float] = 0.75
MEDIUM_SCORE: Final[float] = 0.45

#: 置信度从低到高的排序值。
CONFIDENCE_ORDER: Final[dict[str, int]] = {"low": 0, "medium": 1, "high": 2}

#: 敏感级别从低到高。
LEVEL_ORDER: Final[tuple[str, ...]] = ("general", "sensitive", "high_sensitive")
LEVELS: Final[tuple[str, ...]] = LEVEL_ORDER

#: 每个级别建议的脱敏动作。
LEVEL_ACTIONS: Final[dict[str, str]] = {
    "high_sensitive": "mask",
    "sensitive": "mask",
    "general": "hash",
}


def confidence_for(score: float) -> str:
    """把 0..1 的分数映射为 `high|medium|low`。

    参数:
        score: 综合得分，超出 0..1 时按边界钳制。
    """
    value = min(1.0, max(0.0, float(score)))
    if value >= HIGH_SCORE:
        return "high"
    if value >= MEDIUM_SCORE:
        return "medium"
    return "low"


def downgrade_level(level: str, steps: int = 1) -> str:
    """把敏感级别下调若干档，最低到 `general`。

    参数:
        level: 起始级别。
        steps: 下调档数（负数视为 0）。
    异常:
        ValueError: 级别不在 `LEVEL_ORDER` 中。
    """
    if level not in LEVEL_ORDER:
        raise ValueError("unknown level: " + str(level))
    index = LEVEL_ORDER.index(level)
    return LEVEL_ORDER[max(0, index - max(0, int(steps)))]


def level_for(rule_level: str, confidence: str) -> str:
    """按规则级别与置信度定级。

    设计取舍：校验位/上下文不足以支撑高置信时下调定级，避免把
    "只是长得像身份证的 18 位数字"直接报成 high_sensitive。
    high 保持规则级别，medium 下调一档，low 一律降到 general。

    参数:
        rule_level: 规则里声明的级别。
        confidence: `high|medium|low`。
    异常:
        ValueError: 级别或置信度取值非法。
    """
    if rule_level not in LEVEL_ORDER:
        raise ValueError("unknown level: " + str(rule_level))
    if confidence not in CONFIDENCE_ORDER:
        raise ValueError("unknown confidence: " + str(confidence))
    if confidence == "high":
        return rule_level
    steps = 1 if confidence == "medium" else len(LEVEL_ORDER)
    return downgrade_level(rule_level, steps)


def action_for(level: str) -> str:
    """返回级别对应的建议动作：`mask|hash|redact`。"""
    return LEVEL_ACTIONS.get(level, "hash")


def meets_minimum(confidence: str, minimum: str) -> bool:
    """判断置信度是否达到过滤下限（非法取值抛 ValueError）。"""
    if confidence not in CONFIDENCE_ORDER:
        raise ValueError("unknown confidence: " + str(confidence))
    if minimum not in CONFIDENCE_ORDER:
        raise ValueError("unknown minimum confidence: " + str(minimum))
    return CONFIDENCE_ORDER[confidence] >= CONFIDENCE_ORDER[minimum]


def explain(score: float) -> str:
    """给出 ASCII 一句话解释，用于 CLI 调试输出。"""
    return "score=%.2f confidence=%s" % (float(score), confidence_for(score))
