"""classify 单元测试：分数分档、三级定级、建议动作、阈值过滤。"""

from __future__ import annotations

import unittest

from piiscan.classify import (
    CONFIDENCE_ORDER,
    HIGH_SCORE,
    LEVEL_ORDER,
    MEDIUM_SCORE,
    action_for,
    confidence_for,
    downgrade_level,
    explain,
    level_for,
    meets_minimum,
)


class ConfidenceTests(unittest.TestCase):
    """0..1 分数 -> high/medium/low。"""

    def test_boundaries(self) -> None:
        self.assertEqual(confidence_for(0.0), "low")
        self.assertEqual(confidence_for(MEDIUM_SCORE), "medium")
        self.assertEqual(confidence_for(MEDIUM_SCORE - 0.001), "low")
        self.assertEqual(confidence_for(HIGH_SCORE), "high")
        self.assertEqual(confidence_for(HIGH_SCORE - 0.001), "medium")

    def test_clamped(self) -> None:
        self.assertEqual(confidence_for(-1.0), "low")
        self.assertEqual(confidence_for(9.0), "high")

    def test_order_values(self) -> None:
        self.assertEqual(CONFIDENCE_ORDER, {"low": 0, "medium": 1, "high": 2})


class LevelTests(unittest.TestCase):
    """按置信度定级：medium 下调一档，low 一律 general。"""

    def test_high_keeps_rule_level(self) -> None:
        self.assertEqual(level_for("high_sensitive", "high"), "high_sensitive")
        self.assertEqual(level_for("sensitive", "high"), "sensitive")

    def test_medium_downgrades_one_step(self) -> None:
        self.assertEqual(level_for("high_sensitive", "medium"), "sensitive")
        self.assertEqual(level_for("sensitive", "medium"), "general")

    def test_low_is_general(self) -> None:
        self.assertEqual(level_for("high_sensitive", "low"), "general")

    def test_downgrade_floor(self) -> None:
        self.assertEqual(downgrade_level("general", 5), "general")
        self.assertEqual(downgrade_level("high_sensitive", 0), "high_sensitive")

    def test_invalid_values_raise(self) -> None:
        with self.assertRaises(ValueError):
            level_for("nope", "high")
        with self.assertRaises(ValueError):
            level_for("general", "nope")
        with self.assertRaises(ValueError):
            downgrade_level("nope")

    def test_level_order_contract(self) -> None:
        self.assertEqual(LEVEL_ORDER, ("general", "sensitive", "high_sensitive"))


class ActionTests(unittest.TestCase):
    """级别 -> 建议动作。"""

    def test_high_sensitive_needs_mask(self) -> None:
        self.assertEqual(action_for("high_sensitive"), "mask")

    def test_general_is_hash(self) -> None:
        self.assertEqual(action_for("general"), "hash")

    def test_unknown_level_falls_back_to_hash(self) -> None:
        self.assertEqual(action_for("weird"), "hash")


class FilterTests(unittest.TestCase):
    """--min-confidence 过滤。"""

    def test_meets_minimum(self) -> None:
        self.assertTrue(meets_minimum("high", "medium"))
        self.assertTrue(meets_minimum("medium", "medium"))
        self.assertFalse(meets_minimum("medium", "high"))
        self.assertTrue(meets_minimum("low", "low"))

    def test_invalid_input_raises(self) -> None:
        with self.assertRaises(ValueError):
            meets_minimum("nope", "low")
        with self.assertRaises(ValueError):
            meets_minimum("low", "nope")

    def test_explain_is_ascii(self) -> None:
        text = explain(0.8)
        self.assertEqual(text, "score=0.80 confidence=high")
        text.encode("ascii")


if __name__ == "__main__":
    unittest.main()
