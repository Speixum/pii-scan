"""mask 单元测试：三种动作、前缀保留、预览模式、策略优先级、重叠兜底、文件级脱敏。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from piiscan.mask import (
    apply_action,
    apply_mask,
    hash_value,
    mask_file,
    mask_value,
    preview_value,
    redact_value,
    resolve_action,
)

VALID_ID = "11010519491231002X"


class MaskValueTests(unittest.TestCase):
    """单值脱敏。"""

    def test_mask_keeps_head_and_tail(self) -> None:
        self.assertEqual(mask_value(VALID_ID, 4, 4), "1101**********002X")
        self.assertEqual(mask_value("13800138000", 3, 4), "138****8000")

    def test_mask_short_value_is_fully_masked(self) -> None:
        self.assertEqual(mask_value("abc", 4, 4), "***")

    def test_hash_is_stable_salted_and_hides_original(self) -> None:
        digest = hash_value(VALID_ID)
        self.assertEqual(digest, hash_value(VALID_ID))
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)
        self.assertNotEqual(digest, hash_value(VALID_ID, salt="demo"))
        self.assertNotIn(VALID_ID, digest)

    def test_hash_keep_prefix_keeps_leading_chars(self) -> None:
        digest = hash_value(VALID_ID, keep_prefix=4)
        self.assertTrue(digest.startswith("1101sha256:"))
        self.assertNotIn("494123", digest)

    def test_redact_modes(self) -> None:
        self.assertEqual(redact_value("abc"), "***")
        self.assertEqual(redact_value("abc", "remove"), "")
        with self.assertRaises(ValueError):
            redact_value("abc", "nope")

    def test_preview_modes(self) -> None:
        self.assertEqual(preview_value(VALID_ID, "head4_tail4"), "1101**********002X")
        self.assertEqual(preview_value("zhang.san@example.com", "email"), "z***@example.com")
        self.assertEqual(preview_value("192.168.10.20", "ipv4"), "192.168.*.*")
        self.assertEqual(preview_value("x", "star_all"), "*")
        with self.assertRaises(ValueError):
            preview_value("x", "nope")

    def test_apply_action_dispatch(self) -> None:
        self.assertEqual(apply_action("13800138000", "mask", head=3, tail=4), "138****8000")
        self.assertTrue(apply_action("13800138000", "hash").startswith("sha256:"))
        self.assertEqual(apply_action("13800138000", "redact", redact_mode="remove"), "")
        with self.assertRaises(ValueError):
            apply_action("x", "nope")


class ResolveActionTests(unittest.TestCase):
    """动作解析：policy[type] > policy["*"] > 级别默认。"""

    def test_defaults_follow_level(self) -> None:
        self.assertEqual(resolve_action("high_sensitive", "cn_id_card"), "mask")
        self.assertEqual(resolve_action("sensitive", "mobile_cn"), "mask")
        self.assertEqual(resolve_action("general", "ipv4"), "hash")

    def test_policy_overrides(self) -> None:
        self.assertEqual(resolve_action("high_sensitive", "cn_id_card", {"cn_id_card": "hash"}), "hash")
        self.assertEqual(resolve_action("high_sensitive", "cn_id_card", {"*": "redact"}), "redact")
        self.assertEqual(
            resolve_action("high_sensitive", "cn_id_card", {"*": "redact", "cn_id_card": "hash"}),
            "hash",
        )

    def test_bad_policy_action_raises(self) -> None:
        with self.assertRaises(ValueError):
            resolve_action("sensitive", "mobile_cn", {"*": "shred"})


class ApplyMaskTests(unittest.TestCase):
    """文本区间替换。"""

    def test_replaces_hit_and_keeps_other_text(self) -> None:
        text = "身份证 " + VALID_ID + " 已登记"
        start = text.index(VALID_ID)
        span = SimpleNamespace(offset=start, end=start + len(VALID_ID), type="cn_id_card", level="high_sensitive")
        result = apply_mask(text, [span])
        self.assertEqual(result.replaced, 1)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.text, "身份证 " + mask_value(VALID_ID, 3, 4) + " 已登记")
        self.assertEqual(result.by_action, {"mask": 1})

    def test_overlapping_span_is_skipped(self) -> None:
        text = "id " + VALID_ID + " end"
        start = text.index(VALID_ID)
        spans = [
            SimpleNamespace(offset=start, end=start + 18, type="cn_id_card", level="high_sensitive"),
            SimpleNamespace(offset=start + 2, end=start + 8, type="mobile_cn", level="sensitive"),
        ]
        result = apply_mask(text, spans)
        self.assertEqual(result.replaced, 1)
        self.assertEqual(result.skipped, 1)

    def test_out_of_range_span_is_skipped(self) -> None:
        text = "abc"
        span = SimpleNamespace(offset=2, end=99, type="cn_id_card", level="high_sensitive")
        result = apply_mask(text, [span])
        self.assertEqual(result.replaced, 1)
        self.assertEqual(result.text, "ab" + mask_value("c", 3, 4))


class MaskFileTests(unittest.TestCase):
    """文件级脱敏。"""

    def test_mask_file_writes_masked_copy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = base / "note.txt"
            target = base / "note.masked.txt"
            source.write_text("身份证 " + VALID_ID + "\n", encoding="utf-8")
            report = mask_file(source, target, policy={"*": "redact"})
            self.assertEqual(report.total, 1)
            self.assertEqual(report.replaced, 1)
            self.assertEqual(report.target, str(target))
            self.assertEqual(target.read_text(encoding="utf-8"), "身份证 " + "*" * 18 + "\n")
            self.assertIn(VALID_ID, source.read_text(encoding="utf-8"))

    def test_dry_run_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = base / "note.txt"
            source.write_text("手机 13800138000\n", encoding="utf-8")
            target = base / "note.masked.txt"
            report = mask_file(source, None)
            self.assertIsNone(report.target)
            self.assertEqual(report.total, 1)
            self.assertFalse(target.exists())

    def test_missing_source_raises(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(FileNotFoundError):
                mask_file(Path(raw) / "nope.txt")


if __name__ == "__main__":
    unittest.main()
