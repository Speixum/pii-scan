"""scanner 单元测试：分块流式、跨块命中、去重、上下文加权、定级。"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from piiscan.rules import load_rules, parse_rules
from piiscan.scanner import DEFAULT_CHUNK_SIZE, Scanner, scan_text, utc_now

VALID_ID = "11010519491231002X"
INVALID_ID = "110105194912310021"  # 校验位错误，模 11 应为 X


class BasicScanTests(unittest.TestCase):
    """基础命中与字段。"""

    def test_valid_id_is_high(self) -> None:
        result = scan_text("身份证号 " + VALID_ID + " 已登记")
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.type, "cn_id_card")
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(finding.level, "high_sensitive")
        self.assertTrue(finding.checksum)
        self.assertIn("regex:cn_id_card", finding.reasons)
        self.assertIn("checksum:mod11", finding.reasons)

    def test_finding_offsets_and_line_col(self) -> None:
        text = "第一行\n手机号 13800138000\n"
        finding = scan_text(text).findings[0]
        self.assertEqual(text[finding.offset : finding.end], "13800138000")
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.col, 5)
        self.assertEqual(finding.length, 11)

    def test_mobile_with_keyword_is_high(self) -> None:
        finding = scan_text("手机 13800138000").findings[0]
        self.assertEqual(finding.type, "mobile_cn")
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(finding.level, "sensitive")

    def test_ipv4_is_general(self) -> None:
        finding = scan_text("网关 10.0.0.1").findings[0]
        self.assertEqual(finding.type, "ipv4")
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(finding.level, "general")

    def test_email_preview_has_no_full_value(self) -> None:
        finding = scan_text("邮箱 alice@example.com").findings[0]
        self.assertEqual(finding.type, "email")
        self.assertNotIn("alice@example.com", finding.preview)
        self.assertIn("@example.com", finding.preview)

    def test_empty_text(self) -> None:
        result = scan_text("")
        self.assertEqual(result.findings, ())
        self.assertEqual(result.chunks, 0)
        self.assertEqual(result.scanned_chars, 0)

    def test_plain_text_has_no_findings(self) -> None:
        self.assertEqual(scan_text("发布说明 v1.2.3 已修复导出问题").findings, ())

    def test_multiple_values(self) -> None:
        result = scan_text("电话 13800138000，邮箱 alice@example.com，网关 10.0.0.1")
        self.assertEqual(len(result.findings), 3)
        self.assertEqual([item.type for item in result.findings], ["mobile_cn", "email", "ipv4"])

    def test_findings_sorted_by_offset(self) -> None:
        offsets = [item.offset for item in scan_text("13800138000 和 alice@example.com").findings]
        self.assertEqual(offsets, sorted(offsets))


class ChecksumTests(unittest.TestCase):
    """校验位错的身份证绝不能因为正则命中就判 high。"""

    def test_bad_checksum_is_not_high(self) -> None:
        finding = scan_text("身份证号 " + INVALID_ID).findings[0]
        self.assertEqual(finding.confidence, "medium")
        self.assertEqual(finding.level, "sensitive")
        self.assertFalse(finding.checksum)
        self.assertIn("checksum_fail:mod11", finding.reasons)
        self.assertLess(finding.score, 0.75)

    def test_bad_checksum_without_context_is_low(self) -> None:
        finding = scan_text("编号 " + INVALID_ID).findings[0]
        self.assertEqual(finding.confidence, "low")
        self.assertEqual(finding.level, "general")

    def test_valid_id_without_context_stays_high(self) -> None:
        finding = scan_text("编号 " + VALID_ID).findings[0]
        self.assertEqual(finding.confidence, "high")

    def test_bad_luhn_is_not_high(self) -> None:
        finding = scan_text("卡号 4111111111111112").findings[0]
        self.assertEqual(finding.type, "bank_card")
        self.assertFalse(finding.checksum)
        self.assertNotEqual(finding.confidence, "high")


class ContextWindowTests(unittest.TestCase):
    """上下文关键词前后 20 字符内加权。"""

    def test_keyword_within_window_adds_score(self) -> None:
        near = scan_text("身份证号 " + VALID_ID).findings[0]
        far = scan_text("身份证号" + " " * 40 + VALID_ID).findings[0]
        self.assertGreater(near.score, far.score)
        self.assertTrue(any(reason.startswith("context:") for reason in near.reasons))
        self.assertFalse(any(reason.startswith("context:") for reason in far.reasons))

    def test_context_window_can_be_disabled(self) -> None:
        scanner = Scanner(context_window=0)
        finding = scanner.scan_text("身份证号 " + VALID_ID).findings[0]
        self.assertFalse(any(reason.startswith("context:") for reason in finding.reasons))


class StreamingTests(unittest.TestCase):
    """分块扫描：跨块命中、去重、一致性。"""

    def test_id_split_by_small_chunk_boundary(self) -> None:
        text = "y" * 150 + VALID_ID + "z" * 30
        scanner = Scanner(chunk_size=200, overlap=64)
        result = scanner.scan_text(text)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.offset, 150)
        self.assertEqual(text[finding.offset : finding.end], VALID_ID)

    def test_id_split_by_default_1mb_boundary(self) -> None:
        text = "x" * (DEFAULT_CHUNK_SIZE - 9) + VALID_ID
        result = Scanner().scan_text(text)
        self.assertEqual(result.chunks, 2)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.offset, DEFAULT_CHUNK_SIZE - 9)
        self.assertEqual(text[finding.offset : finding.end], VALID_ID)

    def test_overlap_region_is_deduplicated(self) -> None:
        text = "开头 " + VALID_ID + " 结尾"
        scanner = Scanner(chunk_size=128, overlap=64)
        result = scanner.scan_text(text)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len({item.offset for item in result.findings}), 1)

    def test_chunk_size_does_not_change_findings(self) -> None:
        text = "A " + VALID_ID + " B 13800138000 C alice@example.com D 10.0.0.1"
        reference = [(item.type, item.offset, item.end) for item in Scanner().scan_text(text).findings]
        for size in (128, 200, 4096):
            shrunk = [(item.type, item.offset, item.end) for item in Scanner(chunk_size=size, overlap=64).scan_text(text).findings]
            self.assertEqual(shrunk, reference, "chunk_size=" + str(size))

    def test_multiline_across_chunks(self) -> None:
        text = "\n".join(["第 " + str(index) + " 行" for index in range(200)]) + "\n手机 13800138000\n"
        finding = Scanner(chunk_size=160, overlap=64).scan_text(text).findings[0]
        self.assertEqual(finding.line, 201)
        self.assertEqual(finding.col, 4)

    def test_scan_file_matches_scan_text(self) -> None:
        text = "身份证 " + VALID_ID + "\r\n手机 13800138000\r\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.txt"
            path.write_text(text, encoding="utf-8", newline="")
            result = Scanner().scan_file(path)
        self.assertEqual(result.scanned_chars, len(text))
        self.assertEqual([item.type for item in result.findings], ["cn_id_card", "mobile_cn"])
        self.assertEqual(result.findings[1].line, 2)


class FilterTests(unittest.TestCase):
    """过滤与参数校验。"""

    def test_min_confidence_filters_low(self) -> None:
        text = "编号 " + INVALID_ID
        self.assertEqual(len(Scanner().scan_text(text).findings), 1)
        self.assertEqual(len(Scanner(min_confidence="medium").scan_text(text).findings), 0)

    def test_types_filter(self) -> None:
        text = "电话 13800138000 邮箱 alice@example.com"
        result = Scanner(types=["email"]).scan_text(text)
        self.assertEqual([item.type for item in result.findings], ["email"])

    def test_custom_ruleset(self) -> None:
        ruleset = parse_rules([{"name": "order", "type": "order_no", "regex": "ORD-[0-9]{6}"}])
        result = Scanner(ruleset).scan_text("订单 ORD-123456")
        self.assertEqual(result.findings[0].type, "order_no")

    def test_param_validation(self) -> None:
        with self.assertRaises(ValueError):
            Scanner(chunk_size=10)
        with self.assertRaises(ValueError):
            Scanner(overlap=32)
        with self.assertRaises(ValueError):
            Scanner(chunk_size=64, overlap=64)
        with self.assertRaises(ValueError):
            Scanner(context_window=-1)
        with self.assertRaises(ValueError):
            Scanner(min_confidence="nope")

    def test_count_helper(self) -> None:
        result = scan_text("编号 " + INVALID_ID + " 手机 13800138000")
        self.assertEqual(result.count("low"), 2)
        self.assertEqual(result.count("high"), 1)


class PayloadTests(unittest.TestCase):
    """SPEC 3.2 JSON 契约。"""

    def test_payload_shape(self) -> None:
        payload = scan_text("身份证 " + VALID_ID).to_payload()
        self.assertEqual(payload["schema"], "pii-hits/1.0")
        self.assertIn("source", payload)
        self.assertIn("generated_at", payload)
        self.assertEqual(set(payload["ruleset"]), {"name", "version", "file"})
        self.assertEqual(set(payload["summary"]), {"total", "by_type", "by_confidence", "by_level", "by_action"})
        self.assertTrue(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload["generated_at"]))

    def test_generated_at_injection(self) -> None:
        payload = scan_text("x").to_payload(generated_at="2026-11-08T01:35:00Z")
        self.assertEqual(payload["generated_at"], "2026-11-08T01:35:00Z")

    def test_finding_dict_keys(self) -> None:
        item = scan_text("身份证 " + VALID_ID).findings[0].to_dict()
        self.assertEqual(
            list(item),
            [
                "type",
                "level",
                "confidence",
                "score",
                "offset",
                "end",
                "line",
                "col",
                "length",
                "preview",
                "checksum",
                "reasons",
            ],
        )
        self.assertIsInstance(item["checksum"], bool)

    def test_payload_has_no_raw_values(self) -> None:
        text = "身份证 " + VALID_ID + " 手机 13800138000 卡号 4111111111111111 邮箱 alice@example.com"
        payload = scan_text(text).to_payload()
        dumped = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(VALID_ID, dumped)
        self.assertNotIn("13800138000", dumped)
        self.assertNotIn("4111111111111111", dumped)
        self.assertNotIn("alice@example.com", dumped)
        self.assertIsNone(re.search(r"\d{17}[0-9Xx]", dumped))
        self.assertIsNone(re.search(r"1[3-9]\d{9}", dumped))

    def test_utc_now_format(self) -> None:
        self.assertTrue(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", utc_now()))

    def test_summary_counts(self) -> None:
        result = scan_text("身份证 " + VALID_ID + " 手机 13800138000 网关 10.0.0.1")
        summary = result.summary()
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_level"]["high_sensitive"], 1)
        self.assertEqual(summary["by_type"]["ipv4"], 1)


if __name__ == "__main__":
    unittest.main()
