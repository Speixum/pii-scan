"""report 单元测试：三种格式、JSON 契约、HTML 无外链、写文件。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from piiscan import SCHEMA
from piiscan.report import render, write_report
from piiscan.scanner import scan_text

VALID_ID = "11010519491231002X"
MOBILE = "13800138000"


def sample():
    return scan_text("身份证 " + VALID_ID + "，手机 " + MOBILE + "\n")


class RenderTests(unittest.TestCase):
    """渲染。"""

    def test_table_hides_raw_values(self) -> None:
        text = render(sample(), "table")
        self.assertIn("cn_id_card", text)
        self.assertIn("mobile_cn", text)
        self.assertNotIn(VALID_ID, text)
        self.assertNotIn(MOBILE, text)
        self.assertIn("+", text)

    def test_json_matches_contract(self) -> None:
        payload = json.loads(render(sample(), "json"))
        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(payload["summary"]["total"], 2)
        self.assertEqual(len(payload["findings"]), 2)
        finding = payload["findings"][0]
        for key in (
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
        ):
            self.assertIn(key, finding)
        self.assertNotIn(VALID_ID, json.dumps(payload, ensure_ascii=False))
        self.assertTrue(payload["findings"][0]["checksum"])

    def test_json_generated_at_is_injectable(self) -> None:
        payload = json.loads(render(sample(), "json", generated_at="2026-01-01T00:00:00Z"))
        self.assertEqual(payload["generated_at"], "2026-01-01T00:00:00Z")

    def test_html_is_offline_single_file(self) -> None:
        page = render(sample(), "html")
        self.assertIn("<!DOCTYPE html", page)
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)
        self.assertNotIn("<script", page)
        self.assertNotIn("<link", page)
        self.assertNotIn(VALID_ID, page)
        self.assertIn("<style", page)

    def test_unknown_format_raises(self) -> None:
        with self.assertRaises(ValueError):
            render(sample(), "yaml")


class WriteReportTests(unittest.TestCase):
    """落盘。"""

    def test_write_report_returns_path_and_ends_with_newline(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "hits.json"
            written = write_report(sample(), target, "json")
            self.assertEqual(written, target)
            text = target.read_text(encoding="utf-8")
            self.assertTrue(text.endswith("\n"))
            json.loads(text)

    def test_write_report_html(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "hits.html"
            write_report(sample(), target, "html")
            self.assertIn("<!DOCTYPE html", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
