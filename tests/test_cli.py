"""CLI 端到端测试：子命令、退出码、-o/--strategy 别名、规则校验。"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from piiscan.cli import main

VALID_ID = "11010519491231002X"
MOBILE = "13800138000"


def run(argv):
    """调用 main()，返回 (退出码, stdout, stderr)。"""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    """命令行行为。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.note = self.base / "note.txt"
        self.note.write_text("身份证 " + VALID_ID + "\n手机 " + MOBILE + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_scan_table_runs(self) -> None:
        code, out, _ = run(["scan", str(self.note)])
        self.assertEqual(code, 0)
        self.assertIn("cn_id_card", out)

    def test_scan_json_to_file_with_short_out_flag(self) -> None:
        target = self.base / "hits.json"
        code, out, _ = run(["scan", str(self.note), "--format", "json", "-o", str(target)])
        self.assertEqual(code, 0)
        self.assertTrue(target.is_file())
        self.assertIn("report written", out)
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "pii-hits/1.0")
        self.assertEqual(payload["summary"]["total"], 2)

    def test_scan_fail_on_high_exits_2(self) -> None:
        code, _, _ = run(["scan", str(self.note), "--format", "json", "--fail-on", "high"])
        self.assertEqual(code, 2)

    def test_scan_clean_file_exits_0_with_fail_on(self) -> None:
        clean = self.base / "clean.txt"
        clean.write_text("nothing sensitive here\n", encoding="utf-8")
        code, _, _ = run(["scan", str(clean), "--fail-on", "high"])
        self.assertEqual(code, 0)

    def test_scan_missing_file_exits_1(self) -> None:
        code, _, err = run(["scan", str(self.base / "nope.txt")])
        self.assertEqual(code, 1)
        self.assertIn("cannot read input", err)

    def test_scan_type_filter(self) -> None:
        code, out, _ = run(["scan", str(self.note), "--format", "json", "--type", "mobile_cn", "-o", str(self.base / "m.json")])
        self.assertEqual(code, 0)
        payload = json.loads((self.base / "m.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["findings"][0]["type"], "mobile_cn")

    def test_mask_strategy_alias_hashes_file(self) -> None:
        target = self.base / "note.masked.txt"
        code, out, _ = run(["mask", str(self.note), "-o", str(target), "--strategy", "hash", "--salt", "demo"])
        self.assertEqual(code, 0)
        text = target.read_text(encoding="utf-8")
        self.assertNotIn(VALID_ID, text)
        self.assertNotIn(MOBILE, text)
        self.assertIn("sha256:", text)
        self.assertIn("total: 2", out)

    def test_mask_dry_run_writes_nothing(self) -> None:
        target = self.base / "dry.txt"
        code, out, _ = run(["mask", str(self.note), "-o", str(target), "--dry-run"])
        self.assertEqual(code, 0)
        self.assertFalse(target.exists())
        self.assertIn("dry-run", out)

    def test_mask_refuses_overwrite_without_in_place(self) -> None:
        code, _, err = run(["mask", str(self.note), "-o", str(self.note)])
        self.assertEqual(code, 1)
        self.assertIn("overwrite", err)

    def test_rules_list_json(self) -> None:
        code, out, _ = run(["rules", "list", "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        names = {rule["name"] for rule in payload["rules"]}
        self.assertTrue({"cn_id_card", "bank_card", "mobile_cn", "email"} <= names)

    def test_rules_check_builtin_ok(self) -> None:
        code, out, _ = run(["rules", "check"])
        self.assertEqual(code, 0)
        self.assertIn("OK: ruleset is valid", out)

    def test_rules_check_rejects_broken_json(self) -> None:
        bad = self.base / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        code, _, err = run(["rules", "check", "--rules", str(bad)])
        self.assertEqual(code, 1)
        self.assertIn("invalid", err)

    def test_bad_custom_rules_fail_scan(self) -> None:
        bad = self.base / "bad_rule.json"
        bad.write_text(json.dumps({"rules": [{"name": "x", "type": "x", "regex": "("}]}), encoding="utf-8")
        code, _, err = run(["scan", str(self.note), "--rules", str(bad)])
        self.assertEqual(code, 1)
        self.assertIn("invalid ruleset", err)


if __name__ == "__main__":
    unittest.main()
