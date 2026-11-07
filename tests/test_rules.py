"""rules 单元测试：内置规则、自定义 JSON/TOML、非法规则报错。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from piiscan.rules import (
    PREVIEW_MODES,
    Rule,
    RuleError,
    RuleSet,
    builtin_rule_path,
    describe_rules,
    load_rules,
    parse_rules,
    rule_names,
)


class BuiltinRulesTests(unittest.TestCase):
    """内置规则集是默认口径。"""

    def test_builtin_metadata(self) -> None:
        ruleset = load_rules()
        self.assertEqual(ruleset.name, "builtin")
        self.assertEqual(ruleset.version, "1.0")
        self.assertIsNone(ruleset.file)

    def test_builtin_rule_count_and_names(self) -> None:
        ruleset = load_rules()
        self.assertEqual(len(ruleset.rules), 6)
        self.assertEqual(
            set(rule_names(ruleset)),
            {"cn_id_card", "bank_card", "mobile_cn", "email", "uscc", "ipv4"},
        )

    def test_builtin_rule_fields(self) -> None:
        rule = load_rules().by_name("cn_id_card")
        self.assertEqual(rule.type, "cn_id_card")
        self.assertEqual(rule.level, "high_sensitive")
        self.assertEqual(rule.validators, ("cn_id_card",))
        self.assertAlmostEqual(rule.weight, 0.55)
        self.assertEqual(rule.preview, "head4_tail4")
        self.assertIn("身份证", rule.context_keywords)

    def test_builtin_path_exists(self) -> None:
        self.assertTrue(builtin_rule_path().is_file())

    def test_every_builtin_rule_compiles(self) -> None:
        for rule in load_rules().rules:
            self.assertIsNotNone(rule.compiled)

    def test_meta_payload(self) -> None:
        meta = load_rules().meta()
        self.assertEqual(set(meta), {"name", "version", "file"})
        self.assertEqual(meta["name"], "builtin")

    def test_by_name_errors(self) -> None:
        ruleset = load_rules()
        with self.assertRaises(KeyError):
            ruleset.by_name("missing")

    def test_describe_rules(self) -> None:
        rows = describe_rules(load_rules())
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0]["validators"], "cn_id_card")
        rows[0]["weight"].encode("ascii")


class CustomRulesTests(unittest.TestCase):
    """自定义规则：JSON 和 TOML 都能加载。"""

    def test_parse_minimal_dict(self) -> None:
        ruleset = parse_rules(
            {
                "name": "demo",
                "version": "2",
                "rules": [{"name": "emp", "type": "employee_id", "regex": "EMP-[0-9]{6}"}],
            }
        )
        self.assertEqual(ruleset.name, "demo")
        self.assertEqual(ruleset.version, "2")
        rule = ruleset.rules[0]
        self.assertEqual(rule.name, "emp")
        self.assertEqual(rule.level, "sensitive")
        self.assertAlmostEqual(rule.weight, 0.5)
        self.assertEqual(rule.preview, "head3_tail4")
        self.assertEqual(rule.validators, ())

    def test_parse_bare_list(self) -> None:
        ruleset = parse_rules([{"name": "a", "type": "a", "regex": "A-1"}])
        self.assertEqual(ruleset.name, "custom")

    def test_load_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(
                json.dumps(
                    {
                        "name": "file-demo",
                        "version": "1.1",
                        "rules": [
                            {
                                "name": "ticket",
                                "type": "ticket_no",
                                "regex": "TICKET-[0-9]{4}",
                                "validators": ["nonempty"],
                                "context_keywords": ["工单"],
                                "weight": 0.7,
                                "level": "sensitive",
                                "preview": "head1_tail1",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            ruleset = load_rules(path)
            self.assertEqual(ruleset.name, "file-demo")
            self.assertEqual(ruleset.file, str(path))
            self.assertEqual(ruleset.rules[0].context_keywords, ("工单",))

    def test_load_toml_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.toml"
            path.write_text(
                "name = \"toml-demo\"\n"
                "version = \"1.0\"\n"
                "[[rules]]\n"
                "name = \"order\"\n"
                "type = \"order_no\"\n"
                "regex = \"ORD-[0-9]{6}\"\n"
                "level = \"general\"\n"
                "weight = 0.3\n",
                encoding="utf-8",
            )
            ruleset = load_rules(path)
            self.assertEqual(ruleset.name, "toml-demo")
            self.assertEqual(ruleset.rules[0].level, "general")
            self.assertAlmostEqual(ruleset.rules[0].weight, 0.3)

    def test_preview_modes_are_defined(self) -> None:
        self.assertIn("head4_tail4", PREVIEW_MODES)
        self.assertIn("email", PREVIEW_MODES)


class InvalidRulesTests(unittest.TestCase):
    """非法规则必须报 RuleError，且错误信息是 ASCII。"""

    def assert_rule_error(self, document: object, needle: str = "") -> None:
        with self.assertRaises(RuleError) as ctx:
            parse_rules(document, source="bad.json")
        self.assertIn("bad.json", str(ctx.exception))
        self.assertIn(needle, str(ctx.exception))
        str(ctx.exception).encode("ascii")

    def test_missing_field(self) -> None:
        self.assert_rule_error({"rules": [{"name": "x", "regex": "X"}]}, "type")

    def test_unknown_field(self) -> None:
        self.assert_rule_error(
            {"rules": [{"name": "x", "type": "x", "regex": "X", "bogus": 1}]}, "unknown field"
        )

    def test_duplicate_names(self) -> None:
        self.assert_rule_error(
            {
                "rules": [
                    {"name": "x", "type": "x", "regex": "X"},
                    {"name": "x", "type": "x", "regex": "Y"},
                ]
            },
            "duplicate",
        )

    def test_unknown_validator(self) -> None:
        self.assert_rule_error(
            {"rules": [{"name": "x", "type": "x", "regex": "X", "validators": ["nope"]}]},
            "unknown validator",
        )

    def test_weight_out_of_range(self) -> None:
        self.assert_rule_error(
            {"rules": [{"name": "x", "type": "x", "regex": "X", "weight": 1.5}]}, "0..1"
        )

    def test_bad_level(self) -> None:
        self.assert_rule_error(
            {"rules": [{"name": "x", "type": "x", "regex": "X", "level": "critical"}]}, "level"
        )

    def test_bad_preview(self) -> None:
        self.assert_rule_error(
            {"rules": [{"name": "x", "type": "x", "regex": "X", "preview": "nope"}]}, "preview"
        )

    def test_invalid_regex(self) -> None:
        self.assert_rule_error({"rules": [{"name": "x", "type": "x", "regex": "("}]}, "invalid regex")

    def test_empty_match_regex(self) -> None:
        self.assert_rule_error(
            {"rules": [{"name": "x", "type": "x", "regex": "a?"}]}, "empty string"
        )

    def test_empty_rule_list(self) -> None:
        self.assert_rule_error({"rules": []}, "non-empty")

    def test_wrong_document_shape(self) -> None:
        self.assert_rule_error("not a document", "must be an object")

    def test_missing_file(self) -> None:
        with self.assertRaises(RuleError):
            load_rules("no-such-rules.json")

    def test_unsupported_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.yaml"
            path.write_text("rules: []", encoding="utf-8")
            with self.assertRaises(RuleError):
                load_rules(path)

    def test_rule_is_hashable_and_frozen(self) -> None:
        rule = parse_rules([{"name": "a", "type": "a", "regex": "A"}]).rules[0]
        self.assertIsInstance(rule, Rule)
        hash(rule)
        with self.assertRaises(Exception):
            rule.name = "b"  # type: ignore[misc]

    def test_ruleset_meta_file_name(self) -> None:
        ruleset = RuleSet(name="n", version="v", file=None, rules=())
        self.assertEqual(ruleset.meta(), {"name": "n", "version": "v", "file": None})


if __name__ == "__main__":
    unittest.main()
