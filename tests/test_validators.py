"""validators 单元测试：身份证模 11、Luhn、手机号段、IPv4 边界、邮箱、USCC。"""

from __future__ import annotations

import unittest

from piiscan.validators import (
    CheckResult,
    VALIDATORS,
    check_cn_id_card,
    check_email,
    check_ipv4,
    check_luhn,
    check_mobile_cn,
    check_nonempty,
    check_uscc,
    cn_id_check_digit,
    get_validator,
    luhn_check_digit,
    run_validators,
)


class CnIdCardTests(unittest.TestCase):
    """18 位身份证：模 11 权重、校验码表、出生日期、省级代码。"""

    def test_valid_upper_x(self) -> None:
        result = check_cn_id_card("11010519491231002X")
        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.code, "mod11")

    def test_valid_lowercase_x(self) -> None:
        self.assertTrue(check_cn_id_card("11010519491231002x").ok)

    def test_valid_classic_sample(self) -> None:
        self.assertTrue(check_cn_id_card("440524188001010014").ok)

    def test_valid_generated_digits(self) -> None:
        stem = "31010119900307123"
        self.assertTrue(check_cn_id_card(stem + cn_id_check_digit(stem)).ok)

    def test_wrong_check_digit_is_rejected(self) -> None:
        result = check_cn_id_card("110105194912310021")
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "mod11")
        self.assertIn("expect X", result.detail)

    def test_wrong_length_is_rejected(self) -> None:
        result = check_cn_id_card("1101051949123002")
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "length")

    def test_unknown_province_is_rejected(self) -> None:
        stem = "99010519491231002"
        result = check_cn_id_card(stem + cn_id_check_digit(stem))
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "province")

    def test_impossible_birth_date_is_rejected(self) -> None:
        stem = "11010519901301002"  # 13 月
        result = check_cn_id_card(stem + cn_id_check_digit(stem))
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "birth_date")

    def test_birth_year_out_of_range(self) -> None:
        stem = "11010517000101002"  # 1700 年
        result = check_cn_id_card(stem + cn_id_check_digit(stem))
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "birth_date")

    def test_check_digit_helper_matches_table(self) -> None:
        self.assertEqual(cn_id_check_digit("11010519491231002"), "X")
        self.assertEqual(cn_id_check_digit("44052418800101001"), "4")

    def test_check_digit_helper_rejects_bad_input(self) -> None:
        with self.assertRaises(ValueError):
            cn_id_check_digit("1234")
        with self.assertRaises(ValueError):
            cn_id_check_digit("1101051949123100X")


class LuhnTests(unittest.TestCase):
    """Luhn 卡号校验与补位。"""

    def test_visa_sample(self) -> None:
        self.assertTrue(check_luhn("4111111111111111").ok)

    def test_mastercard_sample(self) -> None:
        self.assertTrue(check_luhn("5500005555555559").ok)

    def test_spaces_are_ignored(self) -> None:
        self.assertTrue(check_luhn("4111 1111 1111 1111").ok)

    def test_bad_checksum(self) -> None:
        result = check_luhn("4111111111111112")
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "luhn")

    def test_too_short(self) -> None:
        self.assertEqual(check_luhn("4111").code, "length")

    def test_non_digits(self) -> None:
        self.assertEqual(check_luhn("4111-abcd-1111").code, "length")

    def test_luhn_check_digit_helper(self) -> None:
        self.assertEqual(luhn_check_digit("411111111111111"), "1")
        self.assertEqual(luhn_check_digit("7992739871"), "3")


class MobileTests(unittest.TestCase):
    """手机号：格式 + 号段表。"""

    def test_known_segment(self) -> None:
        result = check_mobile_cn("13800138000")
        self.assertTrue(result.ok)
        self.assertEqual(result.code, "segment")

    def test_19999999999_segment_ok(self) -> None:
        self.assertTrue(check_mobile_cn("19999999999").ok)

    def test_unopened_segment(self) -> None:
        result = check_mobile_cn("14200000000")
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "segment")

    def test_bad_prefix(self) -> None:
        self.assertEqual(check_mobile_cn("12345678901").code, "format")

    def test_bad_length(self) -> None:
        self.assertEqual(check_mobile_cn("1380013800").code, "format")
        self.assertEqual(check_mobile_cn("138001380001").code, "format")


class Ipv4Tests(unittest.TestCase):
    """IPv4：每段 0-255、四段、禁止前导零。"""

    def test_lower_bound(self) -> None:
        self.assertTrue(check_ipv4("0.0.0.0").ok)

    def test_upper_bound(self) -> None:
        self.assertTrue(check_ipv4("255.255.255.255").ok)

    def test_octet_out_of_range(self) -> None:
        result = check_ipv4("256.0.0.1")
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "range")

    def test_leading_zero_rejected(self) -> None:
        self.assertEqual(check_ipv4("01.2.3.4").code, "octet")

    def test_wrong_parts(self) -> None:
        self.assertEqual(check_ipv4("1.2.3").code, "parts")
        self.assertEqual(check_ipv4("1.2.3.4.5").code, "parts")

    def test_non_numeric_octet(self) -> None:
        self.assertEqual(check_ipv4("1.2.3.a").code, "octet")


class EmailTests(unittest.TestCase):
    """邮箱：本地部分 + 域名 + TLD。"""

    def test_simple(self) -> None:
        self.assertTrue(check_email("alice@example.com").ok)

    def test_missing_tld(self) -> None:
        self.assertEqual(check_email("alice@localhost").code, "domain")

    def test_missing_domain(self) -> None:
        self.assertEqual(check_email("alice@").code, "shape")

    def test_double_dot_local(self) -> None:
        self.assertEqual(check_email("a..b@example.com").code, "local")

    def test_too_long(self) -> None:
        self.assertEqual(check_email("a" * 250 + "@example.com").code, "length")


class UsccTests(unittest.TestCase):
    """统一社会信用代码：mod 31。"""

    def test_known_valid_codes(self) -> None:
        self.assertTrue(check_uscc("91330100799655058B").ok)
        self.assertTrue(check_uscc("91350100M000100Y43").ok)

    def test_bad_check_char(self) -> None:
        result = check_uscc("91330100799655058C")
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "mod31")

    def test_bad_length(self) -> None:
        self.assertEqual(check_uscc("9133").code, "length")

    def test_charset(self) -> None:
        self.assertEqual(check_uscc("91330100799655O58B").code, "charset")


class RegistryTests(unittest.TestCase):
    """校验器注册表与组合调用。"""

    def test_check_result_is_truthy(self) -> None:
        self.assertTrue(CheckResult(True, "ok"))
        self.assertFalse(CheckResult(False, "bad"))

    def test_registry_covers_documented_names(self) -> None:
        for name in ("cn_id_card", "luhn", "mobile_cn", "ipv4", "email", "uscc", "nonempty"):
            self.assertIn(name, VALIDATORS)

    def test_unknown_validator_message_is_ascii(self) -> None:
        with self.assertRaises(KeyError) as ctx:
            get_validator("nope")
        self.assertIn("unknown validator", str(ctx.exception))
        str(ctx.exception).encode("ascii")

    def test_run_validators_keeps_order(self) -> None:
        results = run_validators(["nonempty", "luhn"], "4111111111111111")
        self.assertEqual([item.code for item in results], ["nonempty", "luhn"])

    def test_nonempty(self) -> None:
        self.assertFalse(check_nonempty("   ").ok)


if __name__ == "__main__":
    unittest.main()
