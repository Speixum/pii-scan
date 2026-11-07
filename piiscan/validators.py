"""敏感值校验器集合。

覆盖：中国大陆 18 位身份证（模 11 + 出生日期）、Luhn 卡号、手机号号段、
IPv4、邮箱、统一社会信用代码（mod 31）。

每个校验函数都返回 :class:`CheckResult`，其中 `code` 是 ASCII 标识
（如 `mod11`、`luhn`），便于直接写进报告的 `reasons` 字段。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Callable, Final, Sequence

__all__ = [
    "CheckResult",
    "VALIDATORS",
    "check_cn_id_card",
    "check_email",
    "check_ipv4",
    "check_luhn",
    "check_mobile_cn",
    "check_nonempty",
    "check_uscc",
    "cn_id_check_digit",
    "get_validator",
    "luhn_check_digit",
    "run_validators",
]

#: 身份证前 17 位的加权因子（GB 11643-1999）。
CN_ID_WEIGHTS: Final[tuple[int, ...]] = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
#: 余数 0..10 对应的校验码。
CN_ID_CHECK_CODES: Final[str] = "10X98765432"
CN_ID_MIN_YEAR: Final[int] = 1800
CN_ID_MAX_YEAR: Final[int] = 2100
CN_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]{17}[0-9Xx]$")

#: 省级行政区划代码（两位）。
CN_PROVINCE_CODES: Final[frozenset[str]] = frozenset(
    {
        "11", "12", "13", "14", "15",
        "21", "22", "23",
        "31", "32", "33", "34", "35", "36", "37",
        "41", "42", "43", "44", "45", "46",
        "50", "51", "52", "53", "54",
        "61", "62", "63", "64", "65",
        "71", "81", "82", "91",
    }
)

MOBILE_RE: Final[re.Pattern[str]] = re.compile(r"^1[3-9][0-9]{9}$")

#: 已启用的 3 位号段。不含 142/143/144/154 等未开放号段。
MOBILE_SEGMENTS: Final[frozenset[str]] = frozenset(
    [str(_p) for _p in range(130, 140)]
    + [str(_p) for _p in range(150, 154)]
    + [str(_p) for _p in range(155, 160)]
    + [str(_p) for _p in range(180, 190)]
    + [
        "145", "146", "147", "148", "149",
        "162", "165", "166", "167",
        "170", "171", "172", "173", "175", "176", "177", "178",
        "191", "192", "193", "195", "196", "197", "198", "199",
    ]
)

#: 统一社会信用代码字符集（31 个字符，剔除 I O S V Z）。
USCC_CHARSET: Final[str] = "0123456789ABCDEFGHJKLMNPQRTUWXY"
USCC_WEIGHTS: Final[tuple[int, ...]] = (
    1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28,
)

_EMAIL_LOCAL_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+)*$"
)
_EMAIL_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$"
)


@dataclass(frozen=True)
class CheckResult:
    """单个校验器的结果。

    属性:
        ok: 是否通过。
        code: ASCII 短标识，通过时形如 `mod11`，失败时同样写 `mod11`，
            由调用方决定是否追加 `:failed`。
        detail: ASCII 说明，可为空。
    """

    ok: bool
    code: str
    detail: str = ""

    def __bool__(self) -> bool:
        """允许直接 `if result:` 判断。"""
        return self.ok


def _ok(code: str, detail: str = "") -> CheckResult:
    return CheckResult(True, code, detail)


def _bad(code: str, detail: str) -> CheckResult:
    return CheckResult(False, code, detail)


def _digits_only(value: str) -> str:
    """去掉常见分隔符（空格、短横线、点），其余字符原样保留。"""
    return value.strip().replace(" ", "").replace("-", "")


def cn_id_check_digit(stem17: str) -> str:
    """按模 11 计算 18 位身份证的校验码，返回单个字符（0-9 或 X）。

    参数:
        stem17: 前 17 位数字。
    异常:
        ValueError: 长度不是 17 或含非数字。
    """
    if len(stem17) != 17 or not stem17.isdigit():
        raise ValueError("cn_id_check_digit expects 17 digits")
    total = sum(int(stem17[i]) * CN_ID_WEIGHTS[i] for i in range(17))
    return CN_ID_CHECK_CODES[total % 11]


def luhn_check_digit(payload: str) -> str:
    """按 Luhn 算法计算追加在末尾的校验位，返回单个数字字符。

    参数:
        payload: 不含校验位的数字串（长度 >= 1）。
    异常:
        ValueError: 空串或含非数字。
    """
    if not payload or not payload.isdigit():
        raise ValueError("luhn_check_digit expects a non-empty digit string")
    total = 0
    for index, char in enumerate(reversed(payload)):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - total % 10) % 10)


def _birth_date_ok(yyyymmdd: str) -> tuple[bool, str]:
    if len(yyyymmdd) != 8 or not yyyymmdd.isdigit():
        return False, "birth date must be 8 digits"
    year, month, day = int(yyyymmdd[0:4]), int(yyyymmdd[4:6]), int(yyyymmdd[6:8])
    if not CN_ID_MIN_YEAR <= year <= CN_ID_MAX_YEAR:
        return False, "birth year out of range"
    try:
        date(year, month, day)
    except ValueError:
        return False, "birth date is not a real calendar date"
    return True, ""


def check_cn_id_card(value: str) -> CheckResult:
    """校验 18 位居民身份证号：省级代码、出生日期、模 11 校验码。"""
    text = value.strip()
    if not CN_ID_RE.match(text):
        return _bad("length", "expect 18 chars: 17 digits plus digit or X")
    if text[0:2] not in CN_PROVINCE_CODES:
        return _bad("province", "unknown province code")
    date_ok, date_detail = _birth_date_ok(text[6:14])
    if not date_ok:
        return _bad("birth_date", date_detail)
    expected = cn_id_check_digit(text[0:17])
    if text[17].upper() != expected:
        return _bad("mod11", "check digit mismatch: expect " + expected)
    return _ok("mod11")


def check_luhn(value: str) -> CheckResult:
    """校验银行卡号（Luhn 算法，允许空格/短横线分隔）。"""
    text = _digits_only(value)
    if not text.isdigit():
        return _bad("length", "card number must contain digits only")
    if not 12 <= len(text) <= 19:
        return _bad("length", "card number length must be 12..19")
    total = 0
    for index, char in enumerate(reversed(text)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    if total % 10 != 0:
        return _bad("luhn", "luhn sum is not divisible by 10")
    return _ok("luhn")


def check_mobile_cn(value: str) -> CheckResult:
    """校验中国大陆手机号：`1[3-9]\d{9}` 加 3 位号段表。"""
    text = _digits_only(value)
    if not MOBILE_RE.match(text):
        return _bad("format", "expect 11 digits matching 1[3-9]dddddddddd")
    prefix = text[0:3]
    if prefix not in MOBILE_SEGMENTS:
        return _bad("segment", "unknown mobile segment " + prefix)
    return _ok("segment")


def check_ipv4(value: str) -> CheckResult:
    """校验 IPv4：四段十进制、每段 0-255、不允许多余前导零。"""
    text = value.strip()
    parts = text.split(".")
    if len(parts) != 4:
        return _bad("parts", "expect 4 octets")
    for part in parts:
        if not part.isdigit():
            return _bad("octet", "octet is not numeric")
        if len(part) > 1 and part[0] == "0":
            return _bad("octet", "octet has a leading zero")
        if len(part) > 3:
            return _bad("range", "octet longer than 3 digits")
        if int(part) > 255:
            return _bad("range", "octet out of range 0..255")
    return _ok("ipv4")


def check_email(value: str) -> CheckResult:
    """校验邮箱：本地部分 + 域名（含点、TLD 2-24 个字母），总长 <= 254。"""
    text = value.strip()
    if len(text) > 254:
        return _bad("length", "email longer than 254 chars")
    local, separator, domain = text.rpartition("@")
    if not separator or not local or not domain:
        return _bad("shape", "email must be local@domain")
    if len(local) > 64:
        return _bad("length", "local part longer than 64 chars")
    if not _EMAIL_LOCAL_RE.match(local):
        return _bad("local", "invalid local part")
    if not _EMAIL_DOMAIN_RE.match(domain):
        return _bad("domain", "invalid domain part")
    return _ok("email")


def check_uscc(value: str) -> CheckResult:
    """校验 18 位统一社会信用代码（mod 31）。"""
    text = value.strip().upper()
    if len(text) != 18:
        return _bad("length", "expect 18 chars")
    for char in text:
        if char not in USCC_CHARSET:
            return _bad("charset", "char outside USCC charset")
    total = 0
    for index in range(17):
        total += USCC_CHARSET.index(text[index]) * USCC_WEIGHTS[index]
    expected = (31 - total % 31) % 31
    if text[17] != USCC_CHARSET[expected]:
        return _bad("mod31", "check char mismatch: expect " + USCC_CHARSET[expected])
    return _ok("mod31")


def check_nonempty(value: str) -> CheckResult:
    """最小校验：非空白字符串。"""
    if value.strip():
        return _ok("nonempty")
    return _bad("empty", "value is empty")


#: 规则文件里 `validators` 可用的名字 -> 实现。
VALIDATORS: Final[dict[str, Callable[[str], CheckResult]]] = {
    "cn_id_card": check_cn_id_card,
    "luhn": check_luhn,
    "mobile_cn": check_mobile_cn,
    "ipv4": check_ipv4,
    "email": check_email,
    "uscc": check_uscc,
    "nonempty": check_nonempty,
}


def get_validator(name: str) -> Callable[[str], CheckResult]:
    """按名字取校验器。

    异常:
        KeyError: 名字未注册，错误信息为 ASCII。
    """
    try:
        return VALIDATORS[name]
    except KeyError:
        raise KeyError("unknown validator: " + str(name)) from None


def run_validators(names: Sequence[str], value: str) -> list[CheckResult]:
    """依次运行一组校验器，返回结果列表（顺序与 `names` 一致）。"""
    return [get_validator(name)(value) for name in names]
