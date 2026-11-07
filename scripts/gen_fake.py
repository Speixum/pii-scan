"""生成明显虚构的演示数据（零第三方依赖、固定随机种子、可重复）。

用法（在仓库根目录）::

    python scripts/gen_fake.py                       # 写 data/sample.txt
    python scripts/gen_fake.py --out data/sample.txt --meta data/meta.json

数据全部为构造值：手机号形如 `1xx00000000`，邮箱只用 `@example.com`，
姓名只用张三/李四/王五；身份证是本地计算校验位得到的假号，
其中 5 条故意写错校验位，便于验证"错校验不得判 high"。

生成的 JSON/HTML 扫描产物不入库（`data/*.json` 等在 .gitignore 中）；`data/sample.txt` 作为演示 fixture 保留，内容全部是虚构值。
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Any, Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from piiscan.validators import (  # noqa: E402  (需要先补 sys.path)
    USCC_CHARSET,
    USCC_WEIGHTS,
    check_cn_id_card,
    check_luhn,
    cn_id_check_digit,
    luhn_check_digit,
)

__all__ = [
    "FAKE_EMAIL_DOMAIN",
    "FAKE_NAMES",
    "INVALID_ID_COUNT",
    "VALID_ID_COUNT",
    "build_dataset",
    "main",
    "render_text",
    "uscc_check_char",
]

#: 只用这三个虚构人名。
FAKE_NAMES: tuple[str, ...] = ("张三", "李四", "王五")
#: 邮箱域名固定为保留域，永远不会投递到真实地址。
FAKE_EMAIL_DOMAIN = "example.com"
#: 校验位正确的身份证条数。
VALID_ID_COUNT = 20
#: 故意写错校验位的身份证条数。
INVALID_ID_COUNT = 5
#: 手机号条数。
PHONE_COUNT = 30
#: Luhn 合法卡号条数。
CARD_COUNT = 10

_PROVINCES: tuple[str, ...] = ("110105", "310101", "440305", "510107", "330106")
_PHONE_SEGMENTS: tuple[str, ...] = (
    "130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
    "150", "151", "152", "153", "155", "156", "158", "159",
    "180", "181", "185", "186", "187", "188", "189",
    "145", "170", "171", "173", "176", "177", "178",
)
_ADDRESSES: tuple[str, ...] = (
    "北京市朝阳区示例路 1 号",
    "上海市黄浦区样例街 88 号",
    "深圳市南山区演示大道 100 号",
    "成都市武侯区虚构巷 7 号",
    "杭州市西湖区测试路 42 号",
)
_EMAIL_LOCALS: tuple[str, ...] = (
    "zhangsan", "lisi", "wangwu", "demo.user", "sample.user", "test.user",
    "contact", "support", "sales", "ops",
)


def uscc_check_char(first17: str) -> str:
    """按 GB 32100 计算 18 位统一社会信用代码的第 18 位。

    异常:
        ValueError: 前 17 位含字符集外的字符。
    """
    if len(first17) != 17:
        raise ValueError("uscc body must be 17 characters")
    total = 0
    for index, char in enumerate(first17):
        if char not in USCC_CHARSET:
            raise ValueError("char outside USCC charset: " + char)
        total += USCC_CHARSET.index(char) * USCC_WEIGHTS[index]
    return USCC_CHARSET[(31 - total % 31) % 31]


def _random_date(rng: random.Random) -> tuple[int, int, int]:
    year = rng.randint(1960, 2004)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    return year, month, day


def _make_id(rng: random.Random) -> str:
    year, month, day = _random_date(rng)
    stem = (
        rng.choice(_PROVINCES)
        + format(year, "04d")
        + format(month, "02d")
        + format(day, "02d")
        + format(rng.randint(1, 99), "03d")
    )
    return stem + cn_id_check_digit(stem)


def _break_check_digit(value: str, rng: random.Random) -> str:
    """把末位换成另一个字符，保证模 11 校验必然失败。

    同时要求 Luhn 也不通过：否则这条 18 位数字会被 bank_card 规则（16-19 位
    + Luhn）命中并判成 high，不利于演示"错校验身份证不得判 high"。
    """
    correct = value[-1]
    candidates = [
        char
        for char in "0123456789X"
        if char != correct and not check_luhn(value[:-1] + char)
    ]
    if not candidates:
        raise ValueError("cannot break check digit for: " + value)
    return value[:-1] + rng.choice(candidates)


def _make_card(rng: random.Random) -> str:
    body = "4" + "".join(str(rng.randint(0, 9)) for _ in range(14))
    return body + luhn_check_digit(body)


def _make_phone(index: int) -> str:
    segment = _PHONE_SEGMENTS[index % len(_PHONE_SEGMENTS)]
    return segment + "00000000"


def build_dataset(seed: int = 20261108) -> dict[str, Any]:
    """构造演示数据集（纯虚构）。

    返回:
        含以下键的字典：`names`、`valid_ids`、`invalid_ids`、`phones`、
        `cards`、`emails`、`addresses`、`uscc`、`records`（每条客户档案）。
    """
    rng = random.Random(seed)
    valid_ids: list[str] = []
    while len(valid_ids) < VALID_ID_COUNT:
        candidate = _make_id(rng)
        if candidate not in valid_ids and check_cn_id_card(candidate):
            valid_ids.append(candidate)
    invalid_ids: list[str] = []
    while len(invalid_ids) < INVALID_ID_COUNT:
        candidate = _break_check_digit(_make_id(rng), rng)
        if candidate not in invalid_ids and candidate not in valid_ids and not check_cn_id_card(candidate):
            invalid_ids.append(candidate)
    phones = [_make_phone(index) for index in range(PHONE_COUNT)]
    cards: list[str] = []
    while len(cards) < CARD_COUNT:
        candidate = _make_card(rng)
        if candidate not in cards:
            cards.append(candidate)
    emails = [
        _EMAIL_LOCALS[index % len(_EMAIL_LOCALS)] + format(index, "02d") + "@" + FAKE_EMAIL_DOMAIN
        for index in range(VALID_ID_COUNT)
    ]
    uscc: list[str] = []
    for body in ("91110108MA01ABCDE", "9133010079965505B"):
        uscc.append(body + uscc_check_char(body))
    addresses = [rng.choice(_ADDRESSES) for _ in range(VALID_ID_COUNT)]
    records = [
        {
            "name": FAKE_NAMES[index % len(FAKE_NAMES)],
            "id_card": valid_ids[index],
            "phone": phones[index],
            "email": emails[index],
            "address": addresses[index],
        }
        for index in range(VALID_ID_COUNT)
    ]
    return {
        "names": list(FAKE_NAMES),
        "valid_ids": valid_ids,
        "invalid_ids": invalid_ids,
        "phones": phones,
        "cards": cards,
        "emails": emails,
        "addresses": addresses,
        "uscc": uscc,
        "records": records,
    }


def render_text(dataset: dict[str, Any]) -> str:
    """把数据集渲染成一段带正常文本的演示文件内容。"""
    lines: list[str] = [
        "示例数据（全部虚构，仅用于 pii-scan 演示，请勿用于真实场景）",
        "生成器：scripts/gen_fake.py",
        "",
        "一、客户档案（身份证校验位正确）",
    ]
    for index, record in enumerate(dataset["records"], start=1):
        lines.append(
            format(index, "02d")
            + ". "
            + record["name"]
            + "，身份证号 "
            + record["id_card"]
            + "，手机 "
            + record["phone"]
            + "，邮箱 "
            + record["email"]
            + "，地址 "
            + record["address"]
        )
    lines.extend(["", "二、故意写错校验位的身份证（不得判为 high）"])
    for index, value in enumerate(dataset["invalid_ids"], start=1):
        lines.append("身份证错号样本 " + format(index, "02d") + "：" + value)
    lines.extend(["", "三、支付卡号（Luhn 合法，纯构造）"])
    for index, card in enumerate(dataset["cards"], start=1):
        lines.append("卡号 " + format(index, "02d") + "：" + card)
    lines.extend(["", "四、联系方式清单（手机号均为 1xx00000000 形态）"])
    chunk: list[str] = []
    for phone in dataset["phones"]:
        chunk.append(phone)
        if len(chunk) == 3:
            lines.append("联系方式：" + "、".join(chunk))
            chunk = []
    if chunk:
        lines.append("联系方式：" + "、".join(chunk))
    lines.extend(["", "五、统一社会信用代码（虚构）"])
    for index, code in enumerate(dataset["uscc"], start=1):
        lines.append("统一社会信用代码 " + format(index, "02d") + "：" + code)
    lines.extend(
        [
            "",
            "六、服务器与网络信息",
            "网关 10.0.0.1，内网 DNS 192.168.0.53，备用 172.16.31.4。",
            "",
            "七、正常文本（不应命中任何敏感信息）",
            "发布说明：v1.2.3 修复了导出的时间格式问题，订单号 ORD-20261108-0001 已补发。",
            "库存 1200 件，单价 19.90 元，折扣 0.85，合计 2026-11-08 更新。",
            "请勿把本文件用于生产；如需扩展规则，参考 examples/custom_rules.json。",
            "",
        ]
    )
    return "\n".join(lines)


def _summary_rows(dataset: dict[str, Any]) -> list[list[str]]:
    return [
        ["valid_id_card", str(len(dataset["valid_ids"]))],
        ["invalid_id_card", str(len(dataset["invalid_ids"]))],
        ["mobile_cn", str(len(dataset["phones"]))],
        ["bank_card", str(len(dataset["cards"]))],
        ["email", str(len(dataset["emails"]))],
        ["address", str(len(dataset["addresses"]))],
        ["uscc", str(len(dataset["uscc"]))],
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """CLI：生成演示数据文件。"""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    parser = argparse.ArgumentParser(
        prog="gen_fake.py",
        description="Generate clearly fake PII sample data for the pii-scan demo.",
    )
    parser.add_argument("--out", default=str(_ROOT / "data" / "sample.txt"), metavar="PATH", help="output text file")
    parser.add_argument("--meta", metavar="PATH", help="also dump the generated values as JSON")
    parser.add_argument("--seed", type=int, default=20261108, help="random seed (default: 20261108)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    dataset = build_dataset(args.seed)
    text = render_text(dataset)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8", newline="\n")
    if args.meta:
        import json

        meta_path = Path(args.meta)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(
            json.dumps(dataset, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    print("generated: " + str(out_path) + " (" + str(len(text.splitlines())) + " lines)")
    print("+-----------------+-------+")
    print("| kind            | count |")
    print("+-----------------+-------+")
    for kind, count in _summary_rows(dataset):
        print("| " + kind.ljust(15) + " | " + count.rjust(5) + " |")
    print("+-----------------+-------+")
    if args.meta:
        print("meta: " + str(args.meta))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
