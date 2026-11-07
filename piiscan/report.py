"""报告渲染：ASCII 表格、JSON、单文件 HTML（零外链、零第三方）。

三种格式都只输出掩码后的 `preview`，绝不会把命中原文写进报告。
"""

from __future__ import annotations

import html
import json
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import SCHEMA
from .scanner import Finding, ScanResult, utc_now

__all__ = [
    "FORMATS",
    "ascii_grid",
    "render",
    "render_html",
    "render_json",
    "render_table",
    "write_report",
]

#: 支持的输出格式。
FORMATS: tuple[str, ...] = ("table", "json", "html")

_WIDE = ("W", "F")


def _cell_width(text: str) -> int:
    """控制台显示宽度：中日韩全角字符按 2 列计。"""
    return sum(2 if unicodedata.east_asian_width(char) in _WIDE else 1 for char in text)


def _pad(text: str, width: int, align: str = "left") -> str:
    filler = " " * max(0, width - _cell_width(text))
    if align == "right":
        return filler + text
    if align == "center":
        left = len(filler) // 2
        return " " * left + text + " " * (len(filler) - left)
    return text + filler


def ascii_grid(headers: Sequence[str], rows: Iterable[Sequence[str]], aligns: Sequence[str] | None = None) -> str:
    """把二维数据渲染成 ASCII 表格（只用 + - |，中文按两列宽对齐）。"""
    body = [[str(cell) for cell in row] for row in rows]
    columns = len(headers)
    widths = [_cell_width(header) for header in headers]
    for row in body:
        for index in range(columns):
            widths[index] = max(widths[index], _cell_width(row[index] if index < len(row) else ""))
    align_list = list(aligns) if aligns else ["left"] * columns
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def render_row(cells: Sequence[str]) -> str:
        padded = [
            _pad(cells[index] if index < len(cells) else "", widths[index], align_list[index])
            for index in range(columns)
        ]
        return "| " + " | ".join(padded) + " |"

    lines = [border, render_row(headers), border]
    lines.extend(render_row(row) for row in body)
    lines.append(border)
    return "\n".join(lines)


def _identity(result: ScanResult) -> str:
    return result.ruleset.name + " " + result.ruleset.version


def render_table(result: ScanResult, *, title: str = "pii-scan report") -> str:
    """渲染人读的 ASCII 报告：文件信息 + 命中表 + 类型统计。"""
    payload = result.summary()
    head = [
        title,
        "source: " + result.source,
        "ruleset: " + _identity(result),
        "scanned: " + str(result.scanned_chars) + " chars in " + str(result.chunks) + " chunk(s)",
    ]
    rows = []
    for index, item in enumerate(result.findings, start=1):
        rows.append(
            [
                str(index),
                item.type,
                item.level,
                item.confidence,
                format(item.score, ".2f"),
                str(item.line) + ":" + str(item.col),
                str(item.length),
                "-" if item.checksum is None else ("ok" if item.checksum else "fail"),
                item.preview,
            ]
        )
    table = ascii_grid(
        ["#", "TYPE", "LEVEL", "CONF", "SCORE", "LINE:COL", "LEN", "CHECK", "PREVIEW"],
        rows,
        ["right", "left", "left", "left", "right", "right", "right", "left", "left"],
    )
    blocks = ["\n".join(head), "", table]
    type_rows = [[name, str(count)] for name, count in payload["by_type"].items()]
    if type_rows:
        blocks.extend(["", ascii_grid(["TYPE", "COUNT"], type_rows, ["left", "right"])])
    blocks.append("")
    blocks.append(
        "total: "
        + str(payload["total"])
        + " | high: "
        + str(payload["by_confidence"]["high"])
        + " medium: "
        + str(payload["by_confidence"]["medium"])
        + " low: "
        + str(payload["by_confidence"]["low"])
    )
    return "\n".join(blocks)


def render_json(result: ScanResult, *, generated_at: str | None = None) -> str:
    """渲染 SPEC 3.2 的 JSON 报告（UTF-8、ensure_ascii=False、缩进 2）。"""
    payload = result.to_payload(generated_at=generated_at or utc_now())
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _html_rows(findings: Sequence[Finding]) -> str:
    if not findings:
        return '<tr><td colspan="8" class="empty">no findings</td></tr>'
    cells: list[str] = []
    for index, item in enumerate(findings, start=1):
        cells.append(
            "<tr>"
            + '<td class="num">' + str(index) + "</td>"
            + "<td>" + html.escape(item.type) + "</td>"
            + '<td><span class="lv lv-' + html.escape(item.level) + '">' + html.escape(item.level) + "</span></td>"
            + "<td>" + html.escape(item.confidence) + "</td>"
            + '<td class="num">' + format(item.score, ".2f") + "</td>"
            + '<td class="num">' + str(item.line) + ":" + str(item.col) + "</td>"
            + '<td class="num">' + str(item.length) + "</td>"
            + '<td class="mono">' + html.escape(item.preview) + "</td>"
            + "</tr>"
        )
    return "".join(cells)


def _html_summary(summary: dict[str, Any]) -> str:
    parts = ["<li>total: " + str(summary["total"]) + "</li>"]
    for name, count in summary["by_level"].items():
        parts.append("<li>" + html.escape(name) + ": " + str(count) + "</li>")
    for name, count in summary["by_confidence"].items():
        parts.append("<li>confidence " + html.escape(name) + ": " + str(count) + "</li>")
    return "".join(parts)


def render_html(result: ScanResult, *, generated_at: str | None = None, title: str = "pii-scan report") -> str:
    """渲染单文件 HTML（内联样式、无脚本、无任何外链资源）。"""
    stamp = generated_at or utc_now()
    summary = result.summary()
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>" + html.escape(title) + "</title>\n"
        "<style>\n"
        "body{font-family:Segoe UI,-apple-system,system-ui,sans-serif;margin:2rem;color:#1b1b1b;background:#fff}\n"
        "h1{font-size:1.4rem;margin:0 0 .4rem}\n"
        ".meta{color:#555;font-size:.85rem;margin:0 0 1.2rem}\n"
        "table{border-collapse:collapse;width:100%;font-size:.9rem}\n"
        "th,td{border:1px solid #d0d0d0;padding:.35rem .5rem;text-align:left}\n"
        "th{background:#f3f3f3}\n"
        "td.num{text-align:right;font-variant-numeric:tabular-nums}\n"
        "td.mono{font-family:Consolas,monospace}\n"
        "td.empty{text-align:center;color:#777}\n"
        ".lv{display:inline-block;padding:.05rem .4rem;border-radius:.7rem;font-size:.78rem;border:1px solid}\n"
        ".lv-high_sensitive{background:#fde8e8;border-color:#e6a3a3}\n"
        ".lv-sensitive{background:#fdf4e3;border-color:#e2c089}\n"
        ".lv-general{background:#e9f2fb;border-color:#a9c6e4}\n"
        ".stats{margin:1.2rem 0 0;padding-left:1.2rem;font-size:.9rem;color:#333}\n"
        "</style>\n</head>\n<body>\n"
        "<h1>" + html.escape(title) + "</h1>\n"
        '<p class="meta">source: ' + html.escape(result.source) + " | ruleset: " + html.escape(_identity(result))
        + " | scanned: " + str(result.scanned_chars) + " chars | generated_at: " + html.escape(stamp) + " | schema: "
        + html.escape(SCHEMA) + "</p>\n"
        "<table>\n<thead><tr><th>#</th><th>TYPE</th><th>LEVEL</th><th>CONF</th><th>SCORE</th>"
        "<th>LINE:COL</th><th>LEN</th><th>PREVIEW</th></tr></thead>\n<tbody>\n"
        + _html_rows(result.findings)
        + "\n</tbody>\n</table>\n"
        '<ul class="stats">' + _html_summary(summary) + "</ul>\n"
        "</body>\n</html>\n"
    )


def render(result: ScanResult, fmt: str = "table", *, generated_at: str | None = None) -> str:
    """按 `fmt` 渲染报告。

    异常:
        ValueError: 格式不在 `table|json|html` 内。
    """
    if fmt == "table":
        return render_table(result)
    if fmt == "json":
        return render_json(result, generated_at=generated_at)
    if fmt == "html":
        return render_html(result, generated_at=generated_at)
    raise ValueError("unknown format: " + str(fmt))


def write_report(
    result: ScanResult,
    path: str | Path,
    fmt: str = "table",
    *,
    generated_at: str | None = None,
) -> Path:
    """把报告写到文件（UTF-8），返回写入路径。"""
    target = Path(path)
    text = render(result, fmt, generated_at=generated_at)
    if not text.endswith("\n"):
        text += "\n"
    target.write_text(text, encoding="utf-8", newline="\n")
    return target
