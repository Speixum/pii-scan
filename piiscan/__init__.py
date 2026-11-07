"""piiscan: 零依赖敏感信息扫描与脱敏工具。

只依赖 Python 标准库；运行期不联网，只读写用户显式给出的路径。
"""

from __future__ import annotations

__all__ = ["__version__", "SCHEMA"]

__version__ = "1.0.0"

#: JSON 产物的顶层 schema 标识（跨工具契约，见 SPEC 3.2）。
SCHEMA = "pii-hits/1.0"
