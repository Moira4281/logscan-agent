"""日志加载：从文件 / 目录 / stdin 读取原始行。"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path


def _iter_file(path: Path, max_lines: int) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            yield line


def load_sources(
    sources: list[str],
    max_lines: int = 50000,
) -> Iterator[tuple[str, str]]:
    """yield (source_name, line) 对。

    sources 可包含文件路径、目录路径、"-" 表示 stdin。
    目录会递归读取所有文件。
    """
    for src in sources:
        if src == "-":
            for i, line in enumerate(sys.stdin):
                if i >= max_lines:
                    break
                yield "stdin", line
            continue

        path = Path(src)
        if path.is_dir():
            for fp in sorted(path.rglob("*")):
                if fp.is_file() and not fp.name.startswith("."):
                    yield from ((str(fp), l) for l in _iter_file(fp, max_lines))
        elif path.is_file():
            yield from ((str(path), l) for l in _iter_file(path, max_lines))
        else:
            raise FileNotFoundError(f"日志源不存在: {src}")


def expand_sources(sources: list[str]) -> list[Path]:
    """展开目录，返回所有将读取的文件路径（用于预览/统计）。"""
    files: list[Path] = []
    for src in sources:
        if src == "-":
            continue
        path = Path(src)
        if path.is_dir():
            files.extend(sorted(f for f in path.rglob("*") if f.is_file() and not f.name.startswith(".")))
        elif path.is_file():
            files.append(path)
    return files