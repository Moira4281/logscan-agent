# -*- coding: utf-8 -*-
"""把原始 HTTP 报文 dump（CSIC 2010 风格，一个请求横跨多行）转换成统一的 8 字段 CSV。

输出列严格对齐成员A统一 schema（_align.py）：
    时间, 源IP, 方法, 路径, 参数, 状态码, User-Agent, 标签

原始 dump 里没有时间戳 / 源IP / 状态码，这三列输出空字符串（而不是编造值），
并在结尾打印覆盖率，方便判断数据可用性。

用法：
    python convert_http_dump.py anomalousTrafficTest.txt
    python convert_http_dump.py <input.txt> -o out.csv --label attack --limit 5000
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from logscan.logs.parser import parse_http_dump  # noqa: E402

FIELDS = ["时间", "源IP", "方法", "路径", "参数", "状态码", "User-Agent", "标签"]


def infer_label(path: str) -> str:
    name = Path(path).name.lower()
    if "anomalous" in name or "attack" in name:
        return "attack"
    if "normal" in name or "benign" in name:
        return "benign"
    return "unknown"


def iter_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line


def entry_to_row(e, label: str) -> dict[str, str]:
    params = e.extra.get("params", "")
    if not params:
        body = e.extra.get("body", "")
        params = body[:60] if body else ""
    return {
        "时间": e.timestamp,
        "源IP": e.source_ip,
        "方法": e.method,
        "路径": e.path,
        "参数": params,
        "状态码": str(e.status_code) if e.status_code else "",
        "User-Agent": e.extra.get("user_agent", ""),
        "标签": label,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="原始 HTTP 报文 dump → 统一 8 字段 CSV")
    ap.add_argument("input", help="输入文件（如 anomalousTrafficTest.txt）")
    ap.add_argument("-o", "--output", help="输出 CSV 路径，默认与输入同名 .csv")
    ap.add_argument("--label", help="标签值，默认按文件名推断（anomalous→attack, normal→benign）")
    ap.add_argument("--limit", type=int, default=50000, help="最多解析条数，默认 50000")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.exists():
        print(f"输入文件不存在: {src}", file=sys.stderr)
        return 1
    out = Path(args.output) if args.output else src.with_suffix(".csv")
    label = args.label or infer_label(str(src))

    entries = parse_http_dump(iter_lines(str(src)), max_entries=args.limit)
    cov = Counter()
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for e in entries:
            row = entry_to_row(e, label)
            for k, v in row.items():
                if str(v).strip():
                    cov[k] += 1
            w.writerow(row)

    total = len(entries)
    print(f"输入文件 : {src}")
    print(f"输出 CSV : {out}")
    print(f"解析条数 : {total}（limit={args.limit}）")
    print(f"标签     : {label}")
    print("-" * 40)
    for k in FIELDS:
        pct = f"{100.0 * cov[k] / total:.1f}%" if total else "-"
        print(f"  {k:<10} 覆盖 {pct}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
