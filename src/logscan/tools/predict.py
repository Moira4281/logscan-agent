"""成员A模型预测工具：调用 predict.py 对日志条目做攻击分类。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Any

from ..logs.store import LogStore
from .base import Tool, ToolResult


def _row_to_predict_input(row) -> dict[str, str]:
    """把数据库行转成成员A要求的9字段输入格式。"""
    row_dict = dict(row) if not isinstance(row, dict) else row
    extra = {}
    if row_dict.get("extra"):
        try:
            extra = json.loads(row_dict["extra"])
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "ts": row_dict.get("timestamp", ""),
        "src_ip": row_dict.get("source_ip", ""),
        "method": row_dict.get("method", ""),
        "path": row_dict.get("path", ""),
        "params": extra.get("params", ""),
        "status": str(row_dict.get("status_code", "") or ""),
        "ua": extra.get("ua", ""),
        "cookie": extra.get("cookie", ""),
        "hdrs": extra.get("hdrs", ""),
    }


class PredictTool(Tool):
    """调用成员A的 predict.py 对日志条目做ML攻击分类。

    输入：从数据库取日志条目，转成A要求的9字段格式
    输出：每条日志的 label/confidence/review/reason/evidence/keywords
    """

    name = "predict"
    description = (
        "调用ML模型对日志条目做攻击分类。"
        "可按 keyword/level/source_ip 过滤待预测的日志，"
        "返回每条的预测类别、置信度、是否需复核和证据。"
        "模型无法识别 bruteforce（需关联规则），fileinclusion 会标记需复核。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "keyword": {"type": "string", "description": "可选：先按关键词过滤再预测"},
            "level": {"type": "string", "description": "可选：按级别过滤"},
            "source_ip": {"type": "string", "description": "可选：按IP过滤"},
            "limit": {"type": "integer", "description": "预测条数上限，默认50", "default": 50},
        },
    }

    def __init__(self, predict_script: str = "predict.py", python_bin: str = sys.executable):
        self.predict_script = predict_script
        self.python_bin = python_bin

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        limit = args.get("limit", 50)
        # A 建议:按 status_code >= 400 优先抽样，再补足正常行
        bad_limit = int(limit * 0.6)  # 60% 配额给 4xx/5xx
        good_limit = limit - bad_limit

        bad_rows = store.search(
            keyword=args.get("keyword", ""),
            level=args.get("level", ""),
            source_ip=args.get("source_ip", ""),
            status_min=400,
            limit=bad_limit,
        )
        good_rows = store.search(
            keyword=args.get("keyword", ""),
            level=args.get("level", ""),
            source_ip=args.get("source_ip", ""),
            status_max=399,
            limit=good_limit,
        )
        rows = bad_rows + good_rows

        if not rows:
            return ToolResult(ok=True, data=[], error="无匹配日志")

        inputs = [_row_to_predict_input(r) for r in rows]

        if not os.path.exists(self.predict_script):
            return ToolResult(
                ok=False, data=None,
                error=f"predict.py 不存在: {self.predict_script}。请从成员A获取并配置路径。",
            )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f_in:
            json.dump(inputs, f_in, ensure_ascii=False)
            in_path = f_in.name

        out_path = in_path.replace(".json", "_out.json")
        try:
            result = subprocess.run(
                [self.python_bin, self.predict_script, in_path, "-o", out_path],
                capture_output=True, text=True, timeout=60, encoding="utf-8",
            )
            if result.returncode != 0:
                return ToolResult(
                    ok=False, data=None,
                    error=f"predict.py 失败 (code={result.returncode}): {result.stderr[:500]}",
                )
            with open(out_path, "r", encoding="utf-8") as f:
                predictions = json.load(f)
            return ToolResult(ok=True, data=predictions)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, data=None, error="predict.py 超时（60秒）")
        except FileNotFoundError as exc:
            return ToolResult(ok=False, data=None, error=f"文件错误: {exc}")
        finally:
            for p in (in_path, out_path):
                if os.path.exists(p):
                    os.unlink(p)


class MockPredictTool(Tool):
    """模拟预测工具（不需要 predict.py），用于无模型环境测试。

    用简单关键词匹配模拟模型输出，让 Agent 流程能完整跑通。
    """

    name = "predict"
    description = (
        "调用ML模型对日志条目做攻击分类（mock模式，用关键词模拟）。"
        "返回每条的预测类别、置信度、是否需复核和证据。"
    )
    parameters = PredictTool.parameters

    _MOCK_RULES = [
        ("sqli", 0.95, ["union select", "or 1=1", "or '1'='1", "drop table", "information_schema", "sleep("]),
        ("xss", 0.88, ["<script", "onerror=", "onload=", "javascript:", "alert("]),
        ("dirscan", 0.85, ["../", "..\\", "%2e%2e", "etc/passwd", "win.ini"]),
        ("rce", 0.82, [";", "|", "whoami", "cat ", "wget ", "curl ", "$(", "&&"]),
        ("log4j", 0.90, ["${jndi:", "log4j"]),
        ("cookie_injection", 0.87, ["cookie:", "set-cookie"]),
        ("log_forging", 0.85, ["\n", "\r", "%0a", "%0d"]),
    ]

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        limit = args.get("limit", 50)
        bad_limit = int(limit * 0.6)
        good_limit = limit - bad_limit

        bad_rows = store.search(
            keyword=args.get("keyword", ""),
            level=args.get("level", ""),
            source_ip=args.get("source_ip", ""),
            status_min=400,
            limit=bad_limit,
        )
        good_rows = store.search(
            keyword=args.get("keyword", ""),
            level=args.get("level", ""),
            source_ip=args.get("source_ip", ""),
            status_max=399,
            limit=good_limit,
        )
        rows = bad_rows + good_rows

        if not rows:
            return ToolResult(ok=True, data=[], error="无匹配日志")

        results = []
        for i, row in enumerate(rows):
            row_dict = dict(row) if not isinstance(row, dict) else row
            text = (row_dict.get("message", "") + " " + row_dict.get("raw", "")).lower()
            extra = {}
            if row_dict.get("extra"):
                try:
                    extra = json.loads(row_dict["extra"])
                except (json.JSONDecodeError, TypeError):
                    pass
            if extra.get("params"):
                text += " " + extra["params"].lower()
            if extra.get("ua"):
                text += " " + extra["ua"].lower()
            if extra.get("hdrs"):
                text += " " + extra["hdrs"].lower()
            if extra.get("cookie"):
                text += " " + extra["cookie"].lower()

            label = "normal"
            confidence = 0.99
            evidence = []
            for cat, conf, keywords in self._MOCK_RULES:
                matched_kw = [kw for kw in keywords if kw in text]
                if matched_kw:
                    label = cat
                    confidence = conf
                    evidence = matched_kw[:3]
                    break

            review = confidence < 0.60 or label == "fileinclusion"
            results.append({
                "index": i,
                "raw_ref": extra.get("raw_ref", ""),
                "label": label,
                "confidence": round(confidence, 4),
                "review": review,
                "reason": "置信度低于0.6" if review and confidence < 0.60 else
                          ("fileinclusion弱类" if review else ""),
                "evidence": evidence,
                "keywords": evidence,
                "top3": [[label, round(confidence, 4)], ["normal", round(1 - confidence, 4)]],
                "model_version": "mock-v1",
            })
        return ToolResult(ok=True, data=results)