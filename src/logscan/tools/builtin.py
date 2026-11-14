"""具体工具实现：搜索 / 统计 / 时间线 / 样本 / 关联。"""

from __future__ import annotations

import json
from typing import Any

from ..logs.store import LogStore
from .base import Tool, ToolResult


def _row_to_dict(row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


# ------------------------------------------------------------------ #

class SearchLogsTool(Tool):
    name = "search_logs"
    description = (
        "搜索日志条目。支持按关键词全文搜索（FTS5 语法），"
        "以及按 level / source_ip / path / method / params / user_agent / status_code 范围过滤。"
        "返回匹配的日志条目列表。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "keyword": {"type": "string", "description": "全文搜索关键词，支持 FTS5 语法（如 'sql injection'、'error OR warning'）"},
            "level": {"type": "string", "description": "日志级别过滤：DEBUG / INFO / WARN / ERROR / CRITICAL"},
            "source_ip": {"type": "string", "description": "按来源 IP 精确匹配"},
            "path": {"type": "string", "description": "按请求路径模糊匹配（LIKE）"},
            "method": {"type": "string", "description": "按 HTTP 方法精确匹配（GET / POST / PUT / DELETE 等）"},
            "params": {"type": "string", "description": "按请求参数模糊匹配（URL query 或正文片段）"},
            "user_agent": {"type": "string", "description": "按 User-Agent 模糊匹配（可用于识别扫描器/工具指纹）"},
            "status_min": {"type": "integer", "description": "HTTP 状态码下限（含）"},
            "status_max": {"type": "integer", "description": "HTTP 状态码上限（含）"},
            "limit": {"type": "integer", "description": "返回条数上限，默认 50", "default": 50},
            "offset": {"type": "integer", "description": "偏移量，默认 0", "default": 0},
        },
    }

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        rows = store.search(
            keyword=args.get("keyword", ""),
            level=args.get("level", ""),
            source_ip=args.get("source_ip", ""),
            path=args.get("path", ""),
            status_min=args.get("status_min", 0),
            status_max=args.get("status_max", 0),
            method=args.get("method", ""),
            params=args.get("params", ""),
            user_agent=args.get("user_agent", ""),
            limit=args.get("limit", 50),
            offset=args.get("offset", 0),
        )
        return ToolResult(ok=True, data=[_row_to_dict(r) for r in rows])


# ------------------------------------------------------------------ #

class GetStatsTool(Tool):
    name = "get_stats"
    description = (
        "获取日志统计概览：总数、时间范围、按级别分布、按 HTTP 状态码分布、"
        "Top 来源 IP、Top 请求路径。用于快速了解日志全貌。"
    )
    parameters = {"type": "object", "properties": {}}

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        ts_min, ts_max = store.time_range()
        total = store.total()
        data = {
            "total": total,
            "time_range": {"min": ts_min, "max": ts_max},
            "by_level": [{"level": r[0], "count": r[1]} for r in store.stats_by_level()],
            "by_status": [{"status": r[0], "count": r[1]} for r in store.stats_by_status()],
            "top_ips": [{"ip": r[0], "count": r[1]} for r in store.top_ips()],
            "top_paths": [{"path": r[0], "count": r[1]} for r in store.top_paths()],
        }
        # 明确标注缺失字段，避免"留白"被误读为"没有异常"
        if total:
            checks = (
                ("timestamp", "timestamp IS NULL OR timestamp=''", "时间戳"),
                ("source_ip", "source_ip IS NULL OR source_ip=''", "源 IP"),
                ("status_code", "status_code IS NULL OR status_code=0", "状态码"),
            )
            missing = []
            for key, cond, label in checks:
                n = store.conn.execute(
                    f"SELECT COUNT(*) FROM logs WHERE {cond}"
                ).fetchone()[0]
                if n:
                    missing.append({
                        "field": key,
                        "label": label,
                        "missing": n,
                        "total": total,
                        "ratio": round(n / total, 4),
                    })
            if missing:
                data["missing_fields"] = missing
                data["missing_note"] = (
                    "以下字段存在缺失，相关统计（时间范围/来源 IP/状态码分布）会低估："
                    + "、".join(f"{m['label']}({m['missing']}/{m['total']})" for m in missing)
                )
        return ToolResult(ok=True, data=data)


# ------------------------------------------------------------------ #

class GetTimelineTool(Tool):
    name = "get_timeline"
    description = (
        "获取指定来源 IP 的完整活动时间线（按时间正序），"
        "用于分析攻击者的行为序列和横向移动。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "source_ip": {"type": "string", "description": "要分析来源 IP"},
            "limit": {"type": "integer", "description": "返回条数上限，默认 100", "default": 100},
        },
        "required": ["source_ip"],
    }

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        ip = args.get("source_ip", "")
        if not ip:
            return ToolResult(ok=False, data=None, error="source_ip 不能为空")
        rows = store.timeline_for_ip(ip, args.get("limit", 100))
        return ToolResult(ok=True, data=[_row_to_dict(r) for r in rows])


# ------------------------------------------------------------------ #

class GetErrorSampleTool(Tool):
    name = "get_error_sample"
    description = "获取 ERROR / CRITICAL 级别日志样本，用于快速定位异常。"
    parameters = {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "返回条数上限，默认 20", "default": 20},
        },
    }

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        rows = store.error_sample(args.get("limit", 20))
        return ToolResult(ok=True, data=[_row_to_dict(r) for r in rows])


# ------------------------------------------------------------------ #

class GetSampleTool(Tool):
    name = "get_sample"
    description = "获取日志样本（最早的若干条），用于了解日志格式和内容。"
    parameters = {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "返回条数上限，默认 10", "default": 10},
        },
    }

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        rows = store.sample(args.get("limit", 10))
        return ToolResult(ok=True, data=[_row_to_dict(r) for r in rows])


# ------------------------------------------------------------------ #

class CorrelateTool(Tool):
    name = "correlate_events"
    description = (
        "关联分析：查找同时出现在多个来源 IP 中的相同请求路径，"
        "或某个 IP 访问的所有不同路径。用于发现协同攻击或扫描行为。"
    )
    parameters = {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["shared_paths", "ip_paths"],
                "description": "shared_paths: 找被多个 IP 访问的路径; ip_paths: 找某 IP 访问的所有路径",
            },
            "source_ip": {"type": "string", "description": "mode=ip_paths 时指定 IP"},
            "min_ips": {"type": "integer", "description": "shared_paths 模式下，路径至少被多少 IP 访问，默认 3", "default": 3},
        },
        "required": ["mode"],
    }

    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        mode = args.get("mode", "")
        if mode == "ip_paths":
            ip = args.get("source_ip", "")
            if not ip:
                return ToolResult(ok=False, data=None, error="ip_paths 模式需要 source_ip")
            rows = store.conn.execute(
                "SELECT path, COUNT(*) as cnt FROM logs WHERE source_ip=? AND path!='' "
                "GROUP BY path ORDER BY cnt DESC LIMIT 50",
                (ip,),
            ).fetchall()
            return ToolResult(ok=True, data=[{"path": r[0], "count": r[1]} for r in rows])
        elif mode == "shared_paths":
            min_ips = args.get("min_ips", 3)
            rows = store.conn.execute(
                "SELECT path, COUNT(DISTINCT source_ip) as ip_cnt, COUNT(*) as total "
                "FROM logs WHERE path!='' AND source_ip!='' "
                "GROUP BY path HAVING ip_cnt >= ? ORDER BY ip_cnt DESC LIMIT 50",
                (min_ips,),
            ).fetchall()
            return ToolResult(ok=True, data=[
                {"path": r[0], "distinct_ips": r[1], "total_requests": r[2]} for r in rows
            ])
        return ToolResult(ok=False, data=None, error=f"未知 mode: {mode}")


# ------------------------------------------------------------------ #

def default_registry():
    """创建包含全部默认工具的注册表。"""
    from .base import ToolRegistry
    reg = ToolRegistry()
    for tool_cls in (SearchLogsTool, GetStatsTool, GetTimelineTool,
                     GetErrorSampleTool, GetSampleTool, CorrelateTool):
        reg.register(tool_cls())
    return reg