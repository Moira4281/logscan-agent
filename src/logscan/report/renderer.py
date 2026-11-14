"""报告渲染：Markdown / JSON / 终端摘要。"""

from __future__ import annotations

import json
from typing import Any

from ..agent import AgentTrace

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW": "🟢", "INFO": "🔵",
}


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def render_markdown(report: dict[str, Any], trace: AgentTrace | None = None) -> str:
    lines: list[str] = []
    lines.append("# 安全日志分析报告")
    lines.append("")

    # 概述
    summary = report.get("summary", "无概述")
    lines.append("## 概述")
    lines.append(summary)
    lines.append("")

    # 日志概览
    overview = report.get("log_overview", {})
    if overview:
        lines.append("## 日志概览")
        if overview.get("total_entries"):
            lines.append(f"- 日志条目数: {overview['total_entries']}")
        if overview.get("time_range"):
            lines.append(f"- 时间范围: {overview['time_range']}")
        for obs in overview.get("key_observations", []):
            lines.append(f"- {obs}")
        lines.append("")

    # 漏洞
    vulns = report.get("vulnerabilities", [])
    lines.append(f"## 发现漏洞 ({len(vulns)})")
    lines.append("")
    if not vulns:
        lines.append("未发现明显安全漏洞。")
        lines.append("")
    for v in vulns:
        sev = v.get("severity", "INFO")
        icon = _SEVERITY_EMOJI.get(sev, "⚪")
        lines.append(f"### {icon} {v.get('id', '?')} - {v.get('type', '未知类型')}")
        lines.append(f"- **严重性**: {sev}")
        conf = v.get("confidence", 0)
        lines.append(f"- **置信度**: {conf:.0%}" if isinstance(conf, (int, float)) else f"- **置信度**: {conf}")
        review = v.get("review_status", "")
        review_label = {"CONFIRMED": "✅ 已确认", "NEEDS_REVIEW": "⚠️ 需人工复核",
                        "FALSE_POSITIVE": "❌ 误报", "AUTO_RESOLVED": "🔧 已自动处置"}.get(review, review)
        if review:
            lines.append(f"- **复核状态**: {review_label}")
        lines.append(f"- **描述**: {v.get('description', '')}")
        ips = v.get("source_ips", [])
        if ips:
            lines.append(f"- **来源 IP**: {', '.join(ips)}")
        paths = v.get("affected_paths", [])
        if paths:
            lines.append(f"- **受影响路径**: {', '.join(paths)}")
        evidence = v.get("evidence", [])
        if evidence:
            lines.append("- **证据**:")
            for e in evidence:
                lines.append(f"  - {e}")
        method = v.get("detection_method", "")
        if method:
            lines.append(f"- **检测方法**: {method}")
        ms = v.get("model_score", {})
        if ms:
            lines.append(f"- **模型分数**: {ms.get('category', '')} {ms.get('score', 0):.2%} (命中{ms.get('matched_count', 0)}条, {ms.get('model_version', '')})")
        lines.append(f"- **建议**: {v.get('recommendation', '')}")
        lines.append("")

    # 攻击链
    chains = report.get("attack_chains", [])
    if chains:
        lines.append(f"## 攻击链 ({len(chains)})")
        lines.append("")
        for i, c in enumerate(chains, 1):
            lines.append(f"### 攻击链 #{i} — {c.get('attacker_ip', '?')}")
            for j, step in enumerate(c.get("steps", []), 1):
                lines.append(f"{j}. {step}")
            lines.append(f"- **评估**: {c.get('assessment', '')}")
            lines.append("")

    # 统计
    stats = report.get("statistics", {})
    if stats:
        lines.append("## 统计")
        lines.append(f"- 总发现数: {stats.get('total_findings', len(vulns))}")
        by_sev = stats.get("by_severity", {})
        if by_sev:
            parts = [f"{k}: {v}" for k, v in by_sev.items()]
            lines.append(f"- 按严重性: {', '.join(parts)}")
        lines.append("")

    # 追踪
    if trace and trace.steps:
        lines.append("## 分析过程")
        lines.append(f"- 总耗时: {trace.total_elapsed_ms}ms")
        lines.append(f"- 总步数: {len(trace.steps)}")
        tool_calls = [s for s in trace.steps if s.type == "tool_call"]
        lines.append(f"- 工具调用次数: {len(tool_calls)}")
        lines.append("")

    return "\n".join(lines)


def render_trace_table(trace: AgentTrace) -> list[tuple[str, str, str]]:
    """返回 (step, type, detail) 列表，用于终端表格展示。"""
    rows: list[tuple[str, str, str]] = []
    for s in trace.steps:
        if s.type == "tool_call":
            detail = f"{s.tool_name}({json.dumps(s.tool_args, ensure_ascii=False)})"
        elif s.type == "tool_result":
            detail = f"{s.tool_name} → {s.tool_result}"
        elif s.type == "llm_response":
            detail = s.content[:120]
        elif s.type == "final":
            detail = s.content[:120]
        elif s.type == "error":
            detail = s.content
        else:
            detail = s.content
        rows.append((str(s.step), s.type, detail))
    return rows