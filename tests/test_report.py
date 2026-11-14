"""报告渲染测试。"""

from logscan.agent import AgentTrace, AgentStep
from logscan.report.renderer import render_json, render_markdown, render_trace_table


SAMPLE_REPORT = {
    "summary": "发现多个安全威胁",
    "log_overview": {
        "total_entries": 100,
        "time_range": "10:00 ~ 10:07",
        "key_observations": ["大量 404", "SQL 注入特征"],
    },
    "vulnerabilities": [
        {
            "id": "VULN-001",
            "type": "SQL注入尝试",
            "severity": "HIGH",
            "confidence": 0.9,
            "description": "检测到 UNION SELECT 注入",
            "evidence": ["log1", "log2"],
            "source_ips": ["10.0.0.66"],
            "affected_paths": ["/products"],
            "recommendation": "使用参数化查询",
        }
    ],
    "attack_chains": [
        {"attacker_ip": "10.0.0.66", "steps": ["step1", "step2"], "assessment": "SQL注入"}
    ],
    "statistics": {"total_findings": 1, "by_severity": {"HIGH": 1}},
}


def test_render_json():
    out = render_json(SAMPLE_REPORT)
    assert "SQL注入尝试" in out
    assert "VULN-001" in out


def test_render_markdown():
    out = render_markdown(SAMPLE_REPORT)
    assert "安全日志分析报告" in out
    assert "VULN-001" in out
    assert "SQL注入尝试" in out
    assert "HIGH" in out


def test_render_markdown_empty():
    out = render_markdown({"summary": "无漏洞", "vulnerabilities": []})
    assert "未发现明显安全漏洞" in out


def test_render_trace_table():
    trace = AgentTrace()
    trace.add(AgentStep(step=1, type="tool_call", tool_name="search_logs", tool_args={"keyword": "sql"}))
    trace.add(AgentStep(step=1, type="tool_result", tool_name="search_logs", tool_result='{"ok": true}'))
    trace.add(AgentStep(step=2, type="final", content="done"))
    rows = render_trace_table(trace)
    assert len(rows) == 3
    assert rows[0][1] == "tool_call"
    assert "search_logs" in rows[0][2]