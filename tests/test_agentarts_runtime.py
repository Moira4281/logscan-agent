"""AgentArts 运行时托管集成测试：业务函数 / 工具适配 / 人工复核节点。

直接调用 runtime 业务函数（execute_run 等），不经过 HTTP transport，
规避沙箱对 socket 的限制。HTTP 层在非沙箱环境用 uvicorn 起服务验证。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logscan.agentarts.review import (
    apply_action,
    apply_review,
    decide_review_status,
    review_summary,
)
from logscan.agentarts.runtime import (
    execute_run,
    execute_review_action,
    execute_tool_invoke,
    list_skills,
)
from logscan.agentarts.schemas import (
    LogSource,
    ReviewActionRequest,
    RunRequest,
    ToolInvokeRequest,
)
from logscan.agentarts.tools_adapter import to_skill_descriptors
from logscan.tools.builtin import default_registry

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

ATTACK_LOG = "\n".join([
    '{"timestamp":"2024-01-15T10:00:00Z","level":"WARN","source_ip":"192.168.1.100",'
    '"method":"GET","path":"/products?id=1 UNION SELECT password FROM users",'
    '"status":200,"message":"UNION SELECT password FROM users"}',
    '{"timestamp":"2024-01-15T10:01:00Z","level":"ERROR","source_ip":"192.168.1.200",'
    '"method":"POST","path":"/login","status":401,"message":"failed password for admin"}',
    '{"timestamp":"2024-01-15T10:01:01Z","level":"ERROR","source_ip":"192.168.1.200",'
    '"method":"POST","path":"/login","status":401,"message":"failed password for admin"}',
    '{"timestamp":"2024-01-15T10:01:02Z","level":"INFO","source_ip":"192.168.1.200",'
    '"method":"POST","path":"/login","status":200,"message":"login success"}',
])

_VALID_STATUSES = {"CONFIRMED", "NEEDS_REVIEW", "FALSE_POSITIVE", "AUTO_RESOLVED"}


def _run_mock(content: str = ATTACK_LOG, **opt):
    return execute_run(RunRequest(
        mode="mock",
        sources=[LogSource(content=content, filename="attack.json.log")],
        options=opt,
    ))


def test_create_app():
    from logscan.agentarts import create_app
    app = create_app()
    assert app.title.startswith("LogScan Agent")


def test_list_skills():
    skills = list_skills()
    names = [s["name"] for s in skills]
    assert len(names) == 6
    for expected in ("search_logs", "get_stats", "get_timeline", "get_error_sample", "get_sample", "correlate_events"):
        assert expected in names


def test_run_mock_detect_attack():
    body = _run_mock()
    assert body.success is True
    vulns = body.report.get("vulnerabilities", [])
    assert len(vulns) >= 1
    for v in vulns:
        assert v.get("review_status") in _VALID_STATUSES
    assert sum(body.review_summary.values()) == len(vulns)


def test_run_mock_inline_empty():
    body = _run_mock(content="")
    assert body.success is False


def test_run_invalid_mode():
    body = execute_run(RunRequest(
        mode="invalid",
        sources=[LogSource(content="x")],
    ))
    assert body.success is False


def test_run_mock_with_examples_path():
    access = EXAMPLES / "access.log"
    if not access.exists():
        pytest.skip("examples/access.log 不存在")
    body = execute_run(RunRequest(
        mode="mock",
        sources=[LogSource(path=str(access))],
    ))
    assert body.success is True


def test_tool_invoke_get_stats():
    body = execute_tool_invoke(ToolInvokeRequest(
        name="get_stats",
        args={},
        sources=[LogSource(content=ATTACK_LOG, filename="attack.json.log")],
    ))
    assert body.ok is True
    assert body.data["total"] >= 1


def test_tool_invoke_unknown():
    body = execute_tool_invoke(ToolInvokeRequest(
        name="no_such_tool",
        args={},
        sources=[LogSource(content="x")],
    ))
    assert body.ok is False


def test_review_action_confirm():
    body = execute_review_action(ReviewActionRequest(
        event={"event_id": "VULN-001", "confidence": 0.7, "review_status": "NEEDS_REVIEW"},
        action="confirm",
    ))
    assert body.review_status == "CONFIRMED"
    assert body.updated is True


def test_review_action_invalid():
    with pytest.raises(ValueError):
        execute_review_action(ReviewActionRequest(
            event={},
            action="bogus",
        ))


def test_decide_review_status_low_conf():
    assert decide_review_status({"confidence": 0.3}) == "NEEDS_REVIEW"


def test_decide_review_status_confirmed():
    e = {"confidence": 0.95, "risk_level": "CRITICAL", "detection_method": "规则关联 + ML模型"}
    assert decide_review_status(e) == "CONFIRMED"


def test_decide_review_status_confirmed_via_severity():
    e = {"confidence": 0.92, "severity": "CRITICAL", "detection_method": "规则+模型联合研判"}
    assert decide_review_status(e) == "CONFIRMED"


def test_decide_review_status_needs_review_default():
    e = {"confidence": 0.8, "risk_level": "HIGH", "detection_method": "规则"}
    assert decide_review_status(e) == "NEEDS_REVIEW"


def test_apply_review_fills_status_and_judgment():
    report = {"vulnerabilities": [
        {"id": "VULN-001", "confidence": 0.3},
        {"id": "VULN-002", "confidence": 0.95, "risk_level": "CRITICAL", "detection_method": "规则+模型联合"},
    ]}
    apply_review(report)
    assert report["vulnerabilities"][0]["review_status"] == "NEEDS_REVIEW"
    assert "judgment" in report["vulnerabilities"][0]
    assert "judgment" in report["vulnerabilities"][1]


def test_review_summary():
    report = {"vulnerabilities": [
        {"review_status": "CONFIRMED"},
        {"review_status": "NEEDS_REVIEW"},
        {"review_status": "NEEDS_REVIEW"},
    ]}
    s = review_summary(report)
    assert s["CONFIRMED"] == 1
    assert s["NEEDS_REVIEW"] == 2
    assert s["FALSE_POSITIVE"] == 0


def test_apply_action_false_positive():
    e = apply_action({"review_status": "NEEDS_REVIEW"}, "false_positive")
    assert e["review_status"] == "FALSE_POSITIVE"


def test_to_skill_descriptors():
    descriptors = to_skill_descriptors(default_registry())
    assert len(descriptors) == 6
    for d in descriptors:
        assert "name" in d
        assert "description" in d
        assert "parameters" in d
