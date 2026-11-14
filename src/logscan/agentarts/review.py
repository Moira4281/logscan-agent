"""人工复核节点。

按 event_schema.json 的 review_status 四级状态对 Agent 输出事件做复核判定，
体现"不以单条命中即判定入侵"原则。这是成员B与成员C的接口契约，也是答辩重点。

状态语义：
  CONFIRMED       已确认威胁（高置信 + 人工确认）
  NEEDS_REVIEW    需人工复核（默认，低置信或单通道命中）
  FALSE_POSITIVE  误报（人工判定）
  AUTO_RESOLVED    已自动处置（如已封禁/已修复）
"""

from __future__ import annotations

from typing import Any

CONFIRMED = "CONFIRMED"
NEEDS_REVIEW = "NEEDS_REVIEW"
FALSE_POSITIVE = "FALSE_POSITIVE"
AUTO_RESOLVED = "AUTO_RESOLVED"

_ALL_STATUSES = (CONFIRMED, NEEDS_REVIEW, FALSE_POSITIVE, AUTO_RESOLVED)

_HIGH_CONFIDENCE_THRESHOLD = 0.9
_LOW_CONFIDENCE_THRESHOLD = 0.6


def decide_review_status(event: dict[str, Any]) -> str:
    """根据置信度与风险等级自动判定复核状态。

    - confidence < 0.6  → NEEDS_REVIEW（schema 约定）
    - CRITICAL 且 confidence >= 0.9 且双通道命中 → CONFIRMED
    - 其余 → NEEDS_REVIEW（默认需复核，不以单条命中即判定入侵）
    """
    confidence = float(event.get("confidence", 0.0) or 0.0)
    risk_level = str(event.get("risk_level") or event.get("severity") or "").upper()
    detection_method = str(event.get("detection_method", ""))

    if confidence < _LOW_CONFIDENCE_THRESHOLD:
        return NEEDS_REVIEW

    dual_channel = ("规则" in detection_method and "模型" in detection_method) or "联合" in detection_method
    if risk_level == "CRITICAL" and confidence >= _HIGH_CONFIDENCE_THRESHOLD and dual_channel:
        return CONFIRMED

    return NEEDS_REVIEW


def apply_review(report: dict[str, Any]) -> dict[str, Any]:
    """对报告中的所有漏洞事件套用复核节点，原地补全 review_status 并返回。"""
    vulns = report.get("vulnerabilities", [])
    for v in vulns:
        if "review_status" not in v or not v.get("review_status"):
            v["review_status"] = decide_review_status(v)
        if "judgment" not in v or not v.get("judgment"):
            v["judgment"] = _default_judgment(v)
    return report


def _default_judgment(event: dict[str, Any]) -> str:
    status = event.get("review_status", NEEDS_REVIEW)
    conf = event.get("confidence", 0.0)
    method = event.get("detection_method", "单通道")
    if status == CONFIRMED:
        return f"置信度 {conf:.0%} 且{method}联合命中，自动确认。"
    return f"置信度 {conf:.0%}，{method}，需人工复核。"


def review_summary(report: dict[str, Any]) -> dict[str, int]:
    """统计各复核状态数量。"""
    counts = {s: 0 for s in _ALL_STATUSES}
    for v in report.get("vulnerabilities", []):
        status = v.get("review_status", NEEDS_REVIEW)
        if status in counts:
            counts[status] += 1
    return counts


def apply_action(event: dict[str, Any], action: str) -> dict[str, Any]:
    """对单个事件执行人工复核操作。"""
    action = action.strip().lower()
    mapping = {
        "confirm": CONFIRMED,
        "confirmed": CONFIRMED,
        "false_positive": FALSE_POSITIVE,
        "falsepositive": FALSE_POSITIVE,
        "auto_resolved": AUTO_RESOLVED,
        "autoresolved": AUTO_RESOLVED,
    }
    new_status = mapping.get(action)
    if new_status is None:
        return event
    event["review_status"] = new_status
    return event