"""验证完成验收标准：
1. 同一输入重复得到格式一致结果
2. 至少有正常、攻击、低置信度三类样例
"""
import json
from pathlib import Path

from logscan.logs.store import LogStore
from logscan.mock_agent import MockAgent
from logscan.report.renderer import render_json


def check_reproducibility():
    """验收1: 同一输入跑两次，输出必须完全一致。"""
    results = []
    for i in range(2):
        store = LogStore(":memory:")
        store.ingest_sources(["examples/access.log"], 50000)
        agent = MockAgent(store)
        result = agent.run(["examples/access.log"])
        results.append(render_json(result.report))
        store.close()
    consistent = results[0] == results[1]
    print(f"[验收1] 同一输入重复一致性: {'PASS' if consistent else 'FAIL'}")
    if not consistent:
        print(f"  两次输出长度: {len(results[0])} vs {len(results[1])}")
    return consistent


def check_three_categories():
    """验收2: 至少有正常、攻击、低置信度三类样例。"""
    store = LogStore(":memory:")
    store.ingest_sources(["examples/access.log", "examples/app.json.log", "examples/syslog.log"], 50000)
    agent = MockAgent(store)
    result = agent.run(["examples/access.log", "examples/app.json.log", "examples/syslog.log"])

    vulns = result.report.get("vulnerabilities", [])
    has_attack = len(vulns) > 0

    from logscan.tools.predict import MockPredictTool
    reg_tool = MockPredictTool()
    pred_result = reg_tool.execute(store, {"limit": 100})
    labels = set(p["label"] for p in pred_result.data)
    has_normal = "normal" in labels

    review_statuses = set()
    for v in vulns:
        rs = v.get("review_status", "")
        if rs:
            review_statuses.add(rs)
    has_low_confidence = "NEEDS_REVIEW" in review_statuses

    print(f"[验收2] 三类样例检查:")
    print(f"  攻击样例 (vulnerabilities > 0): {'PASS' if has_attack else 'FAIL'} — {len(vulns)} 个漏洞")
    print(f"  正常样例 (label=normal): {'PASS' if has_normal else 'FAIL'} — 标签集: {labels}")
    print(f"  低置信度/需复核样例 (review_status=NEEDS_REVIEW): {'PASS' if has_low_confidence else 'FAIL'}")
    print(f"  复核状态覆盖: {review_statuses}")

    store.close()
    return has_attack and has_normal and has_low_confidence


def check_evidence_traceability():
    """验收3: 每个漏洞能回指原始日志（有 evidence 字段）。"""
    store = LogStore(":memory:")
    store.ingest_sources(["examples/access.log"], 50000)
    agent = MockAgent(store)
    result = agent.run(["examples/access.log"])
    vulns = result.report.get("vulnerabilities", [])
    all_traced = all(v.get("evidence") for v in vulns)
    print(f"[验收3] 证据可追溯性: {'PASS' if all_traced else 'FAIL'} — {len(vulns)} 个漏洞均有 evidence 字段")
    store.close()
    return all_traced


def main():
    print("=" * 60)
    print("  成员 B 完成验收标准验证")
    print("=" * 60)
    print()
    r1 = check_reproducibility()
    print()
    r2 = check_three_categories()
    print()
    r3 = check_evidence_traceability()
    print()
    print("=" * 60)
    all_pass = r1 and r2 and r3
    print(f"  总体结果: {'ALL PASS' if all_pass else 'HAS FAILURES'}")
    print("=" * 60)


if __name__ == "__main__":
    main()