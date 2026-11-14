"""本地测试 /run 接口。用法：python test_run.py

前提：服务已启动（python -m logscan.agentarts.runtime）
"""
from __future__ import annotations

import json
import os
import urllib.request

URL = "http://127.0.0.1:8080/run"
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples", "access.log")
BODY = {
    "mode": "mock",
    "sources": [{"path": LOG_PATH}],
}


def main() -> None:
    data = json.dumps(BODY).encode("utf-8")
    req = urllib.request.Request(
        URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        raw = resp.read().decode("utf-8")
    result = json.loads(raw)

    print("=" * 60)
    print("success:          ", result.get("success"))
    print("error:            ", result.get("error", "") or "(无)")
    print("total_elapsed_ms: ", result.get("total_elapsed_ms", 0))
    print("=" * 60)

    trace = result.get("trace", [])
    print(f"\ntrace（{len(trace)} 步工具调用链）:")
    for step in trace:
        print(f"  [{step.get('step')}] {step.get('type'):20s} tool={step.get('tool_name', '')}")
        if step.get("tool_result"):
            preview = step["tool_result"][:120].replace("\n", " ")
            print(f"       → {preview}{'...' if len(step['tool_result']) > 120 else ''}")

    print("\nreview_summary（复核节点统计）:")
    print(json.dumps(result.get("review_summary", {}), ensure_ascii=False, indent=2))

    report = result.get("report", {})
    if report:
        print("\nreport 摘要:")
        print(json.dumps(report, ensure_ascii=False, indent=2)[:2000])


if __name__ == "__main__":
    main()