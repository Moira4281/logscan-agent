"""生成 agent_runs/ 运行记录：对 3 个样例日志跑 mock 模式，保存报告 + trace。"""
import json
import os
import time
from pathlib import Path

from logscan.config import Settings
from logscan.logs.store import LogStore
from logscan.mock_agent import MockAgent
from logscan.report.renderer import render_markdown, render_json


def main():
    os.makedirs("agent_runs", exist_ok=True)
    examples = ["examples/access.log", "examples/app.json.log", "examples/syslog.log"]
    for ex in examples:
        name = Path(ex).stem
        outdir = Path("agent_runs") / name
        outdir.mkdir(exist_ok=True)
        store = LogStore(":memory:")
        count = store.ingest_sources([ex], 50000)
        agent = MockAgent(store)
        t0 = time.time()
        result = agent.run([ex])
        elapsed = time.time() - t0

        (outdir / "report.json").write_text(render_json(result.report), encoding="utf-8")
        trace_data = {
            "source": ex,
            "log_count": count,
            "success": result.success,
            "error": result.error,
            "total_elapsed_ms": result.trace.total_elapsed_ms,
            "wall_time_s": round(elapsed, 3),
            "steps": [
                {
                    "step": s.step,
                    "type": s.type,
                    "tool_name": s.tool_name,
                    "content": s.content[:2000],
                    "tool_args": s.tool_args,
                    "tool_result": s.tool_result[:3000],
                    "elapsed_ms": s.elapsed_ms,
                }
                for s in result.trace.steps
            ],
        }
        (outdir / "trace.json").write_text(
            json.dumps(trace_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (outdir / "report.md").write_text(
            render_markdown(result.report, result.trace), encoding="utf-8"
        )
        vulns = result.report.get("vulnerabilities", [])
        print(f"{name}: {count}条日志, {len(vulns)}个漏洞, {len(trace_data['steps'])}步, {elapsed:.2f}s")
        store.close()
    print("agent_runs/ 生成完毕")


if __name__ == "__main__":
    main()