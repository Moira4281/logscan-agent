"""直接调用线上 AgentArts 智能体（底层跳过 SSL 验证）。

用法：
    python test_invoke.py            # 默认：llm 模式，异步 submit + 轮询（推荐）
    python test_invoke.py llm sync   # llm 模式，同步单次调用
    python test_invoke.py mock       # mock 模式，异步 submit + 轮询

说明：AgentArts 数据面网关对单次转发有约 15 秒的硬超时，完整 llm 分析（20+ 步）
必然超过，因此默认走异步协议：submit 立即拿到 job_id，再轮询 status 取进度与结果。
submit 与轮询使用同一个 session_id，以命中同一容器实例。
"""
import json
import os
import sys
import time
import uuid

from agentarts.sdk.service.http_client import SignMode
from agentarts.sdk.service.runtime_client import RuntimeClient

DATA_ENDPOINT = os.getenv(
    "AGENTARTS_RUNTIME_DATA_ENDPOINT",
    "https://defaultgw-mmztkmbvhf.cn-southwest-2.huaweicloud-agentarts.com",
)
AGENT_NAME = "logscan-agent-runtime"
REGION = "cn-southwest-2"

mode = sys.argv[1] if len(sys.argv) > 1 else "llm"
sync = len(sys.argv) > 2 and sys.argv[2] == "sync"

log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples", "access.log")
with open(log_path, "r", encoding="utf-8") as f:
    log_content = f.read()

payload = json.dumps({
    "mode": mode,
    "sources": [{"content": log_content, "filename": "access.log"}],
    "options": {"max_steps": 24},
})

print(f"endpoint: {DATA_ENDPOINT}")
print(f"mode: {mode}  sync: {sync}")
print("=" * 60)

client = RuntimeClient(
    data_endpoint=DATA_ENDPOINT,
    verify_ssl=False,
    sign_mode=SignMode.V11_HMAC_SHA256,
    region_id=REGION,
    timeout=120.0,
)
session_id = str(uuid.uuid4())
t0 = time.time()


def call(body: str) -> dict:
    return client.invoke_agent(agent_name=AGENT_NAME, session_id=session_id, payload=body)


if sync:
    result = call(payload)
else:
    submitted = call(json.dumps({"action": "submit", **json.loads(payload)}))
    print(f"[submit] {time.time() - t0:.1f}s -> {submitted}")
    job_id = submitted.get("job_id")
    if not job_id:
        print("submit 失败，退出")
        sys.exit(1)

    seen = 0
    result = {}
    while True:
        time.sleep(2)
        status = call(json.dumps({"action": "status", "job_id": job_id}))
        steps = status.get("steps") or []
        if len(steps) > seen:
            seen = len(steps)
            print(f"[poll] {time.time() - t0:.1f}s status={status.get('status')} steps={seen}")
        if status.get("status") != "running":
            result = status
            break

print("=" * 60)
print(f"总耗时: {time.time() - t0:.1f}s")
print("SUCCESS:", result.get("success"))
print("ERROR:", repr(result.get("error")))
final = result.get("result") or result
print("SUMMARY:", (final.get("report") or {}).get("summary"))
print("ELAPSED_MS:", final.get("total_elapsed_ms"))
print("TRACE 步数:", len(final.get("trace") or []))
