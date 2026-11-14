"""AgentArts 运行时托管入口（平台规范：agentarts-sdk + /invocations）。

部署到 AgentArts 运行时用此文件；本地开发/测试用 runtime.py 的 FastAPI。
平台通过 POST /invocations 调用 handler，payload 为 RunRequest 的 JSON。

由于 AgentArts 数据面网关对单次转发有约 15 秒的硬超时（超时报 HTTP 524），
耗时的 llm 分析不能同步返回，因此入口支持 action 异步协议（同时也是后续
"实时/流式"能力的预留口子）：

    无 action       → 同步执行并返回完整 RunResponse（兼容旧用法，仅适合 mock/短请求）
    action=submit   → 立即返回 {"job_id": ...}，后台线程跑完整分析
    action=status   → 返回 {"status", "steps": [...], "result": ...}，steps 为增量进度
"""

from __future__ import annotations

import os
import threading
import time
import uuid

from dotenv import load_dotenv

from logscan.agentarts.schemas import ChatRequest, RunRequest
from logscan.agentarts.service import execute_chat, execute_run, step_to_schema

load_dotenv()

from agentarts.sdk import AgentArtsRuntimeApp, RequestContext  # noqa: E402

app = AgentArtsRuntimeApp()

# 进程内 job 注册表（异步口子用）。容器空闲回收后丢失，属预期行为。
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_JOB_TTL_SEC = 1800  # 完成后保留 30 分钟便于反复取结果


def _prune_jobs() -> None:
    """清理过期 job，避免内存无界增长。"""
    now = time.time()
    with _JOBS_LOCK:
        stale = [jid for jid, job in _JOBS.items() if now - job["created_at"] > _JOB_TTL_SEC]
        for jid in stale:
            _JOBS.pop(jid, None)


def _run_job(job_id: str, req: RunRequest) -> None:
    """后台执行一次完整分析，逐步把 trace 追加进 job，最后写入结果。"""

    def on_step(step) -> None:
        try:
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                if job is not None:
                    job["steps"].append(step_to_schema(step).model_dump())
        except Exception:
            pass

    try:
        resp = execute_run(req, on_step=on_step)
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is not None:
                job["status"] = "done" if resp.success else "error"
                job["result"] = resp.model_dump()
                job["error"] = resp.error or ""
    except Exception as exc:  # noqa: BLE001 - 后台线程需兜住所有异常
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is not None:
                job["status"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"


def _run_chat_job(job_id: str, req: ChatRequest) -> None:
    """后台执行一次自然语言问答。"""

    def on_step(step) -> None:
        try:
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                if job is not None:
                    job["steps"].append(step_to_schema(step).model_dump())
        except Exception:
            pass

    try:
        resp = execute_chat(req, on_step=on_step)
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is not None:
                job["status"] = "done" if resp.success else "error"
                job["result"] = resp.model_dump()
                job["error"] = resp.error or ""
    except Exception as exc:  # noqa: BLE001
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is not None:
                job["status"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"


def _handle_action(action: str, payload: dict) -> dict:
    if action == "submit":
        body = {k: v for k, v in payload.items() if k != "action"}
        try:
            req = RunRequest(**body)
        except Exception as e:
            return {"success": False, "error": f"请求解析失败: {e}"}
        job_id = uuid.uuid4().hex
        with _JOBS_LOCK:
            _JOBS[job_id] = {
                "status": "running",
                "steps": [],
                "result": None,
                "error": "",
                "created_at": time.time(),
                "kind": "run",
            }
        threading.Thread(target=_run_job, args=(job_id, req), daemon=True).start()
        return {"success": True, "job_id": job_id}

    if action == "chat_submit":
        body = {k: v for k, v in payload.items() if k != "action"}
        try:
            req = ChatRequest(**body)
        except Exception as e:
            return {"success": False, "error": f"请求解析失败: {e}"}
        job_id = uuid.uuid4().hex
        with _JOBS_LOCK:
            _JOBS[job_id] = {
                "status": "running",
                "steps": [],
                "result": None,
                "error": "",
                "created_at": time.time(),
                "kind": "chat",
            }
        threading.Thread(target=_run_chat_job, args=(job_id, req), daemon=True).start()
        return {"success": True, "job_id": job_id}

    if action == "status":
        job_id = payload.get("job_id", "")
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                return {"success": False, "error": f"未知 job_id: {job_id}"}
            snapshot = {
                "success": True,
                "job_id": job_id,
                "status": job["status"],
                "kind": job.get("kind", "run"),
                "steps": list(job["steps"]),
                "error": job["error"],
            }
            if job["result"] is not None:
                snapshot["result"] = job["result"]
            return snapshot

    return {"success": False, "error": f"未知 action: {action}"}


@app.entrypoint
async def handler(payload: dict, context: RequestContext = None) -> dict:
    """AgentArts 平台标准 HTTP 暴露入口。

    payload 即用户传入的 JSON：
      - 分析报告: {"mode": "llm", "sources": [...], "options": {...}}
      - 自然语言问答: {"mode": "llm", "question": "...", "sources": [...]}
    或异步协议：
      {"action": "submit", "mode": "llm", "sources": [...], "options": {...}}
      {"action": "chat_submit", "mode": "llm", "question": "...", "sources": [...]}
      {"action": "status", "job_id": "..."}
    """
    action = payload.get("action")
    if action:
        _prune_jobs()
        return _handle_action(action, payload)
    # 无 action 时按字段自动分发：含 question → 问答，否则 → 完整分析
    if "question" in payload:
        try:
            req = ChatRequest(**payload)
        except Exception as e:
            return {"success": False, "error": f"请求解析失败: {e}"}
        result = execute_chat(req)
        return result.model_dump()
    try:
        req = RunRequest(**payload)
    except Exception as e:
        return {"success": False, "error": f"请求解析失败: {e}"}
    result = execute_run(req)
    return result.model_dump()


if __name__ == "__main__":
    port = int(os.getenv("AGENT_RUN_PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
