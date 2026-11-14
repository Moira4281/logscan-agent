"""FastAPI 本地开发/测试入口（部署请用 app.py + agentarts-sdk）。

业务逻辑在 service.py；本文件提供 HTTP 层用于本地调试，
并额外提供一套"网页演示"接口（后台任务 + 轮询），供答辩/演示时
在浏览器里实时观看 Agent 调用工具、生成报告。

用法：python -m logscan.agentarts.runtime
然后浏览器打开 http://127.0.0.1:8080/
局域网内其他电脑可打开 http://<本机IP>:8080/
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .schemas import (
    ChatRequest,
    ChatResponse,
    ReviewActionRequest,
    ReviewActionResponse,
    RunRequest,
    RunResponse,
    SkillDescriptor,
    ToolInvokeRequest,
    ToolInvokeResponse,
)
from .service import (
    execute_chat,
    execute_review_action,
    execute_run,
    execute_tool_invoke,
    list_skills,
)

__all__ = [
    "create_app",
    "execute_run",
    "execute_tool_invoke",
    "execute_review_action",
    "list_skills",
    "DEMO_MODELS",
]

# 项目根目录（runtime.py -> agentarts -> logscan -> src -> demo）
_ROOT = Path(__file__).resolve().parents[3]
_STATIC = Path(__file__).resolve().parent / "static"

# 演示可选模型：模型名 -> OpenAI 兼容地址（API key 统一取 .env 的 OPENAI_API_KEY）
DEMO_MODELS: list[dict[str, str]] = [
    {
        "name": "qwen3.6-35b-a3b",
        "base_url": "http://59.65.232.180:18000/v1",
        "label": "qwen3.6-35b-a3b · 快 · 公网可达",
    },
    {
        "name": "qwen3.8-27b",
        "base_url": "http://202.204.64.234:11434/v1",
        "label": "qwen3.8-27b · 准 · 仅教育网",
    },
]
_MODEL_BASE_URL = {m["name"]: m["base_url"] for m in DEMO_MODELS}

# 演示任务状态（内存态，本地演示够用）
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


def _step_to_dict(step: Any) -> dict[str, Any]:
    return {
        "step": step.step,
        "type": step.type,
        "content": step.content,
        "tool_name": step.tool_name,
        "tool_args": step.tool_args,
        "tool_result": step.tool_result,
        "elapsed_ms": step.elapsed_ms,
    }


def _run_job(job_id: str, req: RunRequest, base_url: str | None) -> None:
    """后台线程里跑一次分析，把每步实时写入任务状态。"""

    def on_step(step: Any) -> None:
        with _JOBS_LOCK:
            _JOBS[job_id]["steps"].append(_step_to_dict(step))

    try:
        resp = execute_run(req, on_step=on_step, base_url=base_url)
        with _JOBS_LOCK:
            _JOBS[job_id]["result"] = resp.model_dump()
            _JOBS[job_id]["status"] = "done"
    except Exception as exc:  # 兜底：避免后台线程静默失败，前端一直转圈
        with _JOBS_LOCK:
            _JOBS[job_id]["error"] = f"{type(exc).__name__}: {exc}"
            _JOBS[job_id]["status"] = "error"


def _run_chat_job(job_id: str, req: ChatRequest, base_url: str | None) -> None:
    """后台线程里跑一次自然语言问答。"""

    def on_step(step: Any) -> None:
        with _JOBS_LOCK:
            _JOBS[job_id]["steps"].append(_step_to_dict(step))

    try:
        resp = execute_chat(req, on_step=on_step, base_url=base_url)
        with _JOBS_LOCK:
            _JOBS[job_id]["result"] = resp.model_dump()
            _JOBS[job_id]["status"] = "done"
    except Exception as exc:
        with _JOBS_LOCK:
            _JOBS[job_id]["error"] = f"{type(exc).__name__}: {exc}"
            _JOBS[job_id]["status"] = "error"


def create_app() -> FastAPI:
    """构造 FastAPI 应用实例（本地开发用）。"""
    app = FastAPI(
        title="LogScan Agent — AgentArts Runtime",
        description="安全日志漏洞扫描智能体运行时托管入口",
        version="0.1.0",
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/run", response_model=RunResponse)
    def run(req: RunRequest) -> RunResponse:
        return execute_run(req)

    @app.get("/tools", response_model=list[SkillDescriptor])
    def tools() -> list[dict[str, Any]]:
        return list_skills()

    @app.post("/tools/invoke", response_model=ToolInvokeResponse)
    def tool_invoke(req: ToolInvokeRequest) -> ToolInvokeResponse:
        try:
            return execute_tool_invoke(req)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.post("/chat", response_model=ChatResponse)
    def chat(req: ChatRequest) -> ChatResponse:
        """自然语言问答（同步返回，适合 mock 或短问题）。"""
        return execute_chat(req)

    @app.post("/review/action", response_model=ReviewActionResponse)
    def review_action(req: ReviewActionRequest) -> ReviewActionResponse:
        try:
            return execute_review_action(req)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # ---------------- 网页演示 ----------------

    @app.get("/", response_class=HTMLResponse)
    def demo_page() -> HTMLResponse:
        """演示页面（禁止缓存，避免改版后浏览器拿旧页面）。"""
        return HTMLResponse(
            (_STATIC / "index.html").read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-store, must-revalidate"},
        )

    @app.get("/demo/models")
    def demo_models() -> list[dict[str, str]]:
        """演示可选模型列表。"""
        return DEMO_MODELS

    @app.get("/demo/samples")
    def demo_samples() -> list[dict[str, str]]:
        """examples/ 下的示例日志（含统一 CSV）。"""
        out: list[dict[str, str]] = []
        ex_dir = _ROOT / "examples"
        for pattern in ("*.log", "*.csv"):
            for p in sorted(ex_dir.glob(pattern)):
                if p.is_file():
                    out.append({
                        "name": p.name,
                        "content": p.read_text(encoding="utf-8", errors="replace"),
                    })
        return out

    @app.post("/demo/start")
    def demo_start(req: RunRequest, model: str | None = None) -> dict[str, str]:
        """启动一次分析任务，立即返回 job_id。model 指定则覆盖 LLM 地址。"""
        base_url = _MODEL_BASE_URL.get(model) if model else None
        job_id = uuid.uuid4().hex
        with _JOBS_LOCK:
            _JOBS[job_id] = {"status": "running", "steps": [], "result": None, "error": "", "kind": "run"}
        threading.Thread(target=_run_job, args=(job_id, req, base_url), daemon=True).start()
        return {"job_id": job_id}

    @app.post("/demo/chat/start")
    def demo_chat_start(req: ChatRequest, model: str | None = None) -> dict[str, str]:
        """启动一次自然语言问答任务，立即返回 job_id。"""
        base_url = _MODEL_BASE_URL.get(model) if model else None
        job_id = uuid.uuid4().hex
        with _JOBS_LOCK:
            _JOBS[job_id] = {"status": "running", "steps": [], "result": None, "error": "", "kind": "chat"}
        threading.Thread(target=_run_chat_job, args=(job_id, req, base_url), daemon=True).start()
        return {"job_id": job_id}

    @app.get("/demo/status/{job_id}")
    def demo_status(job_id: str) -> dict[str, Any]:
        """查询任务进度（前端轮询用）。"""
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="job 不存在")
            return {
                "status": job["status"],
                "kind": job.get("kind", "run"),
                "steps": list(job["steps"]),
                "result": job["result"],
                "error": job["error"],
            }

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "logscan.agentarts.runtime:create_app",
        factory=True,
        host="0.0.0.0",
        port=8080,
    )
