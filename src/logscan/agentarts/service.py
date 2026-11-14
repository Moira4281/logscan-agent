"""AgentArts 运行时托管业务逻辑（不依赖 FastAPI，可被 SDK 入口或 HTTP 层复用）。

业务函数：execute_run / execute_tool_invoke / execute_review_action / list_skills。
部署时由 app.py（agentarts-sdk）调用；本地开发由 runtime.py（FastAPI）调用。
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any

from ..agent import LogScanAgent
from ..chat import ChatAgent
from ..config import Settings
from ..logs.store import LogStore
from ..mock_agent import MockAgent
from ..tools.builtin import default_registry
from .review import AUTO_RESOLVED, CONFIRMED, FALSE_POSITIVE, apply_action, apply_review, review_summary
from .schemas import (
    ChatRequest,
    ChatResponse,
    LogSource,
    ReviewActionRequest,
    ReviewActionResponse,
    RunOptions,
    RunRequest,
    RunResponse,
    ToolInvokeRequest,
    ToolInvokeResponse,
    TraceStep,
)
from .tools_adapter import invoke_tool, to_skill_descriptors, tool_result_to_dict


def _materialize_sources(sources: list[LogSource]) -> tuple[list[str], list[str]]:
    """把 LogSource 列表解析为文件路径列表；内联内容写入临时文件。返回 (paths, temp_paths)。"""
    paths: list[str] = []
    temps: list[str] = []
    for s in sources:
        if s.path:
            paths.append(s.path)
        elif s.content is not None:
            suffix = Path(s.filename or "log.log").suffix or ".log"
            fd, tmp = tempfile.mkstemp(suffix=suffix, text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(s.content)
            paths.append(tmp)
            temps.append(tmp)
    return paths, temps


def _settings_with_options(options: RunOptions) -> Settings:
    settings = Settings.load()
    if options.max_steps is not None:
        settings.max_steps = options.max_steps
    if options.max_log_lines is not None:
        settings.max_log_lines = options.max_log_lines
    if options.model is not None:
        settings.model = options.model
    return settings


def step_to_schema(s: Any) -> TraceStep:
    """把单个 AgentStep 转为可序列化的 TraceStep（异步轮询时按步增量返回用）。"""
    return TraceStep(
        step=s.step,
        type=s.type,
        content=s.content,
        tool_name=s.tool_name,
        tool_args=s.tool_args,
        tool_result=s.tool_result,
        elapsed_ms=s.elapsed_ms,
    )


def _trace_to_schema(result) -> list[TraceStep]:
    return [step_to_schema(s) for s in result.trace.steps]


def _cleanup(temps: list[str]) -> None:
    for t in temps:
        try:
            os.unlink(t)
        except OSError:
            pass


def list_skills() -> list[dict[str, Any]]:
    """列出全部 Skill 描述。"""
    return to_skill_descriptors(default_registry())


def execute_run(
    req: RunRequest,
    on_step: Any = None,
    base_url: str | None = None,
) -> RunResponse:
    """执行完整分析流程（运行时执行入口业务逻辑）。

    on_step: 可选回调，实时接收 Agent 的每一步（供 Web 演示前端展示）。
    base_url: 可选覆盖 LLM 地址（演示页面切换模型时用）。
    """
    if req.mode not in ("mock", "llm"):
        return RunResponse(success=False, error=f"未知 mode: {req.mode}，应为 mock 或 llm")

    settings = _settings_with_options(req.options)
    if base_url:
        settings.base_url = base_url
    paths, temps = _materialize_sources(req.sources)
    store: LogStore | None = None
    try:
        store = LogStore(settings.db_path)
        count = store.ingest_sources(paths, settings.max_log_lines)
        if count == 0:
            return RunResponse(success=False, error="未加载到任何日志条目")

        if req.mode == "llm":
            if not settings.api_key:
                return RunResponse(
                    success=False,
                    error="llm 模式需要 OPENAI_API_KEY，或改用 mode=mock",
                )
            agent = LogScanAgent(settings, store)
            result = agent.run(paths, on_step=on_step)
        else:
            agent = MockAgent(store)
            t_mock = time.perf_counter()
            result = agent.run(paths)
            if not result.trace.total_elapsed_ms:
                result.trace.total_elapsed_ms = int((time.perf_counter() - t_mock) * 1000)
        report = result.report
        if req.options.auto_review:
            report = apply_review(report)
        summary = review_summary(report)
        return RunResponse(
            success=result.success,
            report=report,
            trace=_trace_to_schema(result),
            raw_output=result.raw_output,
            error=result.error,
            total_elapsed_ms=result.trace.total_elapsed_ms,
            review_summary=summary,
        )
    except FileNotFoundError as exc:
        return RunResponse(success=False, error=f"日志文件不存在: {exc}")
    except Exception as exc:
        return RunResponse(success=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        if store is not None:
            store.close()
        _cleanup(temps)


def execute_tool_invoke(req: ToolInvokeRequest) -> ToolInvokeResponse:
    """单独调用某个工具/Skill。文件不存在时抛 FileNotFoundError。"""
    settings = Settings.load()
    paths, temps = _materialize_sources(req.sources)
    store: LogStore | None = None
    try:
        store = LogStore(settings.db_path)
        store.ingest_sources(paths, settings.max_log_lines)
        result = invoke_tool(default_registry(), store, req.name, req.args)
        return ToolInvokeResponse(**tool_result_to_dict(result))
    finally:
        if store is not None:
            store.close()
        _cleanup(temps)


def execute_review_action(req: ReviewActionRequest) -> ReviewActionResponse:
    """对单个事件执行人工复核操作。未知 action 时抛 ValueError。"""
    valid = {"confirm": CONFIRMED, "false_positive": FALSE_POSITIVE, "auto_resolved": AUTO_RESOLVED}
    if req.action not in valid:
        raise ValueError(f"未知 action: {req.action}")
    updated = apply_action(req.event, req.action)
    return ReviewActionResponse(
        event=updated,
        review_status=updated.get("review_status", ""),
        updated=True,
    )


# ------------------------------------------------------------------ #
# 自然语言问答
# ------------------------------------------------------------------ #

def _mock_chat_answer(store: LogStore, question: str) -> str:
    """mock 模式下基于规则+统计给出回答，不调 LLM。"""
    stats = default_registry().call(store, "get_stats", {}).data
    total = stats.get("total", 0)
    top_ips = [f"{i['ip']}({i['count']}次)" for i in stats.get("top_ips", [])[:5]]
    top_paths = [f"{p['path']}({p['count']}次)" for p in stats.get("top_paths", [])[:5]]
    by_status = [f"{s['status']}={s['count']}" for s in stats.get("by_status", [])[:5]]
    missing = stats.get("missing_note", "")

    lines = [f"日志共 {total} 条。"]
    q = question.lower()
    if any(k in q for k in ("ip", "源", "地址", "来源")):
        lines.append("来源 IP Top5: " + ("、".join(top_ips) if top_ips else "无"))
    if any(k in q for k in ("路径", "path", "访问", "请求")):
        lines.append("请求路径 Top5: " + ("、".join(top_paths) if top_paths else "无"))
    if any(k in q for k in ("错误", "error", "异常", "状态", "状态码")):
        lines.append("状态码分布: " + ("、".join(by_status) if by_status else "无"))
    if not any(k in q for k in ("ip", "源", "地址", "来源", "路径", "path", "访问", "请求", "错误", "error", "异常", "状态")):
        lines.append("来源 IP Top5: " + ("、".join(top_ips) if top_ips else "无"))
        lines.append("请求路径 Top5: " + ("、".join(top_paths) if top_paths else "无"))
        lines.append("状态码分布: " + ("、".join(by_status) if by_status else "无"))
    if missing:
        lines.append(f"注意: {missing}")
    return "\n".join(lines)


def execute_chat(
    req: ChatRequest,
    on_step: Any = None,
    base_url: str | None = None,
) -> ChatResponse:
    """执行一次自然语言问答。"""
    if req.mode not in ("mock", "llm"):
        return ChatResponse(success=False, error=f"未知 mode: {req.mode}，应为 mock 或 llm")

    settings = _settings_with_options(req.options)
    if base_url:
        settings.base_url = base_url
    paths, temps = _materialize_sources(req.sources)
    store: LogStore | None = None
    try:
        store = LogStore(settings.db_path)
        count = store.ingest_sources(paths, settings.max_log_lines)
        if count == 0:
            return ChatResponse(success=False, error="未加载到任何日志条目")

        if req.mode == "llm":
            if not settings.api_key:
                return ChatResponse(
                    success=False,
                    error="llm 模式需要 OPENAI_API_KEY，或改用 mode=mock",
                )
            agent = ChatAgent(settings, store)
            result = agent.chat(req.question, on_step=on_step)
            return ChatResponse(
                success=result.success,
                answer=result.answer,
                trace=_trace_to_schema(result),
                error=result.error,
                total_elapsed_ms=result.trace.total_elapsed_ms,
            )
        else:
            t_mock = time.perf_counter()
            answer = _mock_chat_answer(store, req.question)
            return ChatResponse(
                success=True,
                answer=answer,
                total_elapsed_ms=int((time.perf_counter() - t_mock) * 1000),
            )
    except FileNotFoundError as exc:
        return ChatResponse(success=False, error=f"日志文件不存在: {exc}")
    except Exception as exc:
        return ChatResponse(success=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        if store is not None:
            store.close()
        _cleanup(temps)