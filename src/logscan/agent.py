"""ReAct Agent 核心：LLM 驱动的工具循环。

使用 OpenAI 兼容 API 的 function calling 能力，让 LLM 自主决定
调用哪些工具、如何分析，最终输出结构化漏洞报告。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

from .config import Settings
from .logs.store import LogStore
from .prompts.templates import SYSTEM_PROMPT, user_task_prompt
from .tools.base import ToolRegistry
from .tools.builtin import default_registry


# ------------------------------------------------------------------ #
# 运行追踪
# ------------------------------------------------------------------ #

@dataclass
class AgentStep:
    step: int
    type: str               # "llm_response" / "tool_call" / "tool_result" / "final" / "error"
    content: str = ""
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    tool_result: str = ""
    elapsed_ms: int = 0


@dataclass
class AgentTrace:
    steps: list[AgentStep] = field(default_factory=list)
    total_elapsed_ms: int = 0

    def add(self, step: AgentStep) -> None:
        self.steps.append(step)


# ------------------------------------------------------------------ #
# 结果
# ------------------------------------------------------------------ #

@dataclass
class AnalysisResult:
    report: dict[str, Any]
    trace: AgentTrace
    raw_output: str
    success: bool
    error: str = ""


# ------------------------------------------------------------------ #
# JSON 提取
# ------------------------------------------------------------------ #

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json(text: str) -> dict[str, Any] | None:
    # 优先尝试 markdown 代码块
    for m in _JSON_BLOCK.finditer(text):
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
    # 尝试直接解析
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # 尝试找到第一个 { 到最后一个 } 的范围
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass
    return None


# ------------------------------------------------------------------ #
# Agent
# ------------------------------------------------------------------ #

class LogScanAgent:
    """安全日志分析智能体。"""

    def __init__(
        self,
        settings: Settings,
        store: LogStore,
        registry: ToolRegistry | None = None,
    ) -> None:
        if not settings.api_key:
            raise ValueError(
                "未配置 OPENAI_API_KEY。请复制 .env.example 为 .env 并填入 API Key。"
            )
        self.settings = settings
        self.store = store
        self.registry = registry or default_registry()
        self.client = OpenAI(
            api_key=settings.api_key,
            base_url=settings.base_url,
        )

    def run(self, sources: list[str], on_step: Any = None) -> AnalysisResult:
        """执行完整分析流程。

        on_step: 可选回调，每产生一个 trace 步骤时调用（用于 Web 前端实时展示）。
        """
        trace = AgentTrace()
        t0 = time.perf_counter()

        def _record(step: AgentStep) -> None:
            trace.add(step)
            if on_step is not None:
                on_step(step)

        total = self.store.total()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_task_prompt(sources, total)},
        ]
        tools_schema = self.registry.schemas()
        # 思考型模型：关闭思考可显著提速（且避免正文被思考占满）
        extra_body = (
            {"chat_template_kwargs": {"enable_thinking": False}}
            if self.settings.disable_thinking
            else None
        )

        for step_idx in range(1, self.settings.max_steps + 1):
            t1 = time.perf_counter()
            try:
                resp = self.client.chat.completions.create(
                    model=self.settings.model,
                    messages=messages,
                    tools=tools_schema,
                    tool_choice="auto",
                    temperature=0.2,
                    extra_body=extra_body,
                )
            except Exception as exc:
                _record(AgentStep(
                    step=step_idx, type="error",
                    content=f"LLM 调用失败: {exc}",
                    elapsed_ms=int((time.perf_counter() - t1) * 1000),
                ))
                return AnalysisResult(
                    report={}, trace=trace, raw_output="",
                    success=False, error=f"LLM 调用失败: {exc}",
                )

            elapsed = int((time.perf_counter() - t1) * 1000)
            msg = resp.choices[0].message

            # 记录 LLM 响应
            if msg.content:
                _record(AgentStep(
                    step=step_idx, type="llm_response",
                    content=msg.content[:500],
                    elapsed_ms=elapsed,
                ))

            # 没有工具调用 → 最终输出
            if not msg.tool_calls:
                report = _extract_json(msg.content or "")
                _record(AgentStep(
                    step=step_idx, type="final",
                    content=(msg.content or "")[:500],
                    elapsed_ms=elapsed,
                ))
                trace.total_elapsed_ms = int((time.perf_counter() - t0) * 1000)
                if report is None:
                    return AnalysisResult(
                        report={"raw": msg.content},
                        trace=trace, raw_output=msg.content or "",
                        success=False, error="无法解析为 JSON",
                    )
                return AnalysisResult(
                    report=report, trace=trace,
                    raw_output=msg.content or "", success=True,
                )

            # 把 assistant 消息（含 tool_calls）加入对话
            messages.append(msg.model_dump(exclude_none=True))

            # 执行每个工具调用
            for tc in msg.tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    fn_args = {}

                _record(AgentStep(
                    step=step_idx, type="tool_call",
                    tool_name=fn_name, tool_args=fn_args,
                ))

                result = self.registry.call(self.store, fn_name, fn_args)
                result_str = result.to_json()

                # 截断过长的工具结果，避免上下文爆炸
                if len(result_str) > 8000:
                    result_str = result_str[:8000] + '\n...[结果已截断]'

                _record(AgentStep(
                    step=step_idx, type="tool_result",
                    tool_name=fn_name, tool_result=result_str[:300],
                ))

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_str,
                })

        # 超过最大步数
        trace.total_elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return AnalysisResult(
            report={}, trace=trace, raw_output="",
            success=False,
            error=f"达到最大步数 {self.settings.max_steps}，分析未完成",
        )