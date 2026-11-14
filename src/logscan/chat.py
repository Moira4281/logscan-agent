"""自然语言问答 Agent：多轮对话 + 工具调用，返回自然语言回答。

与 LogScanAgent（产出结构化 JSON 报告）的区别：
- ChatAgent 不强制 JSON 输出，最终回答就是自然语言文本。
- 维护跨轮的对话历史（messages），支持多轮追问。
- 同样基于 OpenAI 兼容 API 的 function calling。
"""

from __future__ import annotations

import json
import time
from typing import Any

from openai import OpenAI

from .agent import AgentStep, AgentTrace
from .config import Settings
from .logs.store import LogStore
from .prompts.templates import CHAT_SYSTEM_PROMPT
from .tools.base import ToolRegistry
from .tools.builtin import default_registry


class ChatResult:
    """一次 chat 调用的结果。"""

    def __init__(
        self,
        answer: str,
        trace: AgentTrace,
        success: bool,
        error: str = "",
    ) -> None:
        self.answer = answer
        self.trace = trace
        self.success = success
        self.error = error


class ChatAgent:
    """自然语言问答智能体，支持多轮对话。"""

    def __init__(
        self,
        settings: Settings,
        store: LogStore,
        registry: ToolRegistry | None = None,
        client: OpenAI | None = None,
    ) -> None:
        if not settings.api_key:
            raise ValueError(
                "未配置 OPENAI_API_KEY。请复制 .env.example 为 .env 并填入 API Key，或使用 mock 模式。"
            )
        self.settings = settings
        self.store = store
        self.registry = registry or default_registry()
        self.client = client or OpenAI(
            api_key=settings.api_key,
            base_url=settings.base_url,
        )
        self.messages: list[dict[str, Any]] = [
            {"role": "system", "content": CHAT_SYSTEM_PROMPT},
        ]
        self.tools_schema = self.registry.schemas()

    def reset(self) -> None:
        """清空对话历史，只保留系统提示。"""
        self.messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]

    def chat(self, question: str, on_step: Any = None) -> ChatResult:
        """发送一个问题，返回自然语言回答。多轮调用会累积历史。"""
        trace = AgentTrace()
        t0 = time.perf_counter()

        def _record(step: AgentStep) -> None:
            trace.add(step)
            if on_step is not None:
                on_step(step)

        self.messages.append({"role": "user", "content": question})

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
                    messages=self.messages,
                    tools=self.tools_schema,
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
                return ChatResult(
                    answer="", trace=trace, success=False,
                    error=f"LLM 调用失败: {exc}",
                )

            elapsed = int((time.perf_counter() - t1) * 1000)
            msg = resp.choices[0].message

            if msg.content:
                _record(AgentStep(
                    step=step_idx, type="llm_response",
                    content=msg.content[:500],
                    elapsed_ms=elapsed,
                ))

            # 没有工具调用 → 最终回答
            if not msg.tool_calls:
                answer = msg.content or ""
                _record(AgentStep(
                    step=step_idx, type="final",
                    content=answer[:500],
                    elapsed_ms=elapsed,
                ))
                trace.total_elapsed_ms = int((time.perf_counter() - t0) * 1000)
                # 把 assistant 的回答加入历史，供下一轮追问
                self.messages.append({"role": "assistant", "content": answer})
                return ChatResult(answer=answer, trace=trace, success=True)

            # 把 assistant 消息（含 tool_calls）加入对话
            self.messages.append(msg.model_dump(exclude_none=True))

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
                if len(result_str) > 8000:
                    result_str = result_str[:8000] + '\n...[结果已截断]'

                _record(AgentStep(
                    step=step_idx, type="tool_result",
                    tool_name=fn_name, tool_result=result_str[:300],
                ))

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_str,
                })

        # 超过最大步数
        trace.total_elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return ChatResult(
            answer="", trace=trace, success=False,
            error=f"达到最大步数 {self.settings.max_steps}，未得到最终回答",
        )
