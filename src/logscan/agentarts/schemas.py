"""AgentArts 运行时托管请求/响应模型。

使用 pydantic BaseModel，与 FastAPI 集成；
同时保持可被标准库 json 序列化的纯数据结构。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LogSource(BaseModel):
    """一个日志源：可内联传内容，或给出运行时环境上的文件路径。"""

    path: str | None = Field(default=None, description="运行时环境上的日志文件/目录路径")
    content: str | None = Field(default=None, description="日志内容内联（适合小日志/演示）")
    filename: str | None = Field(default=None, description="内联内容对应的文件名（用于格式推断）")


class RunOptions(BaseModel):
    max_steps: int | None = Field(default=None, ge=1, le=50)
    max_log_lines: int | None = Field(default=None, ge=1)
    model: str | None = Field(default=None, description="覆盖模型名称")
    auto_review: bool = Field(default=True, description="是否对输出事件自动套用复核节点")


class RunRequest(BaseModel):
    """运行时执行入口请求体。"""

    mode: str = Field(default="mock", description="mock=规则驱动不调 LLM；llm=调用 LLM Agent")
    sources: list[LogSource] = Field(..., min_length=1, description="日志源列表")
    options: RunOptions = Field(default_factory=RunOptions)


class TraceStep(BaseModel):
    step: int
    type: str
    content: str = ""
    tool_name: str = ""
    tool_args: dict[str, Any] = Field(default_factory=dict)
    tool_result: str = ""
    elapsed_ms: int = 0


class RunResponse(BaseModel):
    success: bool
    report: dict[str, Any] = Field(default_factory=dict)
    trace: list[TraceStep] = Field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    total_elapsed_ms: int = 0
    review_summary: dict[str, int] = Field(default_factory=dict)


class ToolInvokeRequest(BaseModel):
    """单独调用某个工具/Skill。"""

    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    sources: list[LogSource] = Field(..., min_length=1, description="提供工具运行的日志上下文")


class ToolInvokeResponse(BaseModel):
    ok: bool
    data: Any = None
    error: str = ""


class SkillDescriptor(BaseModel):
    """平台 Skill 描述。"""

    name: str
    description: str
    parameters: dict[str, Any]


class ReviewActionRequest(BaseModel):
    """对单个事件执行人工复核操作。"""

    event: dict[str, Any]
    action: str = Field(..., description="confirm / false_positive / auto_resolved")
    note: str = ""


class ReviewActionResponse(BaseModel):
    event: dict[str, Any]
    review_status: str
    updated: bool


class ChatRequest(BaseModel):
    """自然语言问答请求。"""

    question: str = Field(..., min_length=1, description="用户的自然语言问题")
    sources: list[LogSource] = Field(..., min_length=1, description="日志源列表")
    mode: str = Field(default="llm", description="mock=规则模拟；llm=调用 LLM")
    options: RunOptions = Field(default_factory=RunOptions)


class ChatResponse(BaseModel):
    """自然语言问答响应。"""

    success: bool
    answer: str = ""
    trace: list[TraceStep] = Field(default_factory=list)
    error: str = ""
    total_elapsed_ms: int = 0