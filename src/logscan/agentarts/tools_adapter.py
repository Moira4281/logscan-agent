"""工具 → AgentArts 平台 Skill 适配层。

把现有 ToolRegistry 中的工具转换为平台 Skill 描述，
并提供统一的调用分发。这是"两步走"第二步（抽成平台 Skill）的适配基础。
"""

from __future__ import annotations

from typing import Any

from ..logs.store import LogStore
from ..tools.base import ToolRegistry, ToolResult


def to_skill_descriptors(registry: ToolRegistry) -> list[dict[str, Any]]:
    """把注册表中的全部工具转为平台 Skill 描述列表。"""
    descriptors: list[dict[str, Any]] = []
    for name in registry.names():
        tool = registry.get(name)
        if tool is None:
            continue
        descriptors.append({
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        })
    return descriptors


def invoke_tool(
    registry: ToolRegistry,
    store: LogStore,
    name: str,
    args: dict[str, Any],
) -> ToolResult:
    """调用指定工具并返回标准 ToolResult。"""
    return registry.call(store, name, args)


def tool_result_to_dict(result: ToolResult) -> dict[str, Any]:
    """ToolResult 转为可序列化字典。"""
    return {"ok": result.ok, "data": result.data, "error": result.error}