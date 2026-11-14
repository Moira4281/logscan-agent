"""工具基类与注册表。"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..logs.store import LogStore


@dataclass
class ToolResult:
    ok: bool
    data: Any
    error: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {"ok": self.ok, "data": self.data, "error": self.error},
            ensure_ascii=False,
            default=str,
        )


class Tool(ABC):
    name: str
    description: str
    parameters: dict[str, Any]   # JSON Schema

    @abstractmethod
    def execute(self, store: LogStore, args: dict[str, Any]) -> ToolResult:
        ...

    def schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def call(self, store: LogStore, name: str, args: dict[str, Any]) -> ToolResult:
        tool = self.get(name)
        if tool is None:
            return ToolResult(ok=False, data=None, error=f"未知工具: {name}")
        try:
            return tool.execute(store, args)
        except Exception as exc:
            return ToolResult(ok=False, data=None, error=f"{type(exc).__name__}: {exc}")