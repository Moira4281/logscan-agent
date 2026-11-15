"""实时监测：日志生成 → 实时规则判定 → SSE 推送。

设计约束：实时链路只走规则（毫秒级），LLM 仅用于节流后的深度研判。
演示日志由生成器合成，仅用于验证「采集 → 检测 → 推送」链路。
"""

from .service import RealtimeService, get_realtime_service

__all__ = ["RealtimeService", "get_realtime_service"]
