"""实时监测服务：生成 → 解析 → 规则判定 → 广播（单例，进程内共享）。

传输采用 SSE：一个 HTTP 长连接上按事件推送 log / alert / stats，
浏览器断线后 EventSource 自动重连，重连时补发最近日志与告警。
"""

from __future__ import annotations

import queue
import threading
import time
from collections import deque
from typing import Any

from ..logs.parser import parse_line
from .detector import RealTimeDetector
from .generator import LogGenerator

_MAX_LOGS = 5000       # 环形缓冲：最近 5000 条
_MAX_ALERTS = 300
_SUB_QUEUE = 1000      # 单个 SSE 订阅者的积压上限


def _split_path(path: str) -> tuple[str, str]:
    p = path or ""
    if "?" in p:
        head, tail = p.split("?", 1)
        return head[:160], tail[:160]
    return p[:160], ""


class RealtimeService:
    """实时监测的运行时状态容器（进程内单例）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: set[queue.Queue] = set()
        self.logs: deque[dict[str, Any]] = deque(maxlen=_MAX_LOGS)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=_MAX_ALERTS)
        self._detector = RealTimeDetector()
        self._gen = LogGenerator(self._on_line)
        self._seq = 0
        self._total = 0
        self._suspicious = 0
        self._alert_total = 0
        self._by_sev: dict[str, int] = {}
        self._started_at = 0.0
        self._last_stats = 0.0

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start(self, rate: float | None = None) -> dict[str, Any]:
        if not self._gen.running:
            self._reset()
        if rate is not None:
            self._gen.set_rate(rate)
        self._gen.start()
        self._broadcast("stats", self.stats())
        return self.stats()

    def stop(self) -> dict[str, Any]:
        self._gen.stop()
        self._broadcast("stats", self.stats())
        return self.stats()

    def inject(self, kind: str = "bruteforce") -> dict[str, Any]:
        if not self._gen.running:      # 未启动时点「注入」也能立刻看到效果
            self.start()
        n = self._gen.inject(kind)
        return {"injected": n, "kind": kind, **self.stats()}

    def _reset(self) -> None:
        with self._lock:
            self.logs.clear()
            self.alerts.clear()
        self._detector = RealTimeDetector()
        self._seq = 0
        self._total = 0
        self._suspicious = 0
        self._alert_total = 0
        self._by_sev = {}
        self._started_at = time.monotonic()

    # ------------------------------------------------------------------ #
    # 采集 → 判定 → 推送
    # ------------------------------------------------------------------ #
    def _on_line(self, line: str) -> None:
        entry = parse_line(line)
        hits = self._detector.inspect(entry)

        self._seq += 1
        self._total += 1
        if hits:
            self._suspicious += 1
        path, params = _split_path(entry.path)
        first = hits[0] if hits else None
        item = {
            "id": self._seq,
            "ts": (entry.timestamp[11:19] if len(entry.timestamp) >= 19
                   else time.strftime("%H:%M:%S")),
            "ip": entry.source_ip,
            "method": entry.method,
            "path": path,
            "params": params,
            "status": entry.status_code,
            "ua": str(entry.extra.get("user_agent", ""))[:64],
            "label": "suspicious" if hits else "normal",
            "rule": first["rule"] if first else "",
            "sev": first["severity"] if first else "",
        }
        with self._lock:
            self.logs.append(item)
        self._broadcast("log", item)

        for alert in hits:
            if not alert.get("updated"):
                self._alert_total += 1
                self._by_sev[alert["severity"]] = self._by_sev.get(alert["severity"], 0) + 1
                with self._lock:
                    self.alerts.append(alert)
            self._broadcast("alert", alert)

        now = time.monotonic()
        if now - self._last_stats >= 1.0:
            self._last_stats = now
            self._broadcast("stats", self.stats())

    # ------------------------------------------------------------------ #
    # 订阅 / 广播
    # ------------------------------------------------------------------ #
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=_SUB_QUEUE)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    def _broadcast(self, event: str, data: Any) -> None:
        msg = {"event": event, "data": data}
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:
                try:
                    q.get_nowait()          # 丢弃最旧一条，保证连接不阻塞
                    q.put_nowait(msg)
                except (queue.Empty, queue.Full):
                    pass

    # ------------------------------------------------------------------ #
    # 快照 / 统计
    # ------------------------------------------------------------------ #
    def stats(self) -> dict[str, Any]:
        running = self._gen.running
        return {
            "running": running,
            "rate": self._gen.rate,
            "uptime": int(time.monotonic() - self._started_at) if running else 0,
            "total": self._total,
            "suspicious": self._suspicious,
            "alerts": self._alert_total,
            "by_severity": dict(self._by_sev),
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            logs = list(self.logs)[-80:]
            alerts = list(self.alerts)[-40:]
        return {"stats": self.stats(), "logs": logs, "alerts": alerts}


_SERVICE: RealtimeService | None = None
_SERVICE_LOCK = threading.Lock()


def get_realtime_service() -> RealtimeService:
    """进程内单例（确保 HTTP 请求线程与后台生成器共用同一份状态）。"""
    global _SERVICE
    with _SERVICE_LOCK:
        if _SERVICE is None:
            _SERVICE = RealtimeService()
        return _SERVICE
