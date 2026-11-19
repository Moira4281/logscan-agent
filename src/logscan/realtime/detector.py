"""实时规则引擎：单条签名匹配 + 短窗口行为聚合。

与离线统计规则（rules/statistical_rules.py 查 SQLite）不同，这里面向流式日志：
每条日志进入即判定，纯内存计算，单条耗时 < 1ms，不依赖数据库与 LLM。

两层规则：
  1. 单条签名：文件包含 / SQL 注入 / 路径遍历 / XSS / 敏感文件探测 / 扫描器指纹
  2. 短窗口聚合：同 IP 登录失败 ≥5 次/30 秒（爆破）、同 IP 404 ≥10 次/15 秒（目录扫描）

同一 (规则, IP) 在冷却窗口内重复命中时只聚合成一条告警（count 递增），
避免一场爆破刷出几百条重复告警。
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import Any
from urllib.parse import unquote

from ..logs.parser import LogEntry

# (规则号, 类型, 严重级别, 特征关键词)
_SIGNATURES: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("RT-001", "文件包含尝试（LFI）", "CRITICAL",
     ("?file=", "?page=", "?include=", "?template=", "php://", "data://")),
    ("RT-002", "SQL 注入尝试", "CRITICAL",
     ("union select", "or 1=1", "or '1'='1", "sleep(", "information_schema",
      "drop table", ";--")),
    ("RT-003", "路径遍历尝试", "HIGH",
     ("../", "..\\", "..%2f", "%2e%2e", "/etc/passwd", "/etc/shadow", "win.ini")),
    ("RT-004", "XSS 跨站脚本尝试", "HIGH",
     ("<script", "onerror=", "javascript:", "alert(")),
    ("RT-005", "敏感文件/后台探测", "MEDIUM",
     ("/.env", "/.git", "/wp-admin", "phpmyadmin", "/backup.", "/db.sql",
      ".ds_store", "/server-status", "/actuator")),
    ("RT-006", "攻击工具指纹（User-Agent）", "MEDIUM",
     ("sqlmap", "nikto", "masscan", "acunetix", "dirbuster", "nmap scripting")),
]

_LOGIN_HINTS = ("login", "signin", "auth")


def _now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")


class RealTimeDetector:
    """流式日志的即时判定器（线程内串行调用，无需额外加锁）。"""

    cooldown_sec = 20.0     # 同 (规则, IP) 聚合冷却
    keep_sec = 60.0         # 每 IP 行为事件保留时长
    brute_window = 30.0     # 爆破统计窗口
    brute_min = 5           # 窗口内登录失败次数阈值
    scan_window = 15.0      # 扫描统计窗口
    scan_min = 10           # 窗口内 404 次数阈值

    def __init__(self) -> None:
        self._events: dict[str, deque] = {}
        self._recent: dict[tuple[str, str], list[Any]] = {}
        self._seq = 0

    # ------------------------------------------------------------------ #
    # 对外入口
    # ------------------------------------------------------------------ #
    def inspect(self, entry: LogEntry) -> list[dict[str, Any]]:
        """判定一条日志，返回告警列表（无告警返回空列表）。"""
        # 先做一次 URL 解码，避免攻击 payload 被 %20 / %27 编码后绕过特征匹配
        text = unquote(entry.raw or "").lower()
        alerts: list[dict[str, Any]] = []
        for rule, rtype, sev, keywords in _SIGNATURES:
            hit = next((k for k in keywords if k in text), None)
            if hit:
                alerts.append(self._make(
                    rule, rtype, sev, entry, f"命中特征「{hit}」", hit,
                ))
                break                      # 一条日志只归到最具体的那条签名
        alerts.extend(self._check_windows(entry))
        return alerts

    # ------------------------------------------------------------------ #
    # 内部实现
    # ------------------------------------------------------------------ #
    def _check_windows(self, entry: LogEntry) -> list[dict[str, Any]]:
        """短窗口行为聚合：爆破 / 目录扫描。"""
        ip = entry.source_ip
        if not ip:
            return []
        now = time.monotonic()
        dq = self._events.get(ip)
        if dq is None:
            dq = deque(maxlen=160)
            self._events[ip] = dq
        dq.append((now, entry.status_code, (entry.path or "").lower()))
        while dq and now - dq[0][0] > self.keep_sec:
            dq.popleft()

        out: list[dict[str, Any]] = []

        fails = [e for e in dq
                 if now - e[0] <= self.brute_window
                 and e[1] in (401, 403)
                 and any(k in e[2] for k in _LOGIN_HINTS)]
        if len(fails) >= self.brute_min:
            out.append(self._make(
                "RT-007", "暴力破解（登录失败聚合）", "HIGH", entry,
                f"{self.brute_window:.0f} 秒内登录端点出现 {len(fails)} 次 401/403"
                f"（阈值 ≥{self.brute_min} 次）",
            ))

        n404 = [e for e in dq if now - e[0] <= self.scan_window and e[1] == 404]
        if len(n404) >= self.scan_min:
            out.append(self._make(
                "RT-008", "目录扫描（404 聚合）", "MEDIUM", entry,
                f"{self.scan_window:.0f} 秒内出现 {len(n404)} 次 404（阈值 ≥{self.scan_min} 次）",
            ))
        return out

    def _make(
        self,
        rule: str,
        rtype: str,
        sev: str,
        entry: LogEntry,
        evidence: str,
        match: str = "",
    ) -> dict[str, Any]:
        """生成告警；冷却窗口内同 (规则, IP) 命中则聚合并标记 updated。

        match 为命中的特征词，前端据此在原始日志里标黄。
        """
        ip = entry.source_ip or "(无源IP)"
        key = (rule, ip)
        now = time.monotonic()

        hit = self._recent.get(key)
        if hit and now - hit[0] <= self.cooldown_sec:
            alert = hit[1]
            alert["count"] += 1
            alert["updated"] = True
            alert["ts"] = _now_str()
            alert["evidence"] = evidence
            alert["match"] = match
            hit[0] = now
            return alert

        self._seq += 1
        alert = {
            "id": f"RT{self._seq:04d}",
            "ts": _now_str(),
            "rule": rule,
            "type": rtype,
            "severity": sev,
            "ip": ip,
            "path": (entry.path or "")[:160],
            "evidence": evidence,
            "match": match,
            "count": 1,
            "updated": False,
        }
        self._recent[key] = [now, alert]

        if len(self._recent) > 400:          # 防止长时间运行无限增长
            cutoff = now - self.cooldown_sec
            for k in [k for k, v in self._recent.items() if v[0] < cutoff]:
                self._recent.pop(k, None)
        return alert
