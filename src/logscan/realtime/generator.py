"""实时日志生成器：周期注入攻击剧本 + 正常业务流量。

只对外暴露 start / stop / set_rate / inject，内部维护一个 20ms 精度的
调度循环，把生成的日志行交给 sink（service 层负责解析与检测）。

说明：生成的是**合成日志**，仅用于验证「采集 → 规则判定 → 实时推送」链路，
不代表任何真实业务流量。随机种子固定（默认 42），答辩演示可复现。
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# 正常业务路径（路径, 状态码）
_NORMAL_TARGETS: list[tuple[str, int]] = [
    ("/", 200),
    ("/index.php", 200),
    ("/products", 200),
    ("/products?category=router", 200),
    ("/search?q=mesh+wifi", 200),
    ("/api/orders", 200),
    ("/api/orders/1024", 200),
    ("/cart", 200),
    ("/login", 200),
    ("/about", 200),
    ("/news/2026-11", 200),
    ("/static/app.js", 200),
    ("/static/style.css", 304),
    ("/images/banner.jpg", 200),
    ("/favicon.ico", 404),
]

_NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/127.0 Mobile Safari/537.36",
]

# 攻击剧本：(方法, 目标, 状态码)
_TARGETS: dict[str, list[tuple[str, str, int]]] = {
    "sqli": [
        ("GET", "/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", 200),
        ("GET", "/products?id=1%20OR%201=1", 200),
        ("GET", "/search?q=admin%27%20AND%20SLEEP(5)--", 200),
        ("GET", "/api/orders?order_id=1;DROP%20TABLE%20orders--", 500),
        ("GET", "/products?id=-1%20UNION%20SELECT%20*%20FROM%20information_schema.tables", 200),
    ],
    "traversal": [
        ("GET", "/download/../../../../etc/passwd", 200),
        ("GET", "/static/../../../../etc/passwd", 403),
        ("GET", "/download/..%2f..%2f..%2fetc%2fpasswd", 200),
        ("GET", "/files/../../../../windows/win.ini", 200),
        ("GET", "/download/../../../../etc/shadow", 403),
    ],
    "lfi": [
        ("GET", "/index.php?page=php://filter/convert.base64-encode/resource=config", 200),
        ("GET", "/index.php?file=php://input", 200),
        ("GET", "/page.php?include=../../../../etc/passwd", 200),
        ("GET", "/index.php?template=data://text/plain;base64,PD9waHA=", 200),
    ],
    "bruteforce": [
        ("POST", "/login", 401),
        ("POST", "/admin/login", 403),
    ],
    "scanner": [
        ("GET", "/.env", 404),
        ("GET", "/.git/config", 404),
        ("GET", "/wp-admin/", 404),
        ("GET", "/phpmyadmin/", 404),
        ("GET", "/backup.zip", 404),
        ("GET", "/config.php.bak", 404),
        ("GET", "/admin.php", 404),
        ("GET", "/db.sql", 404),
        ("GET", "/.DS_Store", 404),
        ("GET", "/server-status", 404),
        ("GET", "/actuator/env", 404),
        ("GET", "/console", 404),
    ],
}

_ATTACK_UA: dict[str, list[str]] = {
    "sqli": ["sqlmap/1.8.3#stable (https://sqlmap.org)",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
    "traversal": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                  "python-requests/2.31.0"],
    "lfi": ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "python-requests/2.31.0"],
    "bruteforce": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                   "python-requests/2.31.0"],
    "scanner": ["Nikto/2.5.0", "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
                "dirbuster/1.0"],
}

# 周期剧本：首次触发时间 / 周期 / 每轮请求数 / 时间跨度
_CAMPAIGNS: list[dict[str, Any]] = [
    {"kind": "sqli",       "first": 4.0,  "period": 45.0, "count": 5,  "span": 8.0},
    {"kind": "traversal",  "first": 8.0,  "period": 40.0, "count": 5,  "span": 6.0},
    {"kind": "lfi",        "first": 12.0, "period": 55.0, "count": 4,  "span": 6.0},
    {"kind": "bruteforce", "first": 16.0, "period": 50.0, "count": 8,  "span": 4.0},
    {"kind": "scanner",    "first": 20.0, "period": 60.0, "count": 12, "span": 10.0},
]


class LogGenerator:
    """后台线程按设定速率吐日志行；攻击剧本周期性注入。"""

    def __init__(
        self,
        sink: Callable[[str], None],
        rate: float = 5.0,
        seed: int = 42,
    ) -> None:
        self._sink = sink
        self._rng = random.Random(seed)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._rate = self._clamp_rate(rate)
        self._pending: list[tuple[float, dict[str, Any]]] = []
        self._next_normal_at = 0.0
        self._clients = [f"203.0.113.{i}" for i in self._rng.sample(range(2, 251), 18)]

    # ------------------------------------------------------------------ #
    # 对外接口
    # ------------------------------------------------------------------ #
    @property
    def running(self) -> bool:
        t = self._thread
        return bool(t and t.is_alive())

    @property
    def rate(self) -> float:
        return self._rate

    def set_rate(self, rate: float) -> None:
        self._rate = self._clamp_rate(rate)

    def start(self, rate: float | None = None) -> None:
        if rate is not None:
            self.set_rate(rate)
        if self.running:
            return
        self._stop.clear()
        with self._lock:
            self._pending.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="logscan-realtime-gen"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=2.0)
        self._thread = None

    def inject(self, kind: str = "bruteforce", count: int = 8) -> int:
        """手动注入一轮攻击（默认暴力破解），约 1 秒内走完，便于现场演示。"""
        if kind not in _TARGETS:
            kind = "bruteforce"
        with self._lock:
            ip = f"198.51.100.{self._rng.randint(200, 250)}"
            specs = self._attack_specs(kind, ip, count)
            now = time.monotonic()
            for i, spec in enumerate(specs):
                self._pending.append((now + 0.12 * i, spec))
        return len(specs)

    # ------------------------------------------------------------------ #
    # 调度循环
    # ------------------------------------------------------------------ #
    def _run(self) -> None:
        now = time.monotonic()
        self._next_normal_at = now
        for c in _CAMPAIGNS:
            c["next_at"] = now + c["first"]

        while not self._stop.is_set():
            now = time.monotonic()

            # 1) 到期攻击报文
            due: list[dict[str, Any]] = []
            with self._lock:
                if self._pending:
                    due = [s for at, s in self._pending if at <= now]
                    self._pending = [(at, s) for at, s in self._pending if at > now]
            for spec in due:
                self._emit(spec)

            # 2) 启动新一轮攻击剧本
            for c in _CAMPAIGNS:
                if now >= c["next_at"]:
                    self._schedule_campaign(c, now)
                    c["next_at"] = now + c["period"]

            # 3) 正常业务流量（补齐节奏，最多一次补 10 条防止卡顿后爆发）
            n = 0
            while now >= self._next_normal_at and n < 10:
                self._emit(self._normal_spec())
                self._next_normal_at += 1.0 / self._rate
                n += 1
            if self._next_normal_at < now:
                self._next_normal_at = now

            self._stop.wait(0.02)

    def _schedule_campaign(self, c: dict[str, Any], now: float) -> None:
        with self._lock:
            ip = f"198.51.100.{self._rng.randint(10, 199)}"
        specs = self._attack_specs(c["kind"], ip, c["count"])
        span = c["span"]
        with self._lock:
            for i, spec in enumerate(specs):
                at = now + span * i / max(len(specs) - 1, 1)
                self._pending.append((at, spec))

    def _attack_specs(self, kind: str, ip: str, count: int) -> list[dict[str, Any]]:
        targets = _TARGETS[kind]
        uas = _ATTACK_UA.get(kind, _ATTACK_UA["sqli"])
        return [
            {
                "ip": ip,
                "method": targets[i % len(targets)][0],
                "target": targets[i % len(targets)][1],
                "status": targets[i % len(targets)][2],
                "ua": uas[i % len(uas)],
            }
            for i in range(count)
        ]

    def _normal_spec(self) -> dict[str, Any]:
        r = self._rng
        target, status = r.choice(_NORMAL_TARGETS)
        method = "GET"
        if "login" in target:
            method = "POST" if r.random() < 0.5 else "GET"
            status = 200 if r.random() < 0.9 else 401
        elif target.startswith("/api/orders"):
            method = "POST" if r.random() < 0.25 else "GET"
        return {
            "ip": r.choice(self._clients),
            "method": method,
            "target": target,
            "status": status,
            "ua": r.choice(_NORMAL_UA),
        }

    # ------------------------------------------------------------------ #
    # 输出
    # ------------------------------------------------------------------ #
    def _emit(self, spec: dict[str, Any]) -> None:
        line = self._line(spec)
        try:
            self._sink(line)
        except Exception:       # 单条失败不影响整条流
            pass

    def _line(self, spec: dict[str, Any]) -> str:
        now = datetime.now()
        ts = (f"{now.day:02d}/{_MONTHS[now.month - 1]}/{now.year}:"
              f"{now.hour:02d}:{now.minute:02d}:{now.second:02d} +0800")
        nbytes = self._rng.randint(180, 9000)
        return (
            f'{spec["ip"]} - - [{ts}] "{spec["method"]} {spec["target"]} HTTP/1.1" '
            f'{spec["status"]} {nbytes} "-" "{spec["ua"]}"'
        )

    @staticmethod
    def _clamp_rate(rate: float) -> float:
        try:
            r = float(rate)
        except (TypeError, ValueError):
            r = 5.0
        return max(0.2, min(200.0, r))
