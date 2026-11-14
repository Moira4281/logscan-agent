"""通用日志解析器。

按优先级尝试多种格式，将任意日志行解析为标准化的 LogEntry：
  JSON → syslog → Nginx/Apache → CSV → 通用时间戳兜底

标准化字段：timestamp / level / message / source_ip / user /
path / method / status_code / extra(dict) / raw
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

# ------------------------------------------------------------------ #
# 正则模式
# ------------------------------------------------------------------ #

# ISO 8601 / 常见变体: 2024-01-15T10:30:45.123Z / 2024-01-15 10:30:45
_ISO_TS = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
# syslog: Jan 15 10:30:45
_SYSLOG_TS = re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
# Nginx time_local: 15/Jan/2024:10:30:45 +0000
_NGINX_TS = re.compile(r"(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})")
# epoch: 1705314645 或 1705314645123
_EPOCH_TS = re.compile(r"(?<![\d.])(\d{10})(?![\d])")

# syslog 完整: <134>Jan 15 10:30:45 host app[pid]: msg  或  host app: msg
_SYSLOG_LINE = re.compile(
    r"^(?:<(\d+)>)?"               # 可选 priority
    r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"                    # hostname
    r"([\w./-]+)(?:\[(\d+)\])?:\s*"  # program[pid]:
    r"(.*)$"                       # message
)

# Nginx/Apache combined
# request 字段用 "([^"]*)" 完整匹配，因为 payload 可能含空格（如 SQL 注入）
_NGINX_LINE = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+'                        # remote_addr - remote_user
    r'\[([^\]]+)\]\s+'                                 # time_local
    r'"([^"]*)"\s+'                                    # "request" 完整行
    r'(\d{3})\s+'                                      # status
    r'(\S+)\s+'                                        # body_bytes_sent
    r'"([^"]*)"\s+'                                    # referer
    r'"([^"]*)"'                                       # user_agent
)

# 原始 HTTP 报文 dump 的请求行：GET /path HTTP/1.1 或 POST http://host:port/path?q HTTP/1.1
_HTTP_REQ_LINE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+(\S+)\s+HTTP/(\d(?:\.\d)?)\s*$"
)

# 单条记录的长度上限（防止超大报文撑爆存储）
_MSG_MAX = 500
_BODY_MAX = 2000
_RAW_MAX = 8000

# 级别推断
_LEVEL_PATTERNS = [
    (re.compile(r"\b(critical|fatal|emerg|alert)\b", re.I), "CRITICAL"),
    (re.compile(r"\b(error|exception|failed|failure|traceback)\b", re.I), "ERROR"),
    (re.compile(r"\b(warn|warning|deprecated)\b", re.I), "WARN"),
    (re.compile(r"\b(debug|verbose)\b", re.I), "DEBUG"),
]

# 月份缩写 → 数字
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


# ------------------------------------------------------------------ #
# 数据结构
# ------------------------------------------------------------------ #

@dataclass
class LogEntry:
    timestamp: str = ""
    level: str = "INFO"
    message: str = ""
    source_ip: str = ""
    user: str = ""
    path: str = ""
    method: str = ""
    status_code: int = 0
    extra: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def as_dict(self) -> dict[str, Any]:
        d = {
            "timestamp": self.timestamp,
            "level": self.level,
            "message": self.message,
            "source_ip": self.source_ip,
            "user": self.user,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "extra": json.dumps(self.extra, ensure_ascii=False) if self.extra else "",
            "raw": self.raw,
        }
        return d


# ------------------------------------------------------------------ #
# 时间戳解析
# ------------------------------------------------------------------ #

def _parse_iso(ts: str) -> str:
    try:
        s = ts.replace(" ", "T")
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt.isoformat()
    except Exception:
        return ts


def _parse_syslog_ts(ts: str) -> str:
    try:
        parts = ts.split()
        mon = _MONTHS[parts[0]]
        day = int(parts[1])
        hms = parts[2].split(":")
        dt = datetime(datetime.now().year, mon, day, int(hms[0]), int(hms[1]), int(hms[2]))
        return dt.isoformat()
    except Exception:
        return ts


def _parse_nginx_ts(ts: str) -> str:
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except Exception:
        return ts


def _parse_epoch(ts: str) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return ts


def _infer_level(text: str) -> str:
    for pat, lvl in _LEVEL_PATTERNS:
        if pat.search(text):
            return lvl
    return "INFO"


def _syslog_priority_to_level(prio: int) -> str:
    severity = prio & 0x07
    return {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR",
            4: "WARN", 5: "INFO", 6: "INFO", 7: "DEBUG"}.get(severity, "INFO")


# ------------------------------------------------------------------ #
# 各格式解析函数
# ------------------------------------------------------------------ #

def _parse_json_line(line: str) -> LogEntry | None:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None

    e = LogEntry(raw=line)
    # 常见字段名映射
    ts = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp") or obj.get("datetime")
    if ts:
        e.timestamp = _parse_iso(str(ts)) if _ISO_TS.search(str(ts)) else str(ts)
    e.level = str(obj.get("level") or obj.get("severity") or obj.get("loglevel") or "").upper() or "INFO"
    e.message = str(obj.get("message") or obj.get("msg") or obj.get("log") or "")
    e.source_ip = str(obj.get("ip") or obj.get("source_ip") or obj.get("remote_addr") or obj.get("client_ip") or "")
    e.user = str(obj.get("user") or obj.get("username") or obj.get("remote_user") or "")
    e.path = str(obj.get("path") or obj.get("url") or obj.get("request_path") or "")
    e.method = str(obj.get("method") or obj.get("http_method") or "")
    sc = obj.get("status") or obj.get("status_code") or obj.get("response_status")
    if sc:
        try:
            e.status_code = int(sc)
        except (ValueError, TypeError):
            pass

    known = {"timestamp", "time", "@timestamp", "datetime", "level", "severity",
             "loglevel", "message", "msg", "log", "ip", "source_ip", "remote_addr",
             "client_ip", "user", "username", "remote_user", "path", "url",
             "request_path", "method", "http_method", "status", "status_code",
             "response_status"}
    e.extra = {k: v for k, v in obj.items() if k not in known}
    if not e.message:
        e.message = line[:200]
    return e


def _parse_syslog_line(line: str) -> LogEntry | None:
    m = _SYSLOG_LINE.match(line)
    if not m:
        return None
    prio, ts, host, prog, pid, msg = m.groups()
    e = LogEntry(
        timestamp=_parse_syslog_ts(ts),
        message=msg,
        raw=line,
    )
    e.extra["host"] = host
    e.extra["program"] = prog
    if pid:
        e.extra["pid"] = int(pid)
    if prio:
        e.level = _syslog_priority_to_level(int(prio))
    else:
        e.level = _infer_level(msg)
    return e


def _parse_nginx_line(line: str) -> LogEntry | None:
    m = _NGINX_LINE.match(line)
    if not m:
        return None
    addr, user, ts, request, status, _bytes, referer, ua = m.groups()
    # 从完整 request 行提取 method 和 path
    req_parts = request.split()
    method = req_parts[0] if req_parts else ""
    path = req_parts[1] if len(req_parts) > 1 else ""
    e = LogEntry(
        timestamp=_parse_nginx_ts(ts),
        source_ip=addr,
        user=user if user != "-" else "",
        method=method,
        path=path,
        status_code=int(status),
        message=f'{method} {path} {status}',
        raw=line,
    )
    e.extra["referer"] = referer if referer != "-" else ""
    e.extra["user_agent"] = ua
    e.extra["bytes"] = int(_bytes) if _bytes != "-" else 0
    if e.status_code >= 500:
        e.level = "ERROR"
    elif e.status_code >= 400:
        e.level = "WARN"
    else:
        e.level = "INFO"
    return e


def _parse_generic_line(line: str) -> LogEntry:
    e = LogEntry(raw=line, message=line.strip()[:500])
    # 尝试提取时间戳
    if m := _ISO_TS.search(line):
        e.timestamp = _parse_iso(m.group(1))
        e.message = (line[:m.start()] + line[m.end():]).strip()[:500]
    elif m := _NGINX_TS.search(line):
        e.timestamp = _parse_nginx_ts(m.group(1))
    elif m := _SYSLOG_TS.search(line):
        e.timestamp = _parse_syslog_ts(m.group(1))
    elif m := _EPOCH_TS.search(line):
        e.timestamp = _parse_epoch(m.group(1))
    e.level = _infer_level(line)
    # 尝试提取 IP
    if ipm := re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line):
        e.source_ip = ipm.group(1)
    return e


# ------------------------------------------------------------------ #
# 公共入口
# ------------------------------------------------------------------ #

# 成员A统一CSV的字段名
_CSV_FIELDS = {"ts", "src_ip", "method", "path", "params", "status",
               "ua", "cookie", "hdrs", "label", "source", "raw_ref"}

# 中文表头（成员A统一CSV / _align.py 的 8 字段）→ 内部英文字段名
_CSV_ALIASES = {
    "时间": "ts", "源IP": "src_ip", "源ip": "src_ip",
    "方法": "method", "路径": "path", "参数": "params",
    "状态码": "status", "User-Agent": "ua", "useragent": "ua",
    "标签": "label", "来源": "source",
}


def parse_csv_row(row: dict[str, str]) -> LogEntry:
    """解析成员A统一CSV的一行（csv.DictReader 的 row）。

    兼容两种表头：
      - 英文 12 字段: ts, src_ip, method, path, params, status, ua,
        cookie, hdrs, label, source, raw_ref
      - 中文 8 字段（_align.py 输出）: 时间, 源IP, 方法, 路径, 参数,
        状态码, User-Agent, 标签
    """
    # 表头归一化：去 BOM/空白 + 中文别名映射到英文字段名
    norm: dict[str, str] = {}
    for k, v in row.items():
        key = str(k).lstrip("\ufeff").strip()
        norm[_CSV_ALIASES.get(key, key)] = v
    row = norm

    e = LogEntry()
    e.timestamp = _parse_iso(row.get("ts", "")) if row.get("ts") else ""
    e.source_ip = row.get("src_ip", "")
    e.method = row.get("method", "")
    e.path = row.get("path", "")
    e.message = f'{e.method} {e.path}'
    if row.get("params"):
        e.message += f' ?{row["params"]}'
    if row.get("status"):
        try:
            e.status_code = int(row["status"])
        except ValueError:
            pass
    # 级别：根据 label 推断
    label = row.get("label", "")
    if label and label != "normal":
        e.level = "WARN"
    else:
        e.level = "INFO"
    if e.status_code >= 500:
        e.level = "ERROR"
    elif e.status_code >= 400:
        e.level = "WARN"
    # extra 存放 A 的元数据字段
    if row.get("label"):
        e.extra["label"] = row["label"]
    if row.get("source"):
        e.extra["source"] = row["source"]
    if row.get("raw_ref"):
        e.extra["raw_ref"] = row["raw_ref"]
    if row.get("params"):
        e.extra["params"] = row["params"]
    if row.get("ua"):
        e.extra["ua"] = row["ua"]
    if row.get("cookie"):
        e.extra["cookie"] = row["cookie"]
    if row.get("hdrs"):
        e.extra["hdrs"] = row["hdrs"]
    # raw 重建
    e.raw = ",".join(str(row.get(f, "")) for f in _CSV_FIELDS)
    return e


def parse_line(line: str) -> LogEntry:
    """解析单行日志，自动选择最佳格式。"""
    line = line.rstrip("\n\r")
    if not line.strip():
        return LogEntry(raw=line)
    for fn in (_parse_json_line, _parse_syslog_line, _parse_nginx_line):
        result = fn(line)
        if result is not None:
            return result
    return _parse_generic_line(line)


def parse_lines(lines: list[str]) -> list[LogEntry]:
    return [parse_line(l) for l in lines if l.strip()]


# ------------------------------------------------------------------ #
# 原始 HTTP 报文 dump（CSIC 2010 风格）
# ------------------------------------------------------------------ #

def _http_block_to_entry(block: list[str]) -> LogEntry | None:
    """把一个 HTTP 请求块（请求行 + headers + 空行 + 正文）转成 LogEntry。"""
    m = _HTTP_REQ_LINE.match(block[0])
    if not m:
        return None
    method, url, version = m.groups()
    sp = urlsplit(url)
    e = LogEntry(
        method=method,
        path=sp.path or url,
        raw="\n".join(block)[:_RAW_MAX],
    )
    if sp.query:
        e.extra["params"] = sp.query
    if sp.scheme:
        e.extra["scheme"] = sp.scheme
    if sp.netloc:
        e.extra["host"] = sp.netloc
    e.extra["http_version"] = version

    # 头部段 → 空行 → 正文段
    body_start = None
    for i, line in enumerate(block[1:], 1):
        if not line.strip():
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip().lower().replace("-", "_")
            if key == "user_agent":
                e.extra["user_agent"] = v.strip()
            elif key in ("host", "referer", "cookie", "content_type", "content_length"):
                e.extra[key] = v.strip()
    if body_start is not None and body_start < len(block):
        body = "\n".join(block[body_start:]).strip()
        if body:
            e.extra["body"] = body[:_BODY_MAX]

    # message 含 query，保证 FTS 能命中参数内容
    e.message = f"{method} {e.path}"
    if sp.query:
        e.message += f" ?{sp.query}"
    e.message = e.message[:_MSG_MAX]
    e.level = _infer_level("\n".join(block))
    return e


def parse_http_dump(lines: Iterable[str], max_entries: int = 50000) -> list[LogEntry]:
    """解析原始 HTTP 报文 dump：一个请求横跨多行，以请求行为起点分块。

    分块锚点 = 下一行匹配 _HTTP_REQ_LINE（不依赖空行，因为正文可能含空行）。
    """
    entries: list[LogEntry] = []
    block: list[str] = []
    for raw in lines:
        line = raw.rstrip("\n\r")
        if _HTTP_REQ_LINE.match(line):
            if block:
                entry = _http_block_to_entry(block)
                if entry is not None:
                    entries.append(entry)
                    if len(entries) >= max_entries:
                        return entries
            block = [line]
        elif block:
            block.append(line)
    if block and len(entries) < max_entries:
        entry = _http_block_to_entry(block)
        if entry is not None:
            entries.append(entry)
    return entries