"""SQLite 日志存储：解析后入库，支持高效检索。"""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from ..config import Settings
from .parser import LogEntry, parse_line


def _sanitize_fts(keyword: str) -> str:
    """转义 FTS5 关键词：保留布尔操作符，其余 token 用双引号包裹。"""
    parts = keyword.split()
    if not parts:
        return f'"{keyword}"'
    result = []
    for part in parts:
        if part.upper() in ("OR", "AND", "NOT", "NEAR"):
            result.append(part.upper())
        else:
            safe = part.replace('"', '""')
            result.append(f'"{safe}"')
    return " ".join(result)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT,
    level       TEXT,
    message     TEXT,
    source_ip   TEXT,
    user        TEXT,
    path        TEXT,
    method      TEXT,
    status_code INTEGER,
    extra       TEXT,
    raw         TEXT,
    source_file TEXT,
    line_no     INTEGER,
    numeric_value REAL,
    features    TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts     ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_level  ON logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_ip     ON logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_logs_path   ON logs(path);
CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(status_code);
CREATE INDEX IF NOT EXISTS idx_logs_numeric ON logs(numeric_value);
CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
    message, raw, content='logs', content_rowid='id'
);
"""

_INSERT = """
INSERT INTO logs (timestamp, level, message, source_ip, user, path,
                  method, status_code, extra, raw, source_file, line_no,
                  numeric_value, features)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


# A 的 4 维数值特征（anomaly_contract.md 冻结）
_FEATURE_FIELDS = ("status", "path_len", "param_len", "hdrs_len")


def _extract_features(entry: LogEntry) -> str:
    """从 LogEntry 提取 4 维数值特征，返回 JSON 字符串。

    status 缺失(0)存 null，feature_matrix 读出时转 NaN；
    长度类空串 = 0（真实长度为 0）。
    """
    feat = {
        "status": entry.status_code if entry.status_code > 0 else None,
        "path_len": len(entry.path),
        "param_len": len(entry.extra.get("params", "")),
        "hdrs_len": len(entry.extra.get("hdrs", "")),
    }
    return json.dumps(feat, ensure_ascii=False)


class LogStore:
    """日志存储与检索。"""

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """已有 DB 文件补列（CREATE TABLE IF NOT EXISTS 不会改已存在的表）。"""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(logs)").fetchall()}
        if "features" not in cols:
            self.conn.execute("ALTER TABLE logs ADD COLUMN features TEXT")
        if "numeric_value" not in cols:
            self.conn.execute("ALTER TABLE logs ADD COLUMN numeric_value REAL")

    # ---- 写入 ---- #

    def insert(self, entry: LogEntry, source_file: str = "", line_no: int = 0) -> int:
        # numeric_value：优先用 entry.extra["numeric_value"]（parser 显式标记），
        # 否则尝试 bytes / url_length / response_time 三个常见数字字段
        nv = entry.extra.get("numeric_value")
        if nv is None:
            for k in ("bytes", "url_length", "response_time", "size"):
                v = entry.extra.get(k)
                if isinstance(v, (int, float)) and v >= 0:
                    nv = float(v)
                    break
        # A 的 4 维数值特征（anomaly_contract.md）
        features_json = _extract_features(entry)
        cur = self.conn.execute(
            _INSERT,
            (
                entry.timestamp, entry.level, entry.message,
                entry.source_ip, entry.user, entry.path, entry.method,
                entry.status_code,
                json.dumps(entry.extra, ensure_ascii=False) if entry.extra else "",
                entry.raw, source_file, line_no, nv, features_json,
            ),
        )
        rid = cur.lastrowid
        self.conn.execute(
            "INSERT INTO logs_fts(rowid, message, raw) VALUES (?, ?, ?)",
            (rid, entry.message, entry.raw),
        )
        return rid

    def ingest_sources(self, sources: list[str], max_lines: int = 50000) -> int:
        """从日志源加载、解析、入库，返回入库条数。

        自动识别 .csv 文件（成员A统一格式），其他文件按行解析。
        """
        import csv as csv_mod
        from .loader import load_sources
        from .parser import parse_csv_row
        count = 0
        for src in sources:
            if src == "-":
                for source, line in load_sources([src], max_lines):
                    if not line.strip():
                        continue
                    count += 1
                    self.insert(parse_line(line), source, count)
                continue

            path = Path(src)
            if path.is_dir():
                for fp in sorted(path.rglob("*")):
                    if not fp.is_file() or fp.name.startswith("."):
                        continue
                    count += self._ingest_one(fp, max_lines, count)
            elif path.is_file():
                count += self._ingest_one(path, max_lines, count)
        self.conn.commit()
        return count

    def _ingest_one(self, path: Path, max_lines: int, offset: int) -> int:
        """加载单个文件，返回入库条数。"""
        import csv as csv_mod
        from .parser import parse_csv_row

        count = 0
        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv_mod.DictReader(f)
                for row in reader:
                    if count >= max_lines:
                        break
                    entry = parse_csv_row(row)
                    self.insert(entry, str(path), count + 1)
                    count += 1
        else:
            from .loader import _iter_file
            for i, line in enumerate(_iter_file(path, max_lines), 1):
                if not line.strip():
                    continue
                entry = parse_line(line)
                self.insert(entry, str(path), i)
                count += 1
        return count

    # ---- 查询 ---- #

    def total(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

    def search(
        self,
        keyword: str = "",
        level: str = "",
        source_ip: str = "",
        path: str = "",
        status_min: int = 0,
        status_max: int = 0,
        method: str = "",
        params: str = "",
        user_agent: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> list[sqlite3.Row]:
        """结构化字段过滤 + FTS 全文搜索。"""
        clauses: list[str] = []
        sql_params: list[object] = []

        if keyword:
            clauses.append("id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)")
            sql_params.append(_sanitize_fts(keyword))
        if level:
            clauses.append("level = ?")
            sql_params.append(level.upper())
        if source_ip:
            clauses.append("source_ip = ?")
            sql_params.append(source_ip)
        if path:
            clauses.append("path LIKE ?")
            sql_params.append(f"%{path}%")
        if status_min:
            clauses.append("status_code >= ?")
            sql_params.append(status_min)
        if status_max:
            clauses.append("status_code <= ?")
            sql_params.append(status_max)
        if method:
            clauses.append("method = ?")
            sql_params.append(method.upper())
        if params:
            clauses.append("extra LIKE ?")
            sql_params.append(f"%{params}%")
        if user_agent:
            clauses.append("extra LIKE ?")
            sql_params.append(f"%{user_agent}%")

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM logs{where} ORDER BY id DESC LIMIT ? OFFSET ?"
        sql_params.extend([limit, offset])
        return self.conn.execute(sql, sql_params).fetchall()

    def stats_by_level(self) -> list[tuple[str, int]]:
        return self.conn.execute(
            "SELECT level, COUNT(*) FROM logs GROUP BY level ORDER BY COUNT(*) DESC"
        ).fetchall()

    def numeric_series(self, field: str, limit: int = 5000) -> list[tuple[int, float]]:
        """返回 [(rowid, value), ...] 数值序列，供异常检测使用。

        内置字段（status_code / numeric_value）直接取列；
        其他字段（bytes / url_length / response_time 等）从 extra JSON 提取。
        跳过 NULL / 空 / 非数字。
        """
        if field == "status_code":
            rows = self.conn.execute(
                "SELECT id, status_code FROM logs WHERE status_code > 0 LIMIT ?", (limit,)
            ).fetchall()
            return [(r[0], float(r[1])) for r in rows]
        if field == "numeric_value":
            rows = self.conn.execute(
                "SELECT id, numeric_value FROM logs WHERE numeric_value IS NOT NULL LIMIT ?", (limit,)
            ).fetchall()
            return [(r[0], float(r[1])) for r in rows]
        # 其他字段从 extra JSON 提取
        rows = self.conn.execute(
            "SELECT id, extra FROM logs WHERE extra != '' LIMIT ?", (limit,)
        ).fetchall()
        result: list[tuple[int, float]] = []
        for r in rows:
            try:
                extra = json.loads(r[1]) if r[1] else {}
                val = extra.get(field)
                if val is not None:
                    result.append((r[0], float(val)))
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
        return result

    def feature_matrix(
        self,
        fields: list[str] | None = None,
        limit: int = 50000,
        fill_nan: bool = True,
    ) -> tuple[list[list[float]], list[int]]:
        """返回 (X, rowids) 供无监督异常检测使用。

        fields 默认 = A 的 4 维: ["status", "path_len", "param_len", "hdrs_len"]
        fill_nan=True 时用每列中位数填充 NaN（sklearn IsolationForest/LOF 不接受 NaN）。
        rowids[i] = 对应 logs 表的 id，供回查证据。
        """
        if fields is None:
            fields = list(_FEATURE_FIELDS)
        rows = self.conn.execute(
            "SELECT id, features FROM logs "
            "WHERE features IS NOT NULL AND features != '' LIMIT ?",
            (limit,),
        ).fetchall()
        X: list[list[float]] = []
        rowids: list[int] = []
        for r in rows:
            try:
                feat = json.loads(r[1])
            except (json.JSONDecodeError, TypeError):
                continue
            vec: list[float] = []
            for f in fields:
                v = feat.get(f)
                if v is None:
                    vec.append(float("nan"))
                else:
                    try:
                        vec.append(float(v))
                    except (ValueError, TypeError):
                        vec.append(float("nan"))
            X.append(vec)
            rowids.append(r[0])

        if fill_nan and X:
            import statistics as _stats
            n_cols = len(X[0])
            for col in range(n_cols):
                col_vals = [row[col] for row in X if not math.isnan(row[col])]
                if not col_vals:
                    continue
                median = _stats.median(col_vals)
                for row in X:
                    if math.isnan(row[col]):
                        row[col] = median
        return X, rowids

    def stats_by_status(self) -> list[tuple[int, int]]:
        return self.conn.execute(
            "SELECT status_code, COUNT(*) FROM logs WHERE status_code > 0 "
            "GROUP BY status_code ORDER BY status_code"
        ).fetchall()

    def top_ips(self, limit: int = 20) -> list[tuple[str, int]]:
        return self.conn.execute(
            "SELECT source_ip, COUNT(*) FROM logs WHERE source_ip != '' "
            "GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def top_paths(self, limit: int = 20) -> list[tuple[str, int]]:
        return self.conn.execute(
            "SELECT path, COUNT(*) FROM logs WHERE path != '' "
            "GROUP BY path ORDER BY COUNT(*) DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def timeline_for_ip(self, source_ip: str, limit: int = 100) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM logs WHERE source_ip = ? ORDER BY id ASC LIMIT ?",
            (source_ip, limit),
        ).fetchall()

    def time_range(self) -> tuple[str, str]:
        row = self.conn.execute(
            "SELECT MIN(timestamp), MAX(timestamp) FROM logs WHERE timestamp != ''"
        ).fetchone()
        return row[0] or "", row[1] or ""

    def sample(self, limit: int = 10) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM logs ORDER BY id ASC LIMIT ?", (limit,)
        ).fetchall()

    def error_sample(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM logs WHERE level IN ('ERROR','CRITICAL') "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def close(self) -> None:
        self.conn.close()