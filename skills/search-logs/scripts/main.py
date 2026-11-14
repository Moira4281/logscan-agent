#!/usr/bin/env python3
"""search-logs Skill 入口：FTS5 全文搜索 + 字段过滤。"""
import json, os, sqlite3, sys

def main():
    args = json.load(sys.stdin)
    db_path = os.getenv("LOGSCAN_DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    keyword = args.get("keyword", "")
    level = args.get("level", "")
    source_ip = args.get("source_ip", "")
    path = args.get("path", "")
    status_min = args.get("status_min", 0)
    status_max = args.get("status_max", 0)
    limit = args.get("limit", 50)
    offset = args.get("offset", 0)

    where, params = [], []
    if level:
        where.append("level = ?"); params.append(level)
    if source_ip:
        where.append("source_ip = ?"); params.append(source_ip)
    if path:
        where.append("path LIKE ?"); params.append(f"%{path}%")
    if status_min:
        where.append("status_code >= ?"); params.append(status_min)
    if status_max:
        where.append("status_code <= ?"); params.append(status_max)

    if keyword:
        sql = "SELECT * FROM logs WHERE id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)"
        if where:
            sql += " AND " + " AND ".join(where)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params = [keyword] + params + [limit, offset]
    else:
        sql = "SELECT * FROM logs"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params = params + [limit, offset]

    rows = conn.execute(sql, params).fetchall()
    result = [{k: r[k] for k in r.keys()} for r in rows]
    print(json.dumps(result, ensure_ascii=False, default=str))
    conn.close()

if __name__ == "__main__":
    main()