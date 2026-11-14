#!/usr/bin/env python3
"""get-timeline Skill 入口：指定 IP 的活动时间线。"""
import json, os, sqlite3, sys

def main():
    args = json.load(sys.stdin)
    db_path = os.getenv("LOGSCAN_DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    ip = args.get("source_ip", "")
    limit = args.get("limit", 100)
    if not ip:
        print(json.dumps({"error": "source_ip 不能为空"}, ensure_ascii=False))
        return

    rows = conn.execute(
        "SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp ASC LIMIT ?",
        (ip, limit),
    ).fetchall()
    result = [{k: r[k] for k in r.keys()} for r in rows]
    print(json.dumps(result, ensure_ascii=False, default=str))
    conn.close()

if __name__ == "__main__":
    main()