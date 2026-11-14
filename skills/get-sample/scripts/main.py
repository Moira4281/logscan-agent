#!/usr/bin/env python3
"""get-sample Skill 入口：日志样本。"""
import json, os, sqlite3, sys

def main():
    args = json.load(sys.stdin)
    db_path = os.getenv("LOGSCAN_DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    limit = args.get("limit", 10)
    rows = conn.execute(
        "SELECT * FROM logs ORDER BY timestamp ASC LIMIT ?",
        (limit,),
    ).fetchall()
    result = [{k: r[k] for k in r.keys()} for r in rows]
    print(json.dumps(result, ensure_ascii=False, default=str))
    conn.close()

if __name__ == "__main__":
    main()