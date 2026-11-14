#!/usr/bin/env python3
"""get-stats Skill 入口：日志统计概览。"""
import json, os, sqlite3, sys

def main():
    db_path = os.getenv("LOGSCAN_DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    ts = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM logs").fetchone()
    by_level = [{"level": r[0], "count": r[1]} for r in conn.execute("SELECT level, COUNT(*) FROM logs GROUP BY level ORDER BY COUNT(*) DESC")]
    by_status = [{"status": r[0], "count": r[1]} for r in conn.execute("SELECT status_code, COUNT(*) FROM logs WHERE status_code > 0 GROUP BY status_code ORDER BY COUNT(*) DESC")]
    top_ips = [{"ip": r[0], "count": r[1]} for r in conn.execute("SELECT source_ip, COUNT(*) FROM logs WHERE source_ip != '' GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10")]
    top_paths = [{"path": r[0], "count": r[1]} for r in conn.execute("SELECT path, COUNT(*) FROM logs WHERE path != '' GROUP BY path ORDER BY COUNT(*) DESC LIMIT 10")]

    result = {
        "total": total,
        "time_range": {"min": ts[0], "max": ts[1]},
        "by_level": by_level,
        "by_status": by_status,
        "top_ips": top_ips,
        "top_paths": top_paths,
    }
    print(json.dumps(result, ensure_ascii=False, default=str))
    conn.close()

if __name__ == "__main__":
    main()