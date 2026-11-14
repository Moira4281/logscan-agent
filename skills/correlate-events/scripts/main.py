#!/usr/bin/env python3
"""correlate-events Skill 入口：关联分析。"""
import json, os, sqlite3, sys

def main():
    args = json.load(sys.stdin)
    db_path = os.getenv("LOGSCAN_DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    mode = args.get("mode", "")

    if mode == "ip_paths":
        ip = args.get("source_ip", "")
        if not ip:
            print(json.dumps({"error": "ip_paths 模式需要 source_ip"}, ensure_ascii=False))
            return
        rows = conn.execute(
            "SELECT path, COUNT(*) as cnt FROM logs WHERE source_ip=? AND path!='' "
            "GROUP BY path ORDER BY cnt DESC LIMIT 50",
            (ip,),
        ).fetchall()
        result = [{"path": r[0], "count": r[1]} for r in rows]
    elif mode == "shared_paths":
        min_ips = args.get("min_ips", 3)
        rows = conn.execute(
            "SELECT path, COUNT(DISTINCT source_ip) as ip_cnt, COUNT(*) as total "
            "FROM logs WHERE path!='' AND source_ip!='' "
            "GROUP BY path HAVING ip_cnt >= ? ORDER BY ip_cnt DESC LIMIT 50",
            (min_ips,),
        ).fetchall()
        result = [{"path": r[0], "distinct_ips": r[1], "total_requests": r[2]} for r in rows]
    else:
        result = {"error": f"未知 mode: {mode}"}

    print(json.dumps(result, ensure_ascii=False, default=str))
    conn.close()

if __name__ == "__main__":
    main()