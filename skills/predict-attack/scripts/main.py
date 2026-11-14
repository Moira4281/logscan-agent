#!/usr/bin/env python3
"""predict-attack Skill 入口：ML 攻击分类预测。

真实模式：调用 predict.py（成员A 模型脚本）。
Mock 模式：用关键词匹配模拟模型输出（无 predict.py 时自动降级）。
"""
import json, os, sqlite3, subprocess, sys, tempfile

_MOCK_RULES = [
    ("sqli", 0.95, ["union select", "or 1=1", "or '1'='1", "drop table", "information_schema", "sleep("]),
    ("xss", 0.88, ["<script", "onerror=", "onload=", "javascript:", "alert("]),
    ("dirscan", 0.85, ["../", "..\\", "%2e%2e", "etc/passwd", "win.ini"]),
    ("rce", 0.82, [";", "|", "whoami", "cat ", "wget ", "curl ", "$(", "&&"]),
    ("log4j", 0.90, ["${jndi:", "log4j"]),
    ("cookie_injection", 0.87, ["cookie:", "set-cookie"]),
    ("log_forging", 0.85, ["\n", "\r", "%0a", "%0d"]),
]

def mock_predict(rows):
    results = []
    for i, row in enumerate(rows):
        text = (row.get("message", "") + " " + row.get("raw", "")).lower()
        label, confidence, evidence = "normal", 0.99, []
        for cat, conf, keywords in _MOCK_RULES:
            matched = [kw for kw in keywords if kw in text]
            if matched:
                label, confidence, evidence = cat, conf, matched[:3]
                break
        review = confidence < 0.60 or label == "fileinclusion"
        results.append({
            "index": i, "label": label, "confidence": round(confidence, 4),
            "review": review, "evidence": evidence, "keywords": evidence,
            "model_version": "mock-v1",
        })
    return results

def main():
    args = json.load(sys.stdin)
    db_path = os.getenv("LOGSCAN_DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    keyword = args.get("keyword", "")
    level = args.get("level", "")
    source_ip = args.get("source_ip", "")
    limit = args.get("limit", 50)

    where, params = [], []
    if keyword:
        where.append("id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)"); params.append(keyword)
    if level:
        where.append("level = ?"); params.append(level)
    if source_ip:
        where.append("source_ip = ?"); params.append(source_ip)
    sql = "SELECT * FROM logs"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " LIMIT ?"
    rows = conn.execute(sql, params + [limit]).fetchall()
    row_dicts = [{k: r[k] for k in r.keys()} for r in rows]

    if not row_dicts:
        print(json.dumps([], ensure_ascii=False))
        return

    predict_script = os.getenv("PREDICT_SCRIPT", "predict.py")
    if os.path.exists(predict_script):
        inputs = [{"ts": r.get("timestamp",""), "src_ip": r.get("source_ip",""),
                    "method": r.get("method",""), "path": r.get("path",""),
                    "status": str(r.get("status_code","") or ""), "ua": "", "cookie": "", "hdrs": "", "params": ""}
                   for r in row_dicts]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(inputs, f, ensure_ascii=False); in_path = f.name
        out_path = in_path.replace(".json", "_out.json")
        try:
            subprocess.run([sys.executable, predict_script, in_path, "-o", out_path], timeout=60)
            with open(out_path) as f:
                print(json.dumps(json.load(f), ensure_ascii=False))
        except Exception:
            print(json.dumps(mock_predict(row_dicts), ensure_ascii=False))
        finally:
            for p in (in_path, out_path):
                if os.path.exists(p): os.unlink(p)
    else:
        print(json.dumps(mock_predict(row_dicts), ensure_ascii=False))
    conn.close()

if __name__ == "__main__":
    main()