# -*- coding: utf-8 -*-
"""
predict.py —— 日志攻击分类预测接口（给成员 B 的 Agent 调用）

用法:
  python predict.py input.json           结果打印到屏幕
  python predict.py input.json -o out.json
  python predict.py -                    从 stdin 读
  python predict.py --samples            从 logs_unified.csv 抽样例生成 samples/

输入: JSON 数组，每个元素是一条规范化日志。字段可少给，缺的用空串:
      ts, src_ip, method, path, params, status, ua, cookie, hdrs
输出: JSON 数组，每个元素:
      index, raw_ref, label, confidence, review, reason, evidence, top3, model_version

设计原则（对应分工文档要求）:
  1. 输出只是"研判证据之一"，不直接定性入侵。
  2. 缺字段 / 低置信度 / 模型在该类上不可靠 时，review=true，交给人工复核，不硬判。
  3. 每条结论附 evidence（模型实际用到的字符串片段），可回指原始日志。
"""

import os
import sys
import csv
import json
import argparse
import datetime

import joblib

ROOT = os.path.dirname(os.path.abspath(__file__))
MDIR = os.path.join(ROOT, "model")
MODEL = os.path.join(MDIR, "model.pkl")
CSV = os.path.join(ROOT, "logs_unified.csv")
SDIR = os.path.join(ROOT, "samples")

# 参与判定的文本字段（与 train_model.py 保持一致）
TEXT_FIELDS = ["method", "path", "params", "cookie", "hdrs", "ua"]
# 输入需要的字段（label/source 是元数据，不需要 B 传）
IN_FIELDS = ["ts", "src_ip", "method", "path", "params", "status", "ua", "cookie", "hdrs"]

CONF_TH = 0.60              # 置信度低于此值 → 待复核
WEAK = {"fileinclusion"}    # metrics.txt 里 F1 很低的类，命中也要复核
MODEL_VERSION = "v1"

# 可读的安全特征关键词（给 Agent 写报告用；只做提示，不单独定性）
KEYWORDS = [
    "union", "select", " from ", "' or", "1=1", "sleep(", "benchmark(",
    "<script", "javascript:", "onerror", "alert(", "confirm(",
    "../", "..%2f", "%2e%2e", "/etc/passwd", "win.ini", "boot.ini",
    "${jndi", "jndi:ldap", "ldap://", "rmi://",
    "cmd=", "exec(", "system(", "passthru", "shell_exec",
    "php://", "data://", "base64_decode",
    "cookielogin", "%0a", "%0d", "wp-login",
]


# ---------------------------------------------------------------- 特征
def to_text(r):
    return " ".join([str(r.get(f) or "") for f in TEXT_FIELDS]).lower()


def load_model():
    if not os.path.exists(MODEL):
        print("找不到模型 %s，请先运行 train_model.py" % MODEL)
        sys.exit(1)
    pipe = joblib.load(MODEL)
    return pipe


# ---------------------------------------------------------------- 预测
def predict_records(pipe, recs):
    tf = pipe.named_steps["tf"]
    lr = pipe.named_steps["lr"]
    cls = [str(c) for c in lr.classes_]

    texts = [to_text(r) for r in recs]
    P = pipe.predict_proba(texts)
    X = tf.transform(texts)                 # 整批转一次，别每条单独转
    names = tf.get_feature_names_out()

    out = []
    for i, r in enumerate(recs):
        p = P[i]
        j = int(p.argmax())
        lab = cls[j]
        conf = float(p[j])

        # 证据: 该条文本里对预测类别贡献最大的字符片段
        row = X[i].tocoo()
        coef = lr.coef_[j]
        sc = [(row.data[k] * coef[row.col[k]], str(names[row.col[k]])) for k in range(len(row.data))]
        ev = [s for v, s in sorted(sc, reverse=True) if v > 0][:8]

        top3 = [[c, round(float(v), 4)]
                for c, v in sorted(zip(cls, p.tolist()), key=lambda z: -z[1])[:3]]

        why = []
        if not any(str(r.get(f) or "").strip() for f in TEXT_FIELDS):
            why.append("缺字段: 这条日志没有任何可用于判定的请求内容")
        if conf < CONF_TH:
            why.append("低置信度 %.2f < %.2f" % (conf, CONF_TH))
        if lab in WEAK:
            why.append("模型在该类上不可靠(F1 低)，需人工确认")
        if lab == "bruteforce":
            why.append("暴力破解需结合同 IP 会话规则，不能只看单条")

        out.append({
            "index": i,
            "raw_ref": str(r.get("raw_ref") or ""),
            "label": lab,
            "confidence": round(conf, 4),
            "review": bool(why),
            "reason": "; ".join(why),
            "evidence": ev,
            "keywords": [k.strip() for k in KEYWORDS if k in texts[i]],
            "top3": top3,
            "model_version": MODEL_VERSION,
        })
    return out


# ---------------------------------------------------------------- 生成样例
def pick_rows(pipe):
    """从 logs_unified.csv 里挑几条有代表性的日志。"""
    want = ["normal", "sqli", "xss", "cookie_injection", "rce"]
    got = {}
    other = []

    def to_in(r):
        return {f: r.get(f, "") for f in IN_FIELDS}

    with open(CSV, "r", encoding="utf-8-sig", newline="") as f:
        for n, r in enumerate(csv.DictReader(f)):
            lab = r.get("label")
            if lab in want and lab not in got:
                got[lab] = (to_in(r), r.get("raw_ref"))
            # 顺手收集一批用于找"低置信度"样例
            if n % 500 == 0:
                other.append((to_in(r), r.get("raw_ref"), lab))

    recs, exp = [], []
    for lab in want:
        if lab in got:
            recs.append(got[lab][0])
            exp.append((lab, got[lab][1]))

    # 找一条模型最没把握的，用来演示 review=true
    res = predict_records(pipe, [x[0] for x in other])
    k = min(range(len(res)), key=lambda i: res[i]["confidence"])
    recs.append(other[k][0])
    exp.append(("低置信度样例(真实=%s)" % other[k][2], other[k][1]))

    # 一条缺字段的
    recs.append({f: "" for f in IN_FIELDS})
    exp.append(("缺字段样例", ""))
    return recs, exp


def make_samples(pipe):
    os.makedirs(SDIR, exist_ok=True)
    recs, exp = pick_rows(pipe)
    res = predict_records(pipe, recs)

    with open(os.path.join(SDIR, "input.json"), "w", encoding="utf-8") as f:
        json.dump(recs, f, ensure_ascii=False, indent=2)

    pairs = []
    for i, r in enumerate(res):
        pairs.append({"expect": exp[i][0], "raw_ref": exp[i][1], "input": recs[i], "output": r})
    with open(os.path.join(SDIR, "io.json"), "w", encoding="utf-8") as f:
        json.dump(pairs, f, ensure_ascii=False, indent=2)

    print("已生成 %d 条样例:" % len(recs))
    for i, r in enumerate(res):
        print("  [%d] %-18s conf=%.3f review=%-5s %s"
              % (i, r["label"], r["confidence"], r["review"], r["reason"][:40]))
    print("输入: %s" % os.path.join(SDIR, "input.json"))
    print("配对: %s" % os.path.join(SDIR, "io.json"))


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser(description="日志攻击分类预测接口")
    ap.add_argument("input", nargs="?", help="输入 JSON 文件，或用 - 读 stdin")
    ap.add_argument("-o", "--out", help="结果写到文件（默认打印）")
    ap.add_argument("--samples", action="store_true", help="生成 samples/ 样例")
    a = ap.parse_args()

    pipe = load_model()
    print("# model=%s version=%s loaded=%s"
          % (MODEL, MODEL_VERSION,
             datetime.datetime.fromtimestamp(os.path.getmtime(MODEL)).strftime("%Y-%m-%d %H:%M")),
          file=sys.stderr)

    if a.samples:
        make_samples(pipe)
        return

    if not a.input:
        ap.print_help()
        return

    if a.input == "-":
        recs = json.load(sys.stdin)
    else:
        with open(a.input, "r", encoding="utf-8") as f:
            recs = json.load(f)

    res = predict_records(pipe, recs)
    s = json.dumps(res, ensure_ascii=False, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(s)
        print("已写入 %s（%d 条）" % (a.out, len(res)), file=sys.stderr)
    else:
        print(s)


if __name__ == "__main__":
    main()