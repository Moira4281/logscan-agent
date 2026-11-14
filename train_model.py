# -*- coding: utf-8 -*-
"""
train_model.py —— 用 TF-IDF + 逻辑回归训练日志攻击分类基线模型

输入: logs_unified.csv（clean_logs.py 生成）
输出: model/model.pkl      训练好的模型（用全量数据重训）
      model/metrics.txt    评估报告（Precision/Recall/F1/混淆矩阵）
      model/errors.csv     误报/漏报样例（可回查 raw_ref）

切分方式: StratifiedGroupKFold(5) 按 source|path 分组 + 按标签分层。
         手动跑 5 折，每个样本都在"它当测试"的那一折里被预测一次，
         这样每个类别都能算指标；同时分组保证同一端点不跨训练/测试。

用法: python -u train_model.py
"""

import os
import csv
import time

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import classification_report, confusion_matrix

ROOT = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(ROOT, "logs_unified.csv")
MDIR = os.path.join(ROOT, "model")
os.makedirs(MDIR, exist_ok=True)

N_SPLIT = 5           # 交叉验证折数
SHOW_BAD = 20         # 每种错分组合最多保留多少条样例


def to_text(r):
    """把一条日志拼成文本特征。"""
    return " ".join([r["method"], r["path"], r["params"],
                     r["cookie"], r["hdrs"], r["ua"]]).lower()


def make_pipe():
    """TF-IDF(字符 2-4 gram) + 逻辑回归。"""
    return Pipeline([
        ("tf", TfidfVectorizer(
            analyzer="char_wb", ngram_range=(2, 4),
            min_df=5, max_features=100000, sublinear_tf=True)),
        ("lr", LogisticRegression(
            max_iter=1000, class_weight="balanced")),
    ])


def main():
    print("=" * 60)
    print("train_model.py 开始", flush=True)
    if not os.path.exists(CSV):
        print("找不到", CSV, "请先运行 clean_logs.py")
        return

    # ---------- 读数据 ----------
    X, y, gs, ref = [], [], [], []
    with open(CSV, "r", encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            X.append(to_text(r))
            y.append(r["label"])
            # 分组键: 来源 + 路径（路径为空就用 raw_ref，避免整类挤在一组）
            gs.append(r["source"] + "|" + (r["path"] or r["raw_ref"]))
            ref.append(r["raw_ref"])
    n = len(X)
    print("样本数:", n, flush=True)
    cnt = {}
    for v in y:
        cnt[v] = cnt.get(v, 0) + 1
    print("类别分布:", dict(sorted(cnt.items(), key=lambda z: -z[1])), flush=True)

    # ---------- 5 折交叉验证预测 ----------
    labs = sorted(set(y))
    sgkf = StratifiedGroupKFold(n_splits=N_SPLIT, shuffle=True, random_state=42)
    yp = [""] * n
    prob = [0.0] * n
    t0 = time.time()
    for f, (tr, te) in enumerate(sgkf.split(X, y, gs), start=1):
        m = make_pipe()
        m.fit([X[i] for i in tr], [y[i] for i in tr])
        Xte = [X[i] for i in te]
        pr = m.predict(Xte)
        pb = m.predict_proba(Xte)
        cls = list(m.classes_)
        for j, i in enumerate(te):
            yp[i] = pr[j]
            prob[i] = pb[j][cls.index(pr[j])]
        acc_f = sum(1 for j, i in enumerate(te) if pr[j] == y[i]) / len(te)
        print("  第 %d/%d 折完成: 训练=%d 测试=%d 准确率=%.4f  (累计 %.0f 秒)"
              % (f, N_SPLIT, len(tr), len(te), acc_f, time.time() - t0), flush=True)

    # ---------- 评估 ----------
    rep = classification_report(y, yp, labels=labs, digits=4, zero_division=0)
    cm = confusion_matrix(y, yp, labels=labs)
    acc = sum(1 for a, b in zip(y, yp) if a == b) / n

    lines = []
    lines.append("训练日志攻击分类基线 - 评估报告")
    lines.append("=" * 60)
    lines.append("模型: TF-IDF(char_wb 2-4gram) + 逻辑回归(class_weight=balanced)")
    lines.append("切分: StratifiedGroupKFold(%d)，按 source|path 分组防泄漏" % N_SPLIT)
    lines.append("评估: 5 折折外预测（每个样本只被没见过它的模型预测一次）")
    lines.append("样本总数: %d" % n)
    lines.append("整体准确率: %.4f" % acc)
    lines.append("")
    lines.append("分类报告:")
    lines.append(rep)
    lines.append("混淆矩阵 (行=真实, 列=预测):")
    lines.append("标签顺序: " + ", ".join(labs))
    for i, lab in enumerate(labs):
        lines.append("%-18s %s" % (lab, " ".join("%6d" % v for v in cm[i])))
    txt = "\n".join(lines)
    print(txt, flush=True)

    with open(os.path.join(MDIR, "metrics.txt"), "w", encoding="utf-8") as f:
        f.write(txt + "\n")

    # ---------- 误报/漏报样例 ----------
    grp = {}
    badn = 0
    for i in range(n):
        if yp[i] != y[i]:
            badn += 1
            grp.setdefault((y[i], yp[i]), []).append((prob[i], ref[i], X[i]))
    with open(os.path.join(MDIR, "errors.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["真实标签", "预测标签", "置信度", "raw_ref", "文本特征"])
        for (t, p), rs in sorted(grp.items(), key=lambda z: -len(z[1])):
            rs.sort(key=lambda z: -z[0])
            for pr, rf, s in rs[:SHOW_BAD]:
                w.writerow([t, p, "%.3f" % pr, rf, s[:300]])
    print("-" * 60, flush=True)
    print("错分总数: %d / %d  (错误率 %.4f)" % (badn, n, badn / n), flush=True)
    print("错分最多的组合:", flush=True)
    for (t, p), rs in sorted(grp.items(), key=lambda z: -len(z[1]))[:8]:
        print("   %-16s -> %-16s %d 条" % (t, p, len(rs)), flush=True)

    # ---------- 全量重训并保存 ----------
    print("-" * 60, flush=True)
    print("用全量数据重训并保存模型 ...", flush=True)
    pipe = make_pipe()
    pipe.fit(X, y)
    mpath = os.path.join(MDIR, "model.pkl")
    joblib.dump(pipe, mpath)
    print("模型:", mpath, flush=True)
    print("报告: %s" % os.path.join(MDIR, "metrics.txt"), flush=True)
    print("错例: %s" % os.path.join(MDIR, "errors.csv"), flush=True)
    print("总耗时 %.0f 秒" % (time.time() - t0), flush=True)
    print("完成", flush=True)


if __name__ == "__main__":
    main()