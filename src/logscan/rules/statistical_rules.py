"""统计异常规则库 —— 基于统计指标的异常检测。

与签名规则（mock_agent._ATTACK_RULES，查"内容像不像攻击")互补：
签名查 payload 特征，统计查行为特征（频率/状态码/长度/时段）。

四条规则：
  1. rule_frequency_3sigma   单 IP 请求频率超过均值 + 3σ
  2. rule_status_burst       某状态码集中爆发（4xx=扫描，5xx=探测）
  3. rule_url_length_outlier URL 长度超过 IQR 1.5 倍
  4. rule_off_hours_access   凌晨 0–5 点高频访问

每条规则返回 list[dict]，格式与 _ATTACK_RULES 对齐，可直接合并进报告。
"""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any

from ..logs.store import LogStore


def rule_frequency_3sigma(
    store: LogStore,
    threshold_sigma: float = 2.0,
    min_total: int = 20,
) -> list[dict[str, Any]]:
    """单 IP 请求频率超过均值 + Nσ → 疑似扫描/爆破。

    统计每 IP 的请求次数，算均值与标准差，超过 mean + 2σ 的视为异常。
    安全运营中 2σ（覆盖 95% 以外）已值得调查，3σ 太严格。
    数据量不足（< min_total 条）或标准差为 0 时跳过。
    """
    rows = store.top_ips(limit=1000)
    if len(rows) < 5 or sum(r[1] for r in rows) < min_total:
        return []
    counts = [r[1] for r in rows]
    mean = statistics.mean(counts)
    stdev = statistics.stdev(counts) if len(counts) > 1 else 0.0
    if stdev == 0:
        return []
    threshold = mean + threshold_sigma * stdev
    flagged = [(ip, cnt) for ip, cnt in rows if cnt >= threshold]
    if not flagged:
        return []
    flagged.sort(key=lambda x: x[1], reverse=True)
    findings: list[dict[str, Any]] = []
    for ip, cnt in flagged[:5]:
        findings.append({
            "id": "STAT-001",
            "type": "高频访问异常（统计偏离）",
            "severity": "HIGH" if cnt > threshold * 1.5 else "MEDIUM",
            "confidence": min(0.95, 0.6 + (cnt - threshold) / max(threshold, 1) * 0.3),
            "source_ips": [ip],
            "description": (
                f"IP {ip} 共发起 {cnt} 次请求，超过均值({mean:.1f}) + "
                f"{threshold_sigma}σ({stdev:.1f})，阈值 {threshold:.1f}。"
                f"无明确签名命中但行为上疑似扫描/爆破。"
            ),
            "recommendation": "对该 IP 启用速率限制，复核是否需要封禁；检查其访问路径分布。",
            "evidence": [f"{ip} 共 {cnt} 次请求（均值 {mean:.1f}，阈值 {threshold:.1f}）"],
            "detection_method": "statistical_3sigma",
        })
    return findings


def rule_status_burst(
    store: LogStore,
    scan_ratio: float = 0.15,
    probe_ratio: float = 0.08,
    min_total: int = 50,
) -> list[dict[str, Any]]:
    """状态码集中爆发：4xx 占比 > scan_ratio=扫描嫌疑；5xx 占比 > probe_ratio=探测嫌疑。"""
    stats = store.stats_by_status()
    total = sum(r[1] for r in stats)
    if total < min_total:
        return []
    by_code = {r[0]: r[1] for r in stats}
    c4xx = sum(c for s, c in by_code.items() if 400 <= s < 500)
    c5xx = sum(c for s, c in by_code.items() if 500 <= s < 600)
    findings: list[dict[str, Any]] = []
    r4 = c4xx / total
    r5 = c5xx / total
    if r4 > scan_ratio:
        findings.append({
            "id": "STAT-002",
            "type": "4xx 状态码集中爆发（扫描嫌疑）",
            "severity": "MEDIUM",
            "confidence": min(0.9, 0.5 + r4 * 0.4),
            "description": (
                f"4xx 状态码共 {c4xx} 次，占总请求 {r4:.1%}（阈值 {scan_ratio:.0%}）。"
                f"大量 404/403 通常意味着目录扫描或资源枚举。"
            ),
            "recommendation": "检查 4xx 集中爆发的来源 IP，对扫描器 UA 拦截，404 页面不暴露路径信息。",
            "evidence": [f"4xx={c4xx}/{total} ({r4:.1%})"],
            "detection_method": "statistical_status_burst",
        })
    if r5 > probe_ratio:
        findings.append({
            "id": "STAT-003",
            "type": "5xx 状态码集中爆发（探测嫌疑）",
            "severity": "HIGH",
            "confidence": min(0.9, 0.55 + r5 * 0.35),
            "description": (
                f"5xx 状态码共 {c5xx} 次，占总请求 {r5:.1%}（阈值 {probe_ratio:.0%}）。"
                f"5xx 集中爆发可能是攻击者在探测应用漏洞（如构造畸形输入触发 500）。"
            ),
            "recommendation": "复盘 5xx 请求的 payload，修复触发异常的接口，部署异常监控告警。",
            "evidence": [f"5xx={c5xx}/{total} ({r5:.1%})"],
            "detection_method": "statistical_status_burst",
        })
    return findings


def rule_url_length_outlier(
    store: LogStore,
    iqr_multiplier: float = 1.5,
    min_total: int = 30,
) -> list[dict[str, Any]]:
    """URL 长度超过 Q3 + 1.5×IQR → 疑似注入 payload（正常 URL 不会太长）。"""
    rows = store.conn.execute(
        "SELECT id, source_ip, path FROM logs WHERE path != '' ORDER BY id LIMIT 5000"
    ).fetchall()
    if len(rows) < min_total:
        return []
    lengths = [len(r[2]) for r in rows]
    lengths.sort()
    n = len(lengths)
    q1 = lengths[n // 4]
    q3 = lengths[3 * n // 4]
    iqr = q3 - q1
    threshold = q3 + iqr_multiplier * iqr
    if threshold <= q3:
        return []
    outliers = [(r[0], r[1], r[2], len(r[2])) for r in rows if len(r[2]) > threshold]
    if not outliers:
        return []
    outliers.sort(key=lambda x: x[3], reverse=True)
    findings: list[dict[str, Any]] = []
    ips = list({o[1] for o in outliers if o[1]})[:5]
    findings.append({
        "id": "STAT-004",
        "type": "URL 长度离群（疑似注入 payload）",
        "severity": "MEDIUM",
        "confidence": 0.7,
        "source_ips": ips,
        "description": (
            f"共 {len(outliers)} 条 URL 长度超过 Q3({q3}) + {iqr_multiplier}×IQR({iqr}) "
            f"= {threshold:.0f} 字符。正常请求 URL 不会太长，超长通常意味着 "
            f"SQL 注入 / XSS / 路径遍历 payload。"
        ),
        "recommendation": "逐条复核超长 URL 的 query 参数，部署 WAF 对超长请求拦截。",
        "evidence": [f"row#{o[0]} ip={o[1] or '(无)'} len={o[3]} path={o[2][:80]}" for o in outliers[:5]],
        "detection_method": "statistical_iqr",
    })
    return findings


def rule_off_hours_access(
    store: LogStore,
    min_count: int = 10,
) -> list[dict[str, Any]]:
    """凌晨 0–5 点高频访问 → 可疑时段（正常用户不会凌晨大量请求）。"""
    rows = store.conn.execute(
        "SELECT source_ip, COUNT(*) as cnt FROM logs "
        "WHERE source_ip != '' AND timestamp != '' "
        "GROUP BY source_ip HAVING cnt >= ? "
        "ORDER BY cnt DESC LIMIT 50",
        (min_count,),
    ).fetchall()
    if not rows:
        return []
    flagged: list[tuple[str, int]] = []
    for ip, cnt in rows:
        sub = store.conn.execute(
            "SELECT COUNT(*) FROM logs WHERE source_ip = ? "
            "AND timestamp != ''",
            (ip,),
        ).fetchone()[0]
        if sub <= 0:
            continue
        off_rows = store.conn.execute(
            "SELECT COUNT(*) FROM logs WHERE source_ip = ? "
            "AND timestamp != '' "
            "AND (substr(timestamp, 12, 2) BETWEEN '00' AND '04' "
            "     OR substr(timestamp, 12, 2) = '00')",
            (ip,),
        ).fetchone()[0]
        if off_rows >= min_count:
            flagged.append((ip, off_rows))
    if not flagged:
        return []
    findings: list[dict[str, Any]] = []
    for ip, cnt in flagged[:5]:
        findings.append({
            "id": "STAT-005",
            "type": "凌晨时段高频访问（行为异常）",
            "severity": "MEDIUM",
            "confidence": 0.65,
            "source_ips": [ip],
            "description": (
                f"IP {ip} 在凌晨 0–5 点发起 {cnt} 次请求（阈值 {min_count}）。"
                f"正常用户极少在该时段高频访问，疑似自动化扫描或持久化 C2 心跳。"
            ),
            "recommendation": "复核该 IP 的请求路径与 UA，若确认无业务需求则加入夜间封禁策略。",
            "evidence": [f"{ip} 凌晨时段 {cnt} 次请求"],
            "detection_method": "statistical_off_hours",
        })
    return findings


# 登录类端点关键词（不区分大小写）
_LOGIN_PATHS = ("login", "wp-login", "admin", "signin", "auth")


def _parse_ts(ts: str) -> datetime | None:
    """解析 ISO8601 / 'YYYY-MM-DD HH:MM:SS' 时间戳。"""
    try:
        return datetime.fromisoformat(ts.replace(" ", "T"))
    except Exception:
        return None


def rule_bruteforce_session(
    store: LogStore,
    min_failures: int = 5,
    window_sec: int = 60,
) -> list[dict[str, Any]]:
    """同一 src_ip + 登录类端点 + 连续 4xx + 窗口 ≤60 秒 → 暴力破解。

    v1 分类器对 bruteforce 的 F1=0（单条请求与正常登录无法区分），
    此规则查"时序关系"——同一 IP 短时间内多次登录失败。
    """
    rows = store.conn.execute(
        "SELECT id, timestamp, source_ip, path, status_code, method "
        "FROM logs WHERE source_ip != '' AND timestamp != '' "
        "AND status_code IN (401, 403) "
        "ORDER BY source_ip, timestamp"
    ).fetchall()
    # 按 IP 分组，只保留登录类端点
    by_ip: dict[str, list] = {}
    for r in rows:
        p = (r["path"] or "").lower()
        if not any(lp in p for lp in _LOGIN_PATHS):
            continue
        by_ip.setdefault(r["source_ip"], []).append(r)
    findings: list[dict[str, Any]] = []
    for ip, seq in by_ip.items():
        if len(seq) < min_failures:
            continue
        # 滑动窗口：找连续 min_failures 条 4xx 且首尾时间差 ≤ window_sec
        hit_start = -1
        hit_end = -1
        for i in range(len(seq) - min_failures + 1):
            window = seq[i:i + min_failures]
            t_first = _parse_ts(window[0]["timestamp"])
            t_last = _parse_ts(window[-1]["timestamp"])
            if t_first is None or t_last is None:
                continue
            delta = (t_last - t_first).total_seconds()
            if 0 <= delta <= window_sec:
                hit_start = i
                hit_end = i + min_failures - 1
                break
        if hit_start < 0:
            continue
        # 统计该 IP 全部 login 4xx 次数和命中窗口的时间跨度
        total_fail = len(seq)
        wt0 = _parse_ts(seq[hit_start]["timestamp"])
        wt1 = _parse_ts(seq[hit_end]["timestamp"])
        win_span = f"{(wt1 - wt0).total_seconds():.0f}秒" if wt0 and wt1 else "未知"
        paths_hit = list({seq[j]["path"] for j in range(hit_start, hit_end + 1)})
        findings.append({
            "id": "STAT-006",
            "type": "暴力破解（会话级行为规则）",
            "severity": "HIGH",
            "confidence": 0.9,
            "source_ips": [ip],
            "description": (
                f"IP {ip} 在登录端点（{', '.join(paths_hit[:3])}）"
                f"连续 {total_fail} 次 4xx 失败"
                f"（命中窗口 {win_span}，阈值 ≤{window_sec}秒内 ≥{min_failures} 次）。"
                f"单条请求与正常登录无法区分，但时序行为模式明确指向暴力破解。"
            ),
            "recommendation": (
                "增加登录失败锁定策略（如 5 次失败锁定 30 分钟），"
                "启用双因素认证，设置登录速率限制，监控该 IP 后续行为。"
            ),
            "evidence": [
                f"{ip} 在 {paths_hit[0]} 上连续 {min_failures} 次 4xx"
                f"（窗口内首条 #{seq[hit_start]['id']}，末条 #{seq[hit_end]['id']}）"
            ],
            "detection_method": "session_bruteforce",
        })
    return findings


def run_all_statistical_rules(store: LogStore) -> list[dict[str, Any]]:
    """运行全部统计规则，合并返回异常列表。"""
    findings: list[dict[str, Any]] = []
    for fn in (
        rule_frequency_3sigma,
        rule_status_burst,
        rule_url_length_outlier,
        rule_off_hours_access,
        rule_bruteforce_session,
    ):
        try:
            findings.extend(fn(store))
        except Exception as exc:  # noqa: BLE001
            findings.append({
                "id": "STAT-ERR",
                "type": f"统计规则 {fn.__name__} 执行失败",
                "severity": "INFO",
                "confidence": 0.0,
                "description": f"{type(exc).__name__}: {exc}",
                "recommendation": "检查数据是否含所需字段（timestamp/source_ip/path）。",
            })
    return findings
