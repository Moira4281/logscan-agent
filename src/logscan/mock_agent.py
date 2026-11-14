"""Mock Agent：不调用 LLM，用预设规则模拟 ReAct 分析流程。

用于无网络环境下的端到端验证，以及 CI/CD 流水线中的冒烟测试。
模拟真实 Agent 的行为序列：get_stats → search_logs → get_timeline → 报告。
"""

from __future__ import annotations

import re
import time
from typing import Any

from .agent import AgentStep, AgentTrace, AnalysisResult
from .logs.store import LogStore
from .tools.base import ToolRegistry
from .tools.builtin import default_registry


# 攻击特征规则
_ATTACK_RULES: list[dict[str, Any]] = [
    {
        "id": "VULN-001",
        "type": "SQL 注入尝试",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "keywords": ["union select", "or 1=1", "or '1'='1", "drop table", "information_schema", "sleep("],
        "search": "sql injection OR union OR drop",
        "description": "检测到 SQL 注入攻击特征，攻击者尝试通过 UNION SELECT / OR 1=1 / DROP TABLE 等 payload 篡改数据库查询。",
        "recommendation": "使用参数化查询（PreparedStatement），部署 WAF 规则拦截 SQL 注入 payload，对 /products 接口增加输入校验。",
    },
    {
        "id": "VULN-002",
        "type": "XSS 跨站脚本攻击",
        "severity": "HIGH",
        "confidence": 0.85,
        "keywords": ["<script", "onerror=", "onload=", "javascript:", "alert("],
        "search": "script OR onerror OR javascript",
        "description": "检测到 XSS 攻击 payload，攻击者尝试注入恶意 JavaScript 脚本。",
        "recommendation": "对所有用户输入进行 HTML 实体编码，设置 Content-Security-Policy 头，启用浏览器 XSS 过滤器。",
    },
    {
        "id": "VULN-003",
        "type": "路径遍历攻击",
        "severity": "HIGH",
        "confidence": 0.9,
        "keywords": ["../", "..\\", "%2e%2e", "etc/passwd", "win.ini"],
        "search": "passwd OR ../ OR %2e%2e",
        "description": "检测到路径遍历攻击，攻击者尝试访问系统敏感文件（/etc/passwd、win.ini）。",
        "recommendation": "对文件路径做规范化处理，限制文件访问根目录，拒绝包含 ../ 的请求。",
    },
    {
        "id": "VULN-004",
        "type": "暴力破解攻击",
        "severity": "HIGH",
        "confidence": 0.88,
        "keywords": ["failed password", "401"],
        "search": "login 401",
        "description": "检测到暴力破解行为，同一 IP 短时间内多次登录失败后成功，疑似密码爆破。",
        "recommendation": "增加登录失败锁定策略（如 5 次失败锁定 30 分钟），启用双因素认证，设置登录速率限制。",
    },
    {
        "id": "VULN-005",
        "type": "目录扫描探测",
        "severity": "MEDIUM",
        "confidence": 0.8,
        "keywords": ["nmap", ".env", ".git", "wp-admin", "phpmyadmin"],
        "search": "404 nmap OR .env OR .git",
        "description": "检测到目录扫描行为，攻击者使用 nmap 探测敏感路径（.env、.git/config、wp-admin 等）。",
        "recommendation": "配置 WAF 拦截扫描器 User-Agent，禁止访问隐藏文件（.env、.git），返回统一的 404 页面。",
    },
    {
        "id": "VULN-006",
        "type": "SSRF 服务端请求伪造",
        "severity": "CRITICAL",
        "confidence": 0.92,
        "keywords": ["169.254.169.254", "localhost", "127.0.0.1", "internal"],
        "search": "169.254 OR localhost OR proxy",
        "description": "检测到 SSRF 攻击，攻击者通过代理接口访问云元数据端点和内部服务（Redis）。",
        "recommendation": "对出站请求做 URL 白名单校验，禁止访问 169.254.169.254 和内网地址段，移除 /api/proxy 的 url 参数。",
    },
    {
        "id": "VULN-007",
        "type": "权限提升",
        "severity": "CRITICAL",
        "confidence": 0.87,
        "keywords": ["sudo", "cat /etc/shadow", "wget", "shell.sh", "cron"],
        "search": "sudo OR shadow OR wget",
        "description": "检测到权限提升行为，攻击者在 SSH 登录后通过 sudo 执行高危命令（读取 shadow、下载并执行脚本）。",
        "recommendation": "限制 sudo 权限，禁止 root 远程登录，部署 HIDS 监控高危命令执行，审计 cron 任务。",
    },
    {
        "id": "VULN-008",
        "type": "文件包含攻击",
        "severity": "CRITICAL",
        "confidence": 0.9,
        "keywords": [
            "?file=", "?include=", "?page=", "?path=", "?doc=", "?template=",
            "php://", "data://", "file://", "php://filter", "php://input",
            "../", "..\\", "..%2f", "%2e%2e", "%252e",
            "/etc/passwd", "/etc/shadow", "win.ini", "boot.ini", "/proc/self",
        ],
        "search": "file= OR include= OR page= OR php:// OR data:// OR ../ OR etc/passwd",
        "description": (
            "检测到文件包含攻击特征。攻击者通过 ?file= / ?page= / ?include= 等参数"
            "或 PHP 伪协议（php://filter、php://input）尝试加载服务器端任意文件，"
            "可能读取 /etc/passwd 等敏感文件或执行远程代码。"
        ),
        "recommendation": (
            "对文件加载参数做白名单校验，禁用 php:// / data:// / file:// 伪协议，"
            "关闭 allow_url_include，对路径参数过滤 ../ 和 URL 编码变体。"
        ),
    },
]


def _build_evidence(rows: list, max_items: int = 5) -> list[str]:
    evidence = []
    for r in rows[:max_items]:
        row_dict = dict(r) if not isinstance(r, dict) else r
        ts = row_dict.get("timestamp", "") or "（无时间）"
        ip = row_dict.get("source_ip", "") or "（无源IP）"
        msg = row_dict.get("message", "") or row_dict.get("raw", "")
        evidence.append(f"[{ts}] {ip} | {msg[:120]}")
    return evidence


def _extract_ips(rows: list) -> list[str]:
    ips = set()
    for r in rows:
        row_dict = dict(r) if not isinstance(r, dict) else r
        ip = row_dict.get("source_ip", "")
        if ip:
            ips.add(ip)
    return sorted(ips)


def _extract_paths(rows: list) -> list[str]:
    paths = set()
    for r in rows:
        row_dict = dict(r) if not isinstance(r, dict) else r
        p = row_dict.get("path", "")
        if p:
            paths.add(p)
    return sorted(paths)


class MockAgent:
    """模拟 LLM Agent 的分析流程，使用预设规则。"""

    def __init__(self, store: LogStore, registry: ToolRegistry | None = None):
        self.store = store
        self.registry = registry or default_registry()

    def run(self, sources: list[str]) -> AnalysisResult:
        trace = AgentTrace()
        t0 = time.perf_counter()
        step = 0

        def _trace_tool(name: str, args: dict, result_text: str):
            nonlocal step
            step += 1
            trace.add(AgentStep(step=step, type="tool_call", tool_name=name, tool_args=args))
            trace.add(AgentStep(step=step, type="tool_result", tool_name=name,
                                tool_result=result_text[:300]))

        # Step 1: get_stats
        step += 1
        result = self.registry.call(self.store, "get_stats", {})
        _trace_tool("get_stats", {}, result.to_json()[:300])
        stats_data = result.data if result.ok else {}

        # Step 2: get_sample
        result = self.registry.call(self.store, "get_sample", {"limit": 5})
        _trace_tool("get_sample", {"limit": 5}, result.to_json()[:300])

        # Step 3: get_error_sample
        result = self.registry.call(self.store, "get_error_sample", {"limit": 20})
        _trace_tool("get_error_sample", {"limit": 20}, result.to_json()[:300])
        error_rows = result.data if result.ok else []

        # Step 4: 调用ML模型预测（联合研判）；predict.py 存在时用真实模型
        import os
        from .tools.predict import MockPredictTool, PredictTool

        _project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        _predict_script = os.getenv("PREDICT_SCRIPT", "")
        if not _predict_script:
            _candidates = [os.path.join(_project_root, "predict.py"), "predict.py"]
            _predict_script = next((p for p in _candidates if os.path.exists(p)), "")
        if _predict_script and os.path.exists(_predict_script):
            predict_tool = PredictTool(predict_script=_predict_script)
        else:
            predict_tool = MockPredictTool()
        model_predictions: list[dict[str, Any]] = []
        # 按 4xx/5xx 优先 + 正常行补足，覆盖足够的数据量
        result = predict_tool.execute(self.store, {"limit": 2000})
        _trace_tool("predict", {"limit": 2000}, result.to_json()[:300])
        if result.ok and result.data:
            model_predictions = result.data

        # 按攻击类型聚合模型预测
        model_by_type: dict[str, list[dict]] = {}
        for pred in model_predictions:
            if pred.get("label") and pred["label"] != "normal":
                model_by_type.setdefault(pred["label"], []).append(pred)

        # Step 5-N: 逐条规则搜索（规则关联研判）
        vulnerabilities: list[dict[str, Any]] = []
        all_attacker_ips: dict[str, list[str]] = {}

        for rule in _ATTACK_RULES:
            result = self.registry.call(self.store, "search_logs", {
                "keyword": rule["search"],
                "limit": 50,
            })
            _trace_tool("search_logs", {"keyword": rule["search"], "limit": 50},
                        result.to_json()[:300])

            if not result.ok or not result.data:
                continue

            rows = result.data
            # 二次验证：检查是否真的包含关键词
            matched = []
            for r in rows:
                text = (r.get("message", "") + " " + r.get("raw", "")).lower()
                if any(kw in text for kw in rule["keywords"]):
                    matched.append(r)

            if not matched:
                continue

            ips = _extract_ips(matched)
            paths = _extract_paths(matched)
            evidence = _build_evidence(matched)

            # 提取时间范围
            timestamps = [r.get("timestamp", "") for r in matched if r.get("timestamp")]
            start_time = min(timestamps) if timestamps else ""
            end_time = max(timestamps) if timestamps else ""

            # 复核状态：低置信度或证据不足时标记需复核
            if rule["confidence"] >= 0.85 and len(matched) >= 2:
                review_status = "CONFIRMED"
            elif rule["confidence"] >= 0.7:
                review_status = "NEEDS_REVIEW"
            else:
                review_status = "NEEDS_REVIEW"

            vuln = {
                "id": rule["id"],
                "type": rule["type"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "review_status": review_status,
                "start_time": start_time,
                "end_time": end_time,
                "description": rule["description"],
                "evidence": evidence,
                "source_ips": ips,
                "affected_paths": paths,
                "recommendation": rule["recommendation"],
                "detection_method": "规则关联",
            }

            # 联合模型证据：如果模型也检出了同类型攻击，叠加置信度
            model_label_map = {"SQL 注入尝试": "sqli", "XSS 跨站脚本攻击": "xss",
                               "路径遍历攻击": "dirscan", "SSRF 服务端请求伪造": "rce",
                               "权限提升": "rce"}
            model_label = model_label_map.get(rule["type"], "")
            if model_label and model_label in model_by_type:
                preds = model_by_type[model_label]
                avg_conf = sum(p.get("confidence", 0) for p in preds) / len(preds)
                vuln["model_score"] = {
                    "category": model_label,
                    "score": round(avg_conf, 4),
                    "model_version": preds[0].get("model_version", ""),
                    "matched_count": len(preds),
                }
                vuln["detection_method"] = "规则关联 + ML模型"
                vuln["confidence"] = min(1.0, (rule["confidence"] + avg_conf) / 2 + 0.05)

            vulnerabilities.append(vuln)

            for ip in ips:
                all_attacker_ips.setdefault(ip, []).append(rule["type"])

        # Step: 模型独立检出（规则未覆盖的攻击类型）
        rule_covered = {"sqli", "xss", "dirscan", "rce"}
        # 模型检出的"零日/疑似未知"类型作为逃逸口：
        # 规则层和分类层都没覆盖到的异常模式 → severity HIGH + NEEDS_REVIEW
        model_only_types = {
            "log4j": ("LOG4J 注入", "CRITICAL", "检测到 ${jndi:} 载荷，攻击者尝试利用 Log4Shell 漏洞。", "升级 Log4j 版本，移除 JNDI lookup 功能，部署 WAF 规则拦截 ${jndi:} payload。"),
            "cookie_injection": ("Cookie 注入", "HIGH", "检测到 Cookie 头注入攻击，攻击者尝试篡改会话信息。", "对 Cookie 值做严格校验，使用 HttpOnly 和 Secure 标志，启用 Cookie 签名。"),
            "log_forging": ("日志伪造", "MEDIUM", "检测到日志伪造攻击，攻击者尝试在日志中注入换行符伪造记录。", "对日志输入做换行符过滤，使用结构化日志格式。"),
            "unknown_suspicious": ("疑似零日/未知攻击", "HIGH", "模型判定为异常但不属于已知攻击类别，疑似零日漏洞或新型攻击模式。", "人工复核确认；如确认是新攻击则扩充签名库并重新训练分类器；保持对该行为的监控。"),
        }
        for label, preds in model_by_type.items():
            if label in rule_covered or label not in model_only_types:
                continue
            type_name, severity, desc, rec = model_only_types[label]
            avg_conf = sum(p.get("confidence", 0) for p in preds) / len(preds)
            # unknown_suspicious 强制 NEEDS_REVIEW（零日逃逸口，永远需要人工复核）
            review = "NEEDS_REVIEW" if label == "unknown_suspicious" else (
                "CONFIRMED" if avg_conf >= 0.85 else "NEEDS_REVIEW"
            )
            vuln = {
                "id": f"VULN-M{label[:3].upper()}",
                "type": type_name,
                "severity": severity,
                "confidence": round(avg_conf, 4),
                "review_status": review,
                "description": desc,
                "evidence": [f"模型检出 {len(preds)} 条，置信度 {avg_conf:.2f}，证据: {p.get('evidence', [])}" for p in preds[:3]],
                "source_ips": [],
                "affected_paths": [],
                "recommendation": rec,
                "detection_method": "ML模型独立检出",
                "model_score": {
                    "category": label,
                    "score": round(avg_conf, 4),
                    "model_version": preds[0].get("model_version", ""),
                    "matched_count": len(preds),
                },
            }
            vulnerabilities.append(vuln)

        # Step: 统计规则（行为异常，覆盖签名/分类漏检的零日）
        try:
            from .rules.statistical_rules import run_all_statistical_rules
            stat_findings = run_all_statistical_rules(self.store)
            for f in stat_findings:
                # 补齐 report schema 所需字段
                f.setdefault("review_status", "CONFIRMED")
                f.setdefault("source_ips", [])
                f.setdefault("affected_paths", [])
                f.setdefault("detection_method", "统计规则")
                vulnerabilities.append(f)
                # 统计规则检出的 IP 也进攻击链候选
                for ip in f.get("source_ips", []):
                    all_attacker_ips.setdefault(ip, []).append(f["type"])
            _trace_tool("run_all_statistical_rules", {},
                        f"命中 {len(stat_findings)} 条统计异常"[:300])
        except Exception as exc:  # noqa: BLE001 - 统计规则挂了不影响主流程
            _trace_tool("run_all_statistical_rules", {},
                        f"执行失败: {type(exc).__name__}: {exc}"[:300])

        # Step: 对高危 IP 做时间线分析
        attack_chains: list[dict[str, Any]] = []
        top_attacker_ips = sorted(all_attacker_ips.keys())[:3]
        for ip in top_attacker_ips:
            result = self.registry.call(self.store, "get_timeline", {
                "source_ip": ip, "limit": 50,
            })
            _trace_tool("get_timeline", {"source_ip": ip, "limit": 50},
                        result.to_json()[:300])
            if result.ok and result.data:
                timeline = result.data
                steps_desc = []
                for i, r in enumerate(timeline[:10], 1):
                    msg = r.get("message", "") or r.get("raw", "")
                    steps_desc.append(f"步骤{i}: [{r.get('timestamp','')}] {msg[:100]}")
                attack_chains.append({
                    "attacker_ip": ip,
                    "steps": steps_desc,
                    "assessment": f"该 IP 触发了: {', '.join(all_attacker_ips[ip])}",
                })

        # Step: 关联分析
        result = self.registry.call(self.store, "correlate_events", {
            "mode": "shared_paths", "min_ips": 2,
        })
        _trace_tool("correlate_events", {"mode": "shared_paths", "min_ips": 2},
                    result.to_json()[:300])

        # 生成报告
        by_severity: dict[str, int] = {}
        for v in vulnerabilities:
            by_severity[v["severity"]] = by_severity.get(v["severity"], 0) + 1

        level_dist = ", ".join(f"{b['level']}={b['count']}" for b in stats_data.get("by_level", []))
        top_ip_str = ", ".join(f"{i['ip']}({i['count']})" for i in stats_data.get("top_ips", [])[:5])
        tr = stats_data.get("time_range", {})
        time_range_str = f"{tr.get('min', '')} ~ {tr.get('max', '')}"

        report = {
            "summary": (
                f"分析 {stats_data.get('total', 0)} 条日志，发现 {len(vulnerabilities)} 个安全问题。"
                + ("涉及多种攻击手法，建议立即处置。" if len(vulnerabilities) > 2 else "")
            ),
            "log_overview": {
                "total_entries": stats_data.get("total", 0),
                "time_range": time_range_str,
                "key_observations": [
                    f"日志级别分布: {level_dist}",
                    f"Top 来源 IP: {top_ip_str}",
                    f"错误/告警条目: {len(error_rows)} 条",
                ],
            },
            "vulnerabilities": vulnerabilities,
            "attack_chains": attack_chains,
            "statistics": {
                "total_findings": len(vulnerabilities),
                "by_severity": by_severity,
            },
        }

        step += 1
        trace.add(AgentStep(step=step, type="final", content=f"生成报告: {len(vulnerabilities)} 个漏洞"))
        trace.total_elapsed_ms = int((time.perf_counter() - t0) * 1000)

        return AnalysisResult(
            report=report, trace=trace,
            raw_output="", success=True,
        )