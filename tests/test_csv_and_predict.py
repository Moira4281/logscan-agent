"""CSV 解析与联合研判测试。"""

from __future__ import annotations

import pytest

from logscan.logs.parser import parse_csv_row
from logscan.logs.store import LogStore
from logscan.mock_agent import MockAgent
from logscan.tools.predict import MockPredictTool


# ------------------------------------------------------------------ #
# CSV 解析
# ------------------------------------------------------------------ #

class TestCsvParsing:
    def test_normal_row(self):
        row = {
            "ts": "2024-07-29T03:56:28+00:00", "src_ip": "192.168.1.1",
            "method": "GET", "path": "/index.html", "params": "",
            "status": "200", "ua": "Mozilla/5.0", "cookie": "", "hdrs": "",
            "label": "normal", "source": "xlsx", "raw_ref": "xlsx#L2",
        }
        e = parse_csv_row(row)
        assert e.source_ip == "192.168.1.1"
        assert e.method == "GET"
        assert e.path == "/index.html"
        assert e.status_code == 200
        assert e.level == "INFO"
        assert e.extra.get("label") == "normal"
        assert e.extra.get("raw_ref") == "xlsx#L2"

    def test_attack_row(self):
        row = {
            "ts": "", "src_ip": "10.0.0.1",
            "method": "GET", "path": "/products", "params": "id=1' OR '1'='1",
            "status": "500", "ua": "sqlmap", "cookie": "", "hdrs": "",
            "label": "sqli", "source": "atrdf", "raw_ref": "atrdf/test#5",
        }
        e = parse_csv_row(row)
        assert e.status_code == 500
        assert e.level == "ERROR"
        assert e.extra.get("label") == "sqli"
        assert e.extra.get("params") == "id=1' OR '1'='1"

    def test_missing_fields(self):
        e = parse_csv_row({})
        assert e.timestamp == ""
        assert e.source_ip == ""
        assert e.level == "INFO"

    def test_cookie_and_hdrs_preserved(self):
        row = {
            "ts": "", "src_ip": "", "method": "", "path": "/", "params": "",
            "status": "", "ua": "", "cookie": "session=abc", "hdrs": "Accept-Encoding: gzip",
            "label": "cookie_injection", "source": "atrdf", "raw_ref": "x#1",
        }
        e = parse_csv_row(row)
        assert e.extra.get("cookie") == "session=abc"
        assert e.extra.get("hdrs") == "Accept-Encoding: gzip"

    def test_chinese_headers_mapped(self):
        """兼容 _align.py 输出的中文 8 字段表头。"""
        row = {
            "时间": "2024-07-29T03:56:28+00:00", "源IP": "192.168.1.1",
            "方法": "POST", "路径": "/login", "参数": "user=admin",
            "状态码": "401", "User-Agent": "sqlmap/1.7", "标签": "attack",
        }
        e = parse_csv_row(row)
        assert e.timestamp.startswith("2024-07-29")
        assert e.source_ip == "192.168.1.1"
        assert e.method == "POST"
        assert e.path == "/login"
        assert e.status_code == 401
        assert e.extra["params"] == "user=admin"
        assert e.extra["ua"] == "sqlmap/1.7"
        assert e.extra["label"] == "attack"
        assert e.level == "WARN"

    def test_bom_and_whitespace_in_headers(self):
        """表头含 BOM / 尾随空格时仍能正确映射。"""
        row = {
            "\ufeff时间 ": "", "源IP ": "1.2.3.4", "方法": "GET",
            "路径": "/", "参数": "", "状态码": "", "User-Agent": "", "标签": "normal",
        }
        e = parse_csv_row(row)
        assert e.source_ip == "1.2.3.4"
        assert e.method == "GET"
        assert e.level == "INFO"


# ------------------------------------------------------------------ #
# MockPredictTool
# ------------------------------------------------------------------ #

class TestMockPredictTool:
    @pytest.fixture
    def store_with_attacks(self):
        s = LogStore(":memory:")
        from logscan.logs.parser import parse_line
        lines = [
            '10.0.0.66 - - [15/Jan/2024:10:01:02 +0000] "GET /products?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 120 "-" "sqlmap"',
            '10.0.0.23 - - [15/Jan/2024:10:02:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 450 "-" "Mozilla/5.0"',
            '192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        ]
        for i, line in enumerate(lines, 1):
            s.insert(parse_line(line), "test.log", i)
        s.conn.commit()
        return s

    def test_detects_sqli(self, store_with_attacks):
        tool = MockPredictTool()
        result = tool.execute(store_with_attacks, {"limit": 10})
        assert result.ok
        labels = [p["label"] for p in result.data]
        assert "sqli" in labels

    def test_detects_xss(self, store_with_attacks):
        tool = MockPredictTool()
        result = tool.execute(store_with_attacks, {"limit": 10})
        assert result.ok
        labels = [p["label"] for p in result.data]
        assert "xss" in labels

    def test_normal_is_normal(self, store_with_attacks):
        tool = MockPredictTool()
        result = tool.execute(store_with_attacks, {"limit": 10})
        assert result.ok
        normal_preds = [p for p in result.data if p["label"] == "normal"]
        assert len(normal_preds) >= 1

    def test_review_flag(self, store_with_attacks):
        tool = MockPredictTool()
        result = tool.execute(store_with_attacks, {"limit": 10})
        assert result.ok
        for p in result.data:
            if p["confidence"] < 0.60:
                assert p["review"] is True

    def test_empty_store(self):
        s = LogStore(":memory:")
        tool = MockPredictTool()
        result = tool.execute(s, {"limit": 10})
        assert result.ok
        assert result.data == []


# ------------------------------------------------------------------ #
# 联合研判（MockAgent + MockPredictTool）
# ------------------------------------------------------------------ #

class TestCombinedDetection:
    def test_model_and_rules_combined(self):
        s = LogStore(":memory:")
        from logscan.logs.parser import parse_line
        lines = [
            '10.0.0.66 - - [15/Jan/2024:10:01:02 +0000] "GET /products?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 120 "-" "sqlmap"',
            '10.0.0.66 - - [15/Jan/2024:10:01:05 +0000] "GET /products?id=1 UNION SELECT * FROM users-- HTTP/1.1" 500 98 "-" "sqlmap"',
            '10.0.0.23 - - [15/Jan/2024:10:02:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 450 "-" "Mozilla/5.0"',
            '192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        ]
        for i, line in enumerate(lines, 1):
            s.insert(parse_line(line), "test.log", i)
        s.conn.commit()

        agent = MockAgent(s)
        result = agent.run(["test.log"])
        assert result.success

        vulns = result.report["vulnerabilities"]
        types = [v["type"] for v in vulns]
        assert "SQL 注入尝试" in types
        assert "XSS 跨站脚本攻击" in types

        xss_vuln = next(v for v in vulns if "XSS" in v["type"])
        assert xss_vuln["detection_method"] == "规则关联 + ML模型"
        assert "model_score" in xss_vuln

    def test_bruteforce_only_rules(self):
        s = LogStore(":memory:")
        from logscan.logs.parser import parse_line
        lines = [
            '10.0.0.99 - - [15/Jan/2024:10:04:00 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"',
            '10.0.0.99 - - [15/Jan/2024:10:04:01 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"',
            '10.0.0.99 - - [15/Jan/2024:10:04:02 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"',
            '10.0.0.99 - - [15/Jan/2024:10:04:03 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"',
            '10.0.0.99 - - [15/Jan/2024:10:04:04 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"',
        ]
        for i, line in enumerate(lines, 1):
            s.insert(parse_line(line), "test.log", i)
        s.conn.commit()

        agent = MockAgent(s)
        result = agent.run(["test.log"])
        assert result.success

        vulns = result.report["vulnerabilities"]
        brute = next((v for v in vulns if "暴力" in v["type"]), None)
        assert brute is not None
        assert "规则" in brute["detection_method"]