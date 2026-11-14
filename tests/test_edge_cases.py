"""异常场景测试：空文件、未知格式、时间缺失、无攻击记录、模型超时。

对应分工文档成员B第7步：检查空文件、未知格式、时间字段缺失、
模型超时、没有攻击记录等情形；给出清楚提示，不静默失败。
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from logscan.logs.parser import parse_line
from logscan.logs.store import LogStore
from logscan.mock_agent import MockAgent
from logscan.tools.builtin import default_registry


# ------------------------------------------------------------------ #
# 1. 空文件 / 空行
# ------------------------------------------------------------------ #

class TestEmptyInput:
    def test_empty_line(self):
        e = parse_line("")
        assert e.message == ""
        assert e.level == "INFO"

    def test_whitespace_only(self):
        e = parse_line("   \n\t  ")
        assert e.message.strip() == ""

    def test_store_empty(self):
        store = LogStore(":memory:")
        assert store.total() == 0
        assert store.time_range() == ("", "")
        assert store.error_sample() == []
        assert store.top_ips() == []

    def test_mock_agent_no_data(self):
        store = LogStore(":memory:")
        agent = MockAgent(store)
        result = agent.run(["empty"])
        assert result.success
        assert result.report["statistics"]["total_findings"] == 0
        assert result.report["vulnerabilities"] == []

    def test_search_empty_store(self):
        store = LogStore(":memory:")
        results = store.search(keyword="anything")
        assert results == []


# ------------------------------------------------------------------ #
# 2. 未知格式
# ------------------------------------------------------------------ #

class TestUnknownFormat:
    def test_garbage_line(self):
        e = parse_line("asdfghjkl 12345 !!! @#$%")
        assert e.raw == "asdfghjkl 12345 !!! @#$%"
        assert e.level == "INFO"

    def test_no_timestamp(self):
        e = parse_line("something happened but no timestamp here")
        assert e.timestamp == ""
        assert "something happened" in e.message

    def test_binary_like_content(self):
        e = parse_line("\x00\x01\x02 binary garbage \xff\xfe")
        assert e.raw != ""

    def test_partial_json(self):
        e = parse_line('{"timestamp": "2024-01-15", "level": "ERROR", "message":')
        assert e.timestamp != "" or e.message != ""

    def test_mixed_format_in_store(self):
        store = LogStore(":memory:")
        lines = [
            '{"timestamp": "2024-01-15T10:00:00Z", "level": "INFO", "message": "ok"}',
            "random garbage line without format",
            "192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"-\"",
            "<134>Jan 15 10:00:02 host app: normal message",
            "",
            "   ",
        ]
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
            store.insert(parse_line(line), "mixed.log", i)
        store.conn.commit()
        assert store.total() == 4  # 空行被跳过


# ------------------------------------------------------------------ #
# 3. 时间字段缺失
# ------------------------------------------------------------------ #

class TestMissingTimestamp:
    def test_no_timestamp_in_store(self):
        store = LogStore(":memory:")
        store.insert(parse_line("error without timestamp"), "test.log", 1)
        store.conn.commit()
        lo, hi = store.time_range()
        assert lo == "" and hi == ""

    def test_partial_timestamps(self):
        store = LogStore(":memory:")
        store.insert(parse_line("no time here"), "test.log", 1)
        store.insert(parse_line("2024-01-15T10:00:00Z has time"), "test.log", 2)
        store.insert(parse_line("also no time"), "test.log", 3)
        store.conn.commit()
        lo, hi = store.time_range()
        assert lo != "" and hi != ""

    def test_search_without_timestamp(self):
        store = LogStore(":memory:")
        store.insert(parse_line("error message no time"), "test.log", 1)
        store.conn.commit()
        results = store.search(keyword="error")
        assert len(results) == 1


# ------------------------------------------------------------------ #
# 4. 无攻击记录（全正常流量）
# ------------------------------------------------------------------ #

class TestNoAttacks:
    @pytest.fixture
    def clean_store(self):
        store = LogStore(":memory:")
        normal_lines = [
            '192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
            '192.168.1.1 - - [15/Jan/2024:10:00:02 +0000] "GET /about HTTP/1.1" 200 567 "-" "Mozilla/5.0"',
            '192.168.1.2 - - [15/Jan/2024:10:00:03 +0000] "GET /products HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
            '{"timestamp": "2024-01-15T10:00:04Z", "level": "INFO", "message": "user login success"}',
            '{"timestamp": "2024-01-15T10:00:05Z", "level": "INFO", "message": "health check passed"}',
        ]
        for i, line in enumerate(normal_lines, 1):
            store.insert(parse_line(line), "normal.log", i)
        store.conn.commit()
        return store

    def test_no_vulnerabilities_found(self, clean_store):
        agent = MockAgent(clean_store)
        result = agent.run(["normal.log"])
        assert result.success
        assert result.report["statistics"]["total_findings"] == 0
        assert result.report["vulnerabilities"] == []

    def test_stats_still_work(self, clean_store):
        agent = MockAgent(clean_store)
        result = agent.run(["normal.log"])
        overview = result.report["log_overview"]
        assert overview["total_entries"] == 5

    def test_no_attack_chains(self, clean_store):
        agent = MockAgent(clean_store)
        result = agent.run(["normal.log"])
        assert result.report["attack_chains"] == []


# ------------------------------------------------------------------ #
# 5. 模型超时 / LLM 调用失败
# ------------------------------------------------------------------ #

class TestLLMFailure:
    def test_agent_handles_connection_error(self):
        from logscan.agent import LogScanAgent, AnalysisResult
        from logscan.config import Settings

        settings = Settings(api_key="fake", base_url="http://localhost:1/v1", model="test")
        store = LogStore(":memory:")
        store.insert(parse_line("2024-01-15T10:00:00Z test message"), "test.log", 1)
        store.conn.commit()

        agent = LogScanAgent(settings, store)
        result = agent.run(["test.log"])
        assert not result.success
        assert "LLM 调用失败" in result.error or "Connection" in result.error

    def test_agent_handles_api_error(self):
        from logscan.agent import LogScanAgent
        from logscan.config import Settings

        settings = Settings(api_key="invalid-key", base_url="http://localhost:1/v1", model="test")
        store = LogStore(":memory:")

        agent = LogScanAgent(settings, store)
        result = agent.run(["test.log"])
        assert not result.success

    def test_mock_agent_never_fails_on_llm(self):
        store = LogStore(":memory:")
        store.insert(parse_line("test"), "test.log", 1)
        store.conn.commit()
        agent = MockAgent(store)
        result = agent.run(["test.log"])
        assert result.success


# ------------------------------------------------------------------ #
# 6. 工具异常容错
# ------------------------------------------------------------------ #

class TestToolErrorHandling:
    def test_invalid_fts_keyword(self):
        store = LogStore(":memory:")
        store.insert(parse_line("test message"), "test.log", 1)
        store.conn.commit()
        # 特殊字符不应导致崩溃
        results = store.search(keyword="..\\..\\test")
        assert isinstance(results, list)

    def test_nonexistent_ip_timeline(self):
        store = LogStore(":memory:")
        store.insert(parse_line("test"), "test.log", 1)
        store.conn.commit()
        timeline = store.timeline_for_ip("999.999.999.999")
        assert timeline == []

    def test_correlate_empty_store(self):
        store = LogStore(":memory:")
        reg = default_registry()
        result = reg.call(store, "correlate_events", {"mode": "shared_paths"})
        assert result.ok
        assert result.data == []