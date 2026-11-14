"""Agent 工具测试。"""

import pytest

from logscan.logs.store import LogStore
from logscan.logs.parser import parse_line
from logscan.tools.builtin import default_registry


@pytest.fixture
def store_with_data():
    s = LogStore(":memory:")
    lines = [
        '10.0.0.66 - - [15/Jan/2024:10:01:02 +0000] "GET /products?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 120 "-" "sqlmap"',
        '10.0.0.99 - - [15/Jan/2024:10:04:00 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"',
        '10.0.0.99 - - [15/Jan/2024:10:04:01 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"',
        '192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.12 - - [15/Jan/2024:10:05:01 +0000] "GET /.env HTTP/1.1" 404 10 "-" "nmap"',
        '10.0.0.12 - - [15/Jan/2024:10:05:02 +0000] "GET /.git/config HTTP/1.1" 404 10 "-" "nmap"',
        '{"timestamp": "2024-01-15T10:01:03Z", "level": "ERROR", "message": "SQL injection detected", "source_ip": "10.0.0.66"}',
    ]
    for i, line in enumerate(lines, 1):
        s.insert(parse_line(line), "test.log", i)
    s.conn.commit()
    return s


@pytest.fixture
def registry():
    return default_registry()


class TestTools:
    def test_search_logs(self, store_with_data, registry):
        result = registry.call(store_with_data, "search_logs", {"keyword": "sql"})
        assert result.ok
        assert isinstance(result.data, list)

    def test_search_by_ip(self, store_with_data, registry):
        result = registry.call(store_with_data, "search_logs", {"source_ip": "10.0.0.99"})
        assert result.ok
        assert len(result.data) == 2

    def test_get_stats(self, store_with_data, registry):
        result = registry.call(store_with_data, "get_stats", {})
        assert result.ok
        assert result.data["total"] == 7
        assert "by_level" in result.data
        assert "top_ips" in result.data

    def test_get_timeline(self, store_with_data, registry):
        result = registry.call(store_with_data, "get_timeline", {"source_ip": "10.0.0.99"})
        assert result.ok
        assert len(result.data) == 2

    def test_get_timeline_empty_ip(self, store_with_data, registry):
        result = registry.call(store_with_data, "get_timeline", {"source_ip": ""})
        assert not result.ok

    def test_get_error_sample(self, store_with_data, registry):
        result = registry.call(store_with_data, "get_error_sample", {})
        assert result.ok
        assert all(e["level"] in ("ERROR", "CRITICAL") for e in result.data)

    def test_get_sample(self, store_with_data, registry):
        result = registry.call(store_with_data, "get_sample", {"limit": 3})
        assert result.ok
        assert len(result.data) <= 3

    def test_correlate_shared_paths(self, store_with_data, registry):
        result = registry.call(store_with_data, "correlate_events",
                               {"mode": "shared_paths", "min_ips": 1})
        assert result.ok

    def test_correlate_ip_paths(self, store_with_data, registry):
        result = registry.call(store_with_data, "correlate_events",
                               {"mode": "ip_paths", "source_ip": "10.0.0.12"})
        assert result.ok
        assert isinstance(result.data, list)

    def test_unknown_tool(self, store_with_data, registry):
        result = registry.call(store_with_data, "nonexistent", {})
        assert not result.ok
        assert "未知工具" in result.error

    def test_schemas(self, registry):
        schemas = registry.schemas()
        names = {s["function"]["name"] for s in schemas}
        assert "search_logs" in names
        assert "get_stats" in names
        assert "get_timeline" in names