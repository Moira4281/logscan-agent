"""日志存储与查询测试。"""

import pytest

from logscan.logs.store import LogStore
from logscan.logs.parser import parse_line


@pytest.fixture
def store():
    s = LogStore(":memory:")
    entries = [
        parse_line('10.0.0.66 - - [15/Jan/2024:10:01:02 +0000] "GET /products?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 120 "-" "sqlmap"'),
        parse_line('10.0.0.99 - - [15/Jan/2024:10:04:00 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"'),
        parse_line('10.0.0.99 - - [15/Jan/2024:10:04:01 +0000] "POST /login HTTP/1.1" 401 50 "-" "Mozilla/5.0"'),
        parse_line('192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'),
        parse_line('{"timestamp": "2024-01-15T10:01:03Z", "level": "ERROR", "message": "SQL error OR 1=1", "source_ip": "10.0.0.66"}'),
    ]
    for e in entries:
        s.insert(e, "test.log", 1)
    s.conn.commit()
    return s


class TestStore:
    def test_total(self, store):
        assert store.total() == 5

    def test_search_by_keyword(self, store):
        results = store.search(keyword="sql")
        assert len(results) >= 1

    def test_search_by_level(self, store):
        results = store.search(level="ERROR")
        assert all(r["level"] == "ERROR" for r in results)

    def test_search_by_ip(self, store):
        results = store.search(source_ip="10.0.0.99")
        assert len(results) == 2
        assert all(r["source_ip"] == "10.0.0.99" for r in results)

    def test_search_by_status_range(self, store):
        results = store.search(status_min=400, status_max=599)
        assert all(400 <= r["status_code"] <= 599 for r in results)
        assert len(results) >= 3

    def test_stats_by_level(self, store):
        stats = store.stats_by_level()
        levels = {r[0] for r in stats}
        assert "ERROR" in levels or "WARN" in levels

    def test_top_ips(self, store):
        ips = store.top_ips()
        ip_counts = {r[0]: r[1] for r in ips}
        assert ip_counts.get("10.0.0.99") == 2

    def test_timeline_for_ip(self, store):
        timeline = store.timeline_for_ip("10.0.0.99")
        assert len(timeline) == 2
        assert all(r["source_ip"] == "10.0.0.99" for r in timeline)

    def test_error_sample(self, store):
        errors = store.error_sample()
        assert all(r["level"] in ("ERROR", "CRITICAL") for r in errors)

    def test_time_range(self, store):
        lo, hi = store.time_range()
        assert lo != ""
        assert hi != ""


class TestStoreFieldFilters:
    """method / params / user_agent 过滤（来自统一 CSV 的条目）。"""

    @pytest.fixture
    def csv_store(self):
        from logscan.logs.parser import parse_csv_row
        s = LogStore(":memory:")
        rows = [
            {"ts": "", "src_ip": "10.0.0.5", "method": "POST", "path": "/login",
             "params": "user=admin'--", "status": "401", "ua": "sqlmap/1.7",
             "cookie": "", "hdrs": "", "label": "sqli", "source": "csv", "raw_ref": "a#1"},
            {"ts": "", "src_ip": "10.0.0.6", "method": "GET", "path": "/index.html",
             "params": "", "status": "200", "ua": "Mozilla/5.0",
             "cookie": "", "hdrs": "", "label": "normal", "source": "csv", "raw_ref": "a#2"},
        ]
        for i, r in enumerate(rows, 1):
            s.insert(parse_csv_row(r), "a.csv", i)
        s.conn.commit()
        return s

    def test_search_by_method(self, csv_store):
        results = csv_store.search(method="POST")
        assert len(results) == 1
        assert results[0]["method"] == "POST"

    def test_search_by_method_case_insensitive(self, csv_store):
        assert len(csv_store.search(method="post")) == 1

    def test_search_by_params(self, csv_store):
        results = csv_store.search(params="admin'--")
        assert len(results) == 1
        assert results[0]["path"] == "/login"

    def test_search_by_user_agent(self, csv_store):
        results = csv_store.search(user_agent="sqlmap")
        assert len(results) == 1
        assert results[0]["source_ip"] == "10.0.0.5"

    def test_combined_filters_no_match(self, csv_store):
        assert csv_store.search(method="GET", params="admin") == []

    def test_combined_filters_match(self, csv_store):
        results = csv_store.search(method="GET", user_agent="Mozilla")
        assert len(results) == 1
        assert results[0]["path"] == "/index.html"