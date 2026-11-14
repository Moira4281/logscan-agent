"""原始 HTTP 报文 dump（CSIC 2010 风格）解析测试。"""

from __future__ import annotations

from logscan.logs.parser import parse_http_dump


class TestHttpDump:
    def test_two_requests_aggregated(self):
        lines = [
            "GET /a HTTP/1.1",
            "Host: localhost:8080",
            "User-Agent: curl/7.1",
            "",
            "GET /b?x=1 HTTP/1.1",
            "Host: localhost:8080",
            "",
        ]
        entries = parse_http_dump(lines)
        assert len(entries) == 2
        assert entries[0].method == "GET"
        assert entries[0].path == "/a"
        assert entries[0].extra["user_agent"] == "curl/7.1"
        assert entries[1].path == "/b"
        assert entries[1].extra["params"] == "x=1"

    def test_absolute_url_split(self):
        lines = [
            "POST http://localhost:8080/tienda1/publico/anadir.jsp?id=2&name=x HTTP/1.1",
            "Host: localhost:8080",
            "",
        ]
        e = parse_http_dump(lines)[0]
        assert e.method == "POST"
        assert e.path == "/tienda1/publico/anadir.jsp"
        assert e.extra["params"] == "id=2&name=x"
        assert e.extra["host"] == "localhost:8080"
        assert e.message == "POST /tienda1/publico/anadir.jsp ?id=2&name=x"

    def test_post_with_body(self):
        lines = [
            "POST /login HTTP/1.1",
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: 20",
            "",
            "user=admin&pass=123",
        ]
        e = parse_http_dump(lines)[0]
        assert e.extra["body"] == "user=admin&pass=123"
        assert e.extra["content_type"] == "application/x-www-form-urlencoded"

    def test_body_may_contain_blank_line(self):
        lines = [
            "POST /x HTTP/1.1",
            "Host: h",
            "",
            "a",
            "",
            "b",
            "",
            "GET /y HTTP/1.1",
            "",
        ]
        entries = parse_http_dump(lines)
        assert len(entries) == 2
        assert entries[0].extra["body"] == "a\n\nb"
        assert entries[1].path == "/y"

    def test_user_agent_header_lowercase(self):
        lines = ["GET / HTTP/1.1", "user-agent: sqlmap/1.7-dev", ""]
        e = parse_http_dump(lines)[0]
        assert e.extra["user_agent"] == "sqlmap/1.7-dev"

    def test_no_body_key_when_absent(self):
        e = parse_http_dump(["GET / HTTP/1.1", "Host: h", ""])[0]
        assert "body" not in e.extra

    def test_max_entries_limit(self):
        lines = []
        for i in range(10):
            lines += [f"GET /p{i} HTTP/1.1", "Host: h", ""]
        entries = parse_http_dump(lines, max_entries=3)
        assert len(entries) == 3

    def test_junk_before_first_request_ignored(self):
        lines = ["this is junk", "GET /a HTTP/1.1", "Host: h", ""]
        entries = parse_http_dump(lines)
        assert len(entries) == 1
        assert entries[0].path == "/a"

    def test_empty_input(self):
        assert parse_http_dump([]) == []
