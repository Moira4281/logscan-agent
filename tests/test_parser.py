"""日志解析器测试。"""

from logscan.logs.parser import parse_line, parse_lines


class TestJsonParsing:
    def test_basic_json(self):
        line = '{"timestamp": "2024-01-15T10:00:00Z", "level": "ERROR", "message": "test error"}'
        e = parse_line(line)
        assert e.level == "ERROR"
        assert e.message == "test error"
        assert "2024-01-15" in e.timestamp

    def test_json_with_ip(self):
        line = '{"timestamp": "2024-01-15T10:00:00Z", "level": "WARN", "message": "warn", "source_ip": "10.0.0.1", "path": "/admin"}'
        e = parse_line(line)
        assert e.source_ip == "10.0.0.1"
        assert e.path == "/admin"

    def test_json_extra_fields(self):
        line = '{"timestamp": "2024-01-15T10:00:00Z", "message": "x", "service": "web", "request_id": "abc"}'
        e = parse_line(line)
        assert e.extra.get("service") == "web"
        assert e.extra.get("request_id") == "abc"

    def test_json_nested_timestamp(self):
        line = '{"@timestamp": "2024-01-15T10:00:00.123Z", "message": "x"}'
        e = parse_line(line)
        assert "2024-01-15" in e.timestamp


class TestNginxParsing:
    def test_nginx_combined(self):
        line = '192.168.1.1 - - [15/Jan/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 401 1234 "-" "Mozilla/5.0"'
        e = parse_line(line)
        assert e.source_ip == "192.168.1.1"
        assert e.method == "GET"
        assert e.path == "/admin"
        assert e.status_code == 401
        assert e.level == "WARN"

    def test_nginx_500_is_error(self):
        line = '10.0.0.1 - - [15/Jan/2024:10:30:45 +0000] "GET /products?id=1\' HTTP/1.1" 500 100 "-" "sqlmap"'
        e = parse_line(line)
        assert e.status_code == 500
        assert e.level == "ERROR"

    def test_nginx_with_user(self):
        line = '192.168.1.50 - admin [15/Jan/2024:10:30:45 +0000] "GET /dashboard HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
        e = parse_line(line)
        assert e.user == "admin"


class TestSyslogParsing:
    def test_syslog_with_priority(self):
        line = "<134>Jan 15 10:30:45 myhost myapp[1234]: something happened"
        e = parse_line(line)
        assert e.level == "INFO"
        assert "something happened" in e.message
        assert e.extra.get("host") == "myhost"
        assert e.extra.get("program") == "myapp"
        assert e.extra.get("pid") == 1234

    def test_syslog_error_priority(self):
        line = "<35>Jan 15 10:30:45 myhost sudo[1234]: command failed"
        e = parse_line(line)
        assert e.level == "ERROR"

    def test_syslog_sshd(self):
        line = "<132>Jan 15 10:05:30 webserver01 sshd[1235]: Failed password for root from 10.0.0.99 port 49152"
        e = parse_line(line)
        assert "Failed password" in e.message
        assert e.extra.get("program") == "sshd"


class TestGenericParsing:
    def test_iso_timestamp(self):
        line = "2024-01-15T10:30:45Z some application message here"
        e = parse_line(line)
        assert "2024-01-15" in e.timestamp

    def test_level_inference(self):
        e = parse_line("2024-01-15 something failed with error")
        assert e.level == "ERROR"

        e = parse_line("2024-01-15 this is a warning")
        assert e.level == "WARN"

        e = parse_line("2024-01-15 normal info message")
        assert e.level == "INFO"

    def test_ip_extraction(self):
        e = parse_line("connection from 10.0.0.55 to local service")
        assert e.source_ip == "10.0.0.55"

    def test_empty_line(self):
        e = parse_line("")
        assert e.message == ""
        assert e.level == "INFO"


class TestParseLines:
    def test_batch(self):
        lines = [
            '{"timestamp": "2024-01-15T10:00:00Z", "level": "INFO", "message": "a"}',
            '192.168.1.1 - - [15/Jan/2024:10:00:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
            "",
        ]
        entries = parse_lines(lines)
        assert len(entries) == 2
        assert entries[0].message == "a"
        assert entries[1].source_ip == "192.168.1.1"