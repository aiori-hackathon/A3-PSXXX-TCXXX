from forensic.models import Event, ParseContext, ParseGap
from forensic.parsers.auth_log import AuthLogParser
from forensic.parsers.nginx import NginxParser


def test_auth_log_ssh_failed():
    parser = AuthLogParser()
    ctx = ParseContext("web01", "auth_log", "UTC", 2026)

    # ssh_failed_login
    res = parser.parse_line("Oct  3 02:14:07 web01 sshd[1234]: Failed password for admin from 203.0.113.50 port 51122 ssh2", 1, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "ssh_failed_login"

    # ssh_invalid_user
    res = parser.parse_line("Oct  3 02:14:07 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 51122 ssh2", 2, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "ssh_invalid_user"

    # ssh_accepted_login
    res = parser.parse_line("Oct  3 02:14:15 web01 sshd[1235]: Accepted publickey for deploy from 192.168.1.10 port 40112 ssh2", 3, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "ssh_accepted_login"

    # session_opened
    res = parser.parse_line("Oct  3 02:16:10 web01 sshd[1300]: pam_unix(sshd:session): session opened for user deploy by (uid=0)", 4, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "session_opened"

    # session_closed
    res = parser.parse_line("Oct  3 02:17:00 web01 sshd[1300]: pam_unix(sshd:session): session closed for user deploy", 5, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "session_closed"

    # sudo_command
    res = parser.parse_line("Oct  3 02:15:00 web01 sudo:  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash", 6, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "sudo_command" and res.severity == "high"

    # user_added
    res = parser.parse_line("Oct  3 02:15:30 web01 useradd[1500]: new user: name=attacker, UID=1001, GID=1001, home=/home/attacker, shell=/bin/bash", 7, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "user_added"

    # ssh_disconnect
    res = parser.parse_line("Oct  3 02:16:00 web01 sshd[1235]: Disconnected from user deploy 192.168.1.10 port 40112", 8, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "ssh_disconnect"

    # syslog_other
    res = parser.parse_line("Oct  3 02:14:00 web01 sshd[100]: Server listening on 0.0.0.0 port 22.", 9, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "syslog_other"

def test_nginx_events():
    parser = NginxParser()
    ctx = ParseContext("web01", "nginx", "UTC", 2026)

    # web_request
    res = parser.parse_line('192.168.1.50 - - [03/Oct/2026:02:30:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"', 1, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "web_request"

    # web_scan
    res = parser.parse_line('192.168.1.51 - - [03/Oct/2026:02:31:00 +0000] "GET /admin HTTP/1.1" 404 512 "-" "sqlmap/1.7"', 2, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "web_scan"

    # web_sqli_attempt
    res = parser.parse_line('192.168.1.52 - - [03/Oct/2026:02:32:00 +0000] "GET /index.php?id=1%27%20UNION%20SELECT%201,2 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"', 3, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "web_sqli_attempt"

    # web_sqli_attempt double encoded
    res = parser.parse_line('192.168.1.53 - - [03/Oct/2026:02:33:00 +0000] "GET /index.php?id=1%2527%2520UNION%2520SELECT%25201,2 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"', 4, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "web_sqli_attempt"

    # web_path_traversal
    res = parser.parse_line('192.168.1.54 - - [03/Oct/2026:02:34:00 +0000] "GET /images/../../../../etc/passwd HTTP/1.1" 403 256 "-" "Mozilla/5.0"', 5, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "web_path_traversal"

    # web_webshell_upload
    res = parser.parse_line('192.168.1.55 - - [03/Oct/2026:02:35:00 +0000] "POST /upload.php HTTP/1.1" 201 128 "-" "curl/7.68.0"', 6, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "web_webshell_upload"

    # web_webshell_access
    res = parser.parse_line('192.168.1.56 - - [03/Oct/2026:02:36:00 +0000] "GET /shell.php?cmd=whoami HTTP/1.1" 200 64 "-" "curl/7.68.0"', 7, 0, ctx)
    assert isinstance(res, Event) and res.event_type == "web_webshell_access"

def test_parse_gaps():
    parser = AuthLogParser()
    ctx = ParseContext("web01", "auth_log", "UTC", 2026)

    # empty_line
    res = parser.parse_line("  \n", 1, 0, ctx)
    assert isinstance(res, ParseGap) and res.reason == "empty_line"

    # no_regex_match
    res = parser.parse_line("Garbage line not matching syslog", 2, 0, ctx)
    assert isinstance(res, ParseGap) and res.reason == "no_regex_match"

    # bad_timestamp
    res = parser.parse_line("Feb 30 12:00:00 web01 sshd[100]: Invalid date test", 3, 0, ctx)
    assert isinstance(res, ParseGap) and res.reason == "bad_timestamp"

    # truncated (nginx)
    n_parser = NginxParser()
    n_ctx = ParseContext("web01", "nginx", "UTC", 2026)
    res = n_parser.parse_line('192.168.1.57 - - [03/Oct/2026:02:37:00 +0000] "GET /truncated', 4, 0, n_ctx)
    assert isinstance(res, ParseGap) and res.reason == "truncated"
