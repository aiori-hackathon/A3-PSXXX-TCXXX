import re
import urllib.parse
from datetime import datetime, timezone

from ..models import Event, LineParser, ParseContext, ParseGap

NGINX = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"$'
)

SCANNER_UAS = re.compile(r'nikto|sqlmap|masscan|gobuster', re.IGNORECASE)
PROBE_PATHS = re.compile(r'/wp-login\.php|/\.env|/phpmyadmin', re.IGNORECASE)
SQLI_PATTERNS = re.compile(
    r'UNION\s+SELECT|%27\s*OR|%20OR%20|sleep\(|information_schema|'
    r"' OR 1=1|%27%20UNION|%252",
    re.IGNORECASE,
)
# Webshell access: only match cmd= or exec= as query parameters (not any .php?anything)
WEBSHELL_ACCESS = re.compile(r'[?&](?:cmd|exec)=', re.IGNORECASE)


class NginxParser(LineParser):
    def parse_line(
        self, line: str, line_no: int, byte_offset: int, ctx: ParseContext
    ) -> Event | ParseGap:
        if not line.strip():
            return ParseGap(line_no, "empty_line", line)

        match = NGINX.match(line)
        if not match:
            # Check if it looks truncated (ends mid-quote or similar)
            if '"' in line and line.count('"') % 2 != 0:
                return ParseGap(line_no, "truncated", line)
            return ParseGap(line_no, "no_regex_match", line)

        try:
            ts_str = match.group("ts")
            dt_aware = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            ts_utc = dt_aware.astimezone(timezone.utc)
        except ValueError:
            return ParseGap(line_no, "bad_timestamp", line)

        path_raw = match.group("path")
        path_decoded1 = urllib.parse.unquote(path_raw)
        path_decoded2 = urllib.parse.unquote(path_decoded1)

        method = match.group("method")
        status = match.group("status")
        ua = match.group("ua")

        event_type = "web_request"
        severity = "info"

        # Classification order: webshell_access > webshell_upload > sqli > path_traversal > scan > web_request
        if WEBSHELL_ACCESS.search(path_decoded2):
            event_type = "web_webshell_access"
            severity = "high"
        elif (
            method in ("POST", "PUT")
            and (
                re.search(r'\.php$|\.jsp$', path_decoded2, re.IGNORECASE)
                or "upload" in path_decoded2.lower()
            )
            and status.startswith("2")
        ):
            event_type = "web_webshell_upload"
            severity = "high"
        elif SQLI_PATTERNS.search(path_raw) or SQLI_PATTERNS.search(path_decoded1) or SQLI_PATTERNS.search(path_decoded2):
            event_type = "web_sqli_attempt"
            severity = "high"
        elif (
            "../" in path_decoded2
            or "%2e%2e" in path_decoded1.lower()
            or "..\\" in path_decoded2
        ):
            event_type = "web_path_traversal"
            severity = "high"
        elif SCANNER_UAS.search(ua) or PROBE_PATHS.search(path_decoded2):
            event_type = "web_scan"
            severity = "low"

        detail = f"{method} {path_raw} {status}"
        msg = f"{method} {path_decoded2} -> {status}"
        if len(msg) > 100:
            msg = msg[:97] + "..."

        username = match.group("user") if match.group("user") != "-" else None

        return Event(
            line_no=line_no,
            byte_offset=byte_offset,
            ts_original=ts_str,
            ts_utc=ts_utc,
            host=ctx.host,
            source_type=ctx.source_type,
            event_type=event_type,
            severity=severity,
            src_ip=match.group("ip"),
            username=username,
            detail=detail,
            message=msg,
            raw_line=line,
        )
