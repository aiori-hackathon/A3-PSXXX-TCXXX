import re
from datetime import datetime

from ..models import Event, LineParser, ParseContext, ParseGap
from ..normalize import syslog_to_utc

SYSLOG = re.compile(
    r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<proc>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$'
)

MSG_PATTERNS = [
    (
        re.compile(
            r'Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+'
        ),
        'ssh_failed_login',
        'low',
    ),
    (
        re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\S+)'),
        'ssh_invalid_user',
        'low',
    ),
    (
        re.compile(
            r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port'
        ),
        'ssh_accepted_login',
        'medium',
    ),
    (
        re.compile(r'pam_unix\(.*:session\): session opened for user (?P<user>\S+)'),
        'session_opened',
        'info',
    ),
    (
        re.compile(r'session closed for user (?P<user>\S+)'),
        'session_closed',
        'info',
    ),
    (
        re.compile(r'(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$'),
        'sudo_command',
        'medium',
    ),
    (
        re.compile(r'new user: name=(?P<user>\S+)'),
        'user_added',
        'high',
    ),
    (
        re.compile(r'Disconnected from|Connection closed by'),
        'ssh_disconnect',
        'info',
    ),
]


class AuthLogParser(LineParser):
    def __init__(self):
        self.prev_dt: datetime | None = None
        self.current_year: int | None = None

    def parse_line(
        self, line: str, line_no: int, byte_offset: int, ctx: ParseContext
    ) -> Event | ParseGap:
        if not line.strip():
            return ParseGap(line_no, "empty_line", line)

        match = SYSLOG.match(line)
        if not match:
            return ParseGap(line_no, "no_regex_match", line)

        try:
            ts_str = match.group("ts")
            ts_utc, new_year = syslog_to_utc(
                ts_str, ctx, self.prev_dt, self.current_year
            )
            self.current_year = new_year
            # Use leap-year 2000 base to avoid Feb-29 crash when storing prev_dt
            try:
                self.prev_dt = datetime.strptime(
                    "2000 " + ts_str, "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                self.prev_dt = None
        except ValueError:
            return ParseGap(line_no, "bad_timestamp", line)

        host = match.group("host")
        msg = match.group("msg")

        event_type = "syslog_other"
        severity = "info"
        src_ip = None
        username = None
        detail = None

        for pat, etype, sev in MSG_PATTERNS:
            m = pat.search(msg)
            if m:
                event_type = etype
                severity = sev
                # Map extracted fields
                if 'user' in m.groupdict():
                    username = m.group("user")
                if 'ip' in m.groupdict():
                    src_ip = m.group("ip")
                if 'cmd' in m.groupdict():
                    detail = m.group("cmd")

                # Fix up specific things
                if etype == 'ssh_failed_login' and 'invalid user' in msg:
                    event_type = 'ssh_invalid_user'
                if etype == 'sudo_command' and detail and re.search(
                    r'/bin/(ba)?sh|su -|shadow|useradd|passwd', detail
                ):
                    severity = 'high'
                break

        if event_type == "syslog_other":
            human_msg = msg[:100]
        else:
            human_msg = f"{event_type}"
            if username:
                human_msg += f" {username}"
            if src_ip:
                human_msg += f" from {src_ip}"
            if detail:
                human_msg += f" ({detail})"

        return Event(
            line_no=line_no,
            byte_offset=byte_offset,
            ts_original=match.group("ts"),
            ts_utc=ts_utc,
            host=host,
            source_type=ctx.source_type,
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            username=username,
            detail=detail,
            message=human_msg,
            raw_line=line,
        )
