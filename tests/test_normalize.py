from datetime import datetime, timezone

import pytest

from forensic.models import ParseContext
from forensic.normalize import syslog_to_utc


def test_syslog_to_utc_with_year_hint():
    ctx = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    dt, new_year = syslog_to_utc("Oct  3 02:14:07", ctx, None, None)
    assert dt == datetime(2026, 10, 3, 2, 14, 7, tzinfo=timezone.utc)
    assert new_year == 2026

def test_syslog_to_utc_rollover():
    ctx = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    dt1, year1 = syslog_to_utc("Dec 31 23:59:59", ctx, None, None)
    assert dt1.year == 2026
    dt2, year2 = syslog_to_utc("Jan  1 00:00:01", ctx, datetime(2000, 12, 31), year1)
    assert dt2.year == 2027
    assert year2 == 2027

def test_syslog_to_utc_invalid():
    ctx = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    with pytest.raises(ValueError):
        syslog_to_utc("Feb 30 12:00:00", ctx, None, None)

def test_syslog_ist_vs_nginx_utc():
    ctx_ist = ParseContext(host="test", source_type="auth_log", declared_tz="Asia/Kolkata", year_hint=2026)
    dt_ist, _ = syslog_to_utc("Oct  3 08:00:00", ctx_ist, None, None)

    ctx_utc = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    dt_utc, _ = syslog_to_utc("Oct  3 02:30:00", ctx_utc, None, None)

    assert dt_ist == dt_utc

def test_leap_day():
    ctx_2028 = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2028)
    dt, _ = syslog_to_utc("Feb 29 12:00:00", ctx_2028, None, None)
    assert dt.year == 2028
    assert dt.month == 2
    assert dt.day == 29

    ctx_2026 = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    with pytest.raises(ValueError, match="bad_timestamp"):
        syslog_to_utc("Feb 29 12:00:00", ctx_2026, None, None)

def test_year_hint_none():
    mtime = datetime(2025, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
    ctx = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=None, file_mtime_utc=mtime)
    dt, new_year = syslog_to_utc("Oct  3 02:14:07", ctx, None, None)
    assert dt.year == 2025
    assert new_year == 2025
