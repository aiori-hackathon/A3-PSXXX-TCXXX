from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from .models import ParseContext


def syslog_to_utc(
    ts_str: str,
    ctx: ParseContext,
    prev_dt: datetime | None,
    current_year: int | None,
) -> tuple[datetime, int]:
    # Use a leap year (2000) as the base to avoid "Feb 29" failing on 1900 (not a leap year)
    try:
        parsed = datetime.strptime("2000 " + ts_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        raise ValueError("bad_timestamp")

    if current_year is None:
        if ctx.year_hint:
            current_year = ctx.year_hint
        elif ctx.file_mtime_utc:
            current_year = ctx.file_mtime_utc.year
        else:
            current_year = datetime.now(timezone.utc).year

    if prev_dt:
        if parsed.month < prev_dt.month - 6:
            current_year += 1

    # Apply real year — may fail e.g. Feb 29 in a non-leap year → bad_timestamp
    try:
        dt_naive = parsed.replace(year=current_year)
    except ValueError:
        raise ValueError("bad_timestamp")

    if ctx.file_mtime_utc and not ctx.year_hint:
        if (dt_naive.replace(tzinfo=timezone.utc) - ctx.file_mtime_utc).days > 30:
            current_year -= 1
            try:
                dt_naive = parsed.replace(year=current_year)
            except ValueError:
                raise ValueError("bad_timestamp")

    try:
        tz = ZoneInfo(ctx.declared_tz)
    except Exception:
        tz = timezone.utc

    dt_aware = dt_naive.replace(tzinfo=tz, fold=0)
    dt_utc = dt_aware.astimezone(timezone.utc)

    return dt_utc, current_year
