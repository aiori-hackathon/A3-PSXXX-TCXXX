# Parsing Gap Analysis

## Coverage by Scenario and File

| Scenario | Host | File | Total Lines | Parsed | Gaps | Blank | Parsed % | Reasons |
|---|---|---|---|---|---|---|---|---|
| s1_ssh_bruteforce | web01 | auth.log | 169 | 165 | 4 | 0 | 97.63% | bad_timestamp: 1, no_regex_match: 3 |
| s2_web_attack | web01 | access.log | 111 | 106 | 5 | 1 | 96.36% | empty_line: 1, no_regex_match: 3, truncated: 1 |
| s3_clock_skew | web01 | auth.log | 10 | 10 | 0 | 0 | 100.00% | None |
| s3_clock_skew | web01 | access.log | 12 | 12 | 0 | 0 | 100.00% | None |
| s3_clock_skew | db01 | auth.log | 2 | 2 | 0 | 0 | 100.00% | None |
| s3_clock_skew | db01 | access.log | 11 | 11 | 0 | 0 | 100.00% | None |

## Gap Categories Discussion

- **no_regex_match**: The log line format does not match the parser's expected regular expression. This is typically a tool limitation (e.g. unknown daemon) but can also happen for malformed input.
- **bad_timestamp**: The timestamp could not be parsed into a valid date/time. Often caused by corrupted logs or unexpected date formats (malformed input).
- **truncated**: The log line ends abruptly, possibly due to a crash, disk full, or bad network transfer (malformed input).
- **empty_line**: The log line consists entirely of whitespace. Usually safe to ignore (malformed input / noise).
- **encoding_error**: The line contains non-UTF-8 bytes. Caused by binary data dumped into logs or different encodings (malformed input).

## What the tool does not parse

- RFC 5424 syslog format
- Apache error log
- JSON logs
- Multi-line stack traces (often recorded as multiple invalid lines)
- Non-UTF-8 logs
- DST-ambiguous local times
