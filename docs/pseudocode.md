# Core algorithm (pseudocode)

```python
for each source file:
    h = SHA256(file)
    copy file to evidence/ as read-only
    record name, h, size, collector, utc_now in DB and manifest.json
    manifest_hash = SHA256(manifest.json)
for each stored evidence file, line by line:
    result = parser(line, ctx)
    if result is Event: keep line_no, byte_offset, raw_line
    else: store ParseGap(line_no, reason, raw_line)
    ts_utc = to_utc(ts_original, declared_tz, year_hint)
anchors = pairs of events with same (src_ip, event_type, detail) on different hosts, nearest in time, one-to-one
offset[host] = median(ref_ts - host_ts over anchors), needs at least 3 anchors
confidence = high if stdev < 2s and n >= 5, medium if stdev < 10s, else low
for each event: ts_corrected = ts_utc + offset[host]
timeline = sort(all events by ts_corrected)
```

For each stage:
Collect: Copies raw files into evidence/ directory, enforcing read-only permissions and verifying SHA-256 integrity against manifest.json.
Parse: Uses regex definitions (nginx, auth, etc.) to extract raw variables, recording ParseGap rows when a line fails all patterns.
Normalize: Re-formats fields to typed standards, notably standardizing the original timestamp into UTC while retaining ts_original untouched.
Skew: Uses synchronized actions (e.g., SSH login start vs end) as time anchors across hosts to deduce offset deltas against a reference host.
Timeline: Generates a chronologically unified global timeline of ts_corrected, exporting structured CSVs, JSON reports, and an HTML interactive view.
Report: Evaluates timeline density to find anomalies, flags failed authentication bursts, and summarizes gaps to guide manual review.
