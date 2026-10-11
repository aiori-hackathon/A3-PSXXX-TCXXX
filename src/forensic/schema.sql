PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS evidence (
  id               INTEGER PRIMARY KEY,
  filename         TEXT NOT NULL,         -- original file name
  stored_path      TEXT NOT NULL,         -- path inside cases/<id>/evidence/
  sha256           TEXT NOT NULL UNIQUE,  -- hash of the ORIGINAL bytes, computed at collection
  size_bytes       INTEGER NOT NULL,
  line_count       INTEGER NOT NULL,
  collected_at_utc TEXT NOT NULL,         -- ISO-8601 UTC, e.g. 2026-10-08T09:12:44Z
  collector        TEXT NOT NULL,         -- username of person running the tool
  host             TEXT NOT NULL,         -- logical host the log came from (web01, db01 ...)
  source_type      TEXT NOT NULL,         -- 'auth_log' | 'nginx'
  declared_tz      TEXT NOT NULL          -- IANA name, e.g. 'Asia/Kolkata', 'UTC'
);

CREATE TABLE IF NOT EXISTS events (
  id                INTEGER PRIMARY KEY,
  evidence_id       INTEGER NOT NULL REFERENCES evidence(id),
  line_no           INTEGER NOT NULL,     -- 1-based line in the original file
  byte_offset       INTEGER NOT NULL,     -- offset of line start in the original file
  ts_original       TEXT NOT NULL,        -- timestamp string exactly as in the log
  ts_utc            TEXT NOT NULL,        -- ISO-8601 UTC after tz normalization (no skew fix)
  ts_utc_corrected  TEXT NOT NULL,        -- ts_utc + skew offset (equals ts_utc if no correction)
  skew_offset_s     REAL NOT NULL DEFAULT 0,
  host              TEXT NOT NULL,
  source_type       TEXT NOT NULL,
  event_type        TEXT NOT NULL,        -- see event-type vocabulary in section 4
  severity          TEXT NOT NULL DEFAULT 'info',   -- 'info' | 'low' | 'medium' | 'high'
  src_ip            TEXT,
  username          TEXT,
  detail            TEXT,                 -- request path for web, command for sudo, etc.
  message           TEXT NOT NULL,        -- human-readable summary
  raw_line          TEXT NOT NULL,        -- verbatim original line (also in evidence file)
  UNIQUE (evidence_id, line_no)
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts_utc_corrected);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  message, raw_line, username, src_ip, detail,
  content='events', content_rowid='id'
);
-- build.py must populate events_fts after loading events:
--   INSERT INTO events_fts(rowid, message, raw_line, username, src_ip, detail)
--   SELECT id, message, raw_line, username, src_ip, detail FROM events;

CREATE TABLE IF NOT EXISTS parse_gaps (
  id           INTEGER PRIMARY KEY,
  evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
  line_no      INTEGER NOT NULL,
  reason       TEXT NOT NULL,   -- 'no_regex_match' | 'bad_timestamp' | 'truncated' | 'empty_line' | 'encoding_error'
  raw_line     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS skew_corrections (
  host            TEXT PRIMARY KEY,
  reference_host  TEXT NOT NULL,
  offset_s        REAL NOT NULL,    -- seconds ADDED to this host's ts_utc to align with reference
  method          TEXT NOT NULL,    -- 'anchor_median' | 'manual' | 'none'
  anchor_count    INTEGER NOT NULL,
  stdev_s         REAL,
  confidence_note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL   -- case_id, created_at_utc, tool_version, year_hint
);
