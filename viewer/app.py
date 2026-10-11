import streamlit as st
import pandas as pd
import sqlite3
import argparse
import sys
from pathlib import Path
import altair as alt

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from forensic.timeline import query_events, Filters, summary_stats, gap_summary, skew_summary, evidence_manifest, context_window
from forensic.ingest import verify_items

st.set_page_config(page_title="Forensic Viewer", layout="wide")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", default="cases/s3_clock_skew")
    args, _ = parser.parse_known_args(sys.argv[1:])
    return args

args = parse_args()
case_dir = Path(args.case)
db_path = case_dir / "case.db"

if not db_path.exists():
    st.error(f"Case database not found: {db_path}")
    st.stop()

@st.cache_resource
def get_conn(db_path_str: str):
    conn = sqlite3.connect(db_path_str, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

conn = get_conn(str(db_path))

# Basic info
stats = summary_stats(conn)
if not stats:
    st.error("No events in the database.")
    st.stop()

st.sidebar.header("Filters")
f_hosts = st.sidebar.multiselect("Hosts", options=stats["hosts"])
f_types = st.sidebar.multiselect("Event Types", options=list(stats.get("by_type", {}).keys()))
f_severities = st.sidebar.multiselect("Severity", options=list(stats.get("by_severity", {}).keys()))
f_ip = st.sidebar.text_input("Source IP")
f_user = st.sidebar.text_input("Username")
f_text = st.sidebar.text_input("Search (FTS)")
f_from = st.sidebar.text_input("From (ISO UTC)")
f_to = st.sidebar.text_input("To (ISO UTC)")
use_corrected = st.sidebar.checkbox("Use skew-corrected time", value=True)
limit = st.sidebar.number_input("Event Limit", min_value=1, max_value=100000, value=5000)

filters_dataclass = Filters(
    hosts=f_hosts if f_hosts else None,
    event_types=f_types if f_types else None,
    severities=f_severities if f_severities else None,
    src_ip=f_ip if f_ip else None,
    username=f_user if f_user else None,
    ts_from=f_from if f_from else None,
    ts_to=f_to if f_to else None,
    text=f_text if f_text else None,
    use_corrected=use_corrected
)

@st.cache_data
def load_events(_conn, f: Filters, lim: int):
    return query_events(_conn, f, limit=lim)

events = load_events(conn, filters_dataclass, limit)

st.title(f"Case Viewer: {case_dir.name}")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Events", stats["total_events"])
col2.metric("First Time", stats["first_event"])
col3.metric("Last Time", stats["last_event"])
col4.metric("Gaps", stats["total_gaps"])
col5.metric("Skew corrections", len(skew_summary(conn)))

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Timeline", "Event Detail", "Evidence", "Parsing Gaps", "Clock Skew"])

with tab1:
    if not events:
        st.write("No events match the filters.")
    else:
        df = pd.DataFrame(events)
        ts_col = "ts_utc_corrected" if use_corrected else "ts_utc"
        
        # Altair chart
        df_chart = df.copy()
        df_chart['minute'] = pd.to_datetime(df_chart[ts_col]).dt.floor('min')
        grouped = df_chart.groupby(['minute', 'host']).size().reset_index(name='count')
        chart = alt.Chart(grouped).mark_bar().encode(
            x='minute:T',
            y='count:Q',
            color='host:N',
            tooltip=['minute:T', 'host:N', 'count:Q']
        ).properties(height=200)
        st.altair_chart(chart, width="stretch")
        
        st.dataframe(df[[ts_col, "ts_original", "host", "event_type", "severity", "src_ip", "username", "message"]])

with tab2:
    if events:
        selected_idx = st.selectbox("Select Event ID", [r["id"] for r in events])
        if selected_idx:
            ev = next((r for r in events if r["id"] == selected_idx), None)
            if ev:
                st.write("**Raw Line:**", ev["raw_line"])
                
                evd = conn.execute("SELECT * FROM evidence WHERE id = ?", (ev["evidence_id"],)).fetchone()
                if evd:
                    st.write(f"**Evidence File:** {evd['filename']} | **SHA-256:** {evd['sha256']}")
                    st.write(f"**Line Number:** {ev['line_no']} | **Byte Offset:** {ev['byte_offset']}")
                    
                st.write(f"**Original:** {ev['ts_original']} | **UTC:** {ev['ts_utc']} | **Corrected:** {ev['ts_utc_corrected']}")
                
                st.subheader("+/- 60s Context Window")
                ctx = context_window(conn, ev["id"], 60)
                if ctx:
                    ctx_df = pd.DataFrame(ctx)
                    st.dataframe(ctx_df[["ts_utc_corrected", "host", "event_type", "message"]])

with tab3:
    evs = evidence_manifest(conn)
    if evs:
        if st.button("Verify integrity"):
            try:
                res = verify_items(case_dir)
                st.session_state["verify_result"] = res
            except Exception as e:
                st.exception(e)
                
        if "verify_result" in st.session_state:
            res = st.session_state["verify_result"]
            df_v = pd.DataFrame(res)
            def color_status(val):
                return 'color: green' if val == 'OK' else 'color: red'
            
            st.dataframe(df_v.style.map(color_status, subset=['status']))
            n_ok = sum(1 for r in res if r['status'] == 'OK')
            m_prob = len(res) - n_ok
            if m_prob == 0:
                st.success(f"{n_ok} OK, {m_prob} problems")
            else:
                st.error(f"{n_ok} OK, {m_prob} problems")
                
        st.dataframe(pd.DataFrame(evs))
    else:
        st.write("No evidence records found.")

with tab4:
    gaps = gap_summary(conn)
    if gaps:
        gaps_df = pd.DataFrame(gaps)
        st.dataframe(gaps_df)
        
        reasons_data = []
        for g in gaps:
            for r, c in g.get("reasons", {}).items():
                reasons_data.append({"host": g["host"], "file": g["filename"], "reason": r, "count": c})
                
        if reasons_data:
            st.bar_chart(pd.DataFrame(reasons_data).groupby("reason")["count"].sum())
            
        unparsed = conn.execute("SELECT * FROM parse_gaps LIMIT 50").fetchall()
        st.dataframe(pd.DataFrame([dict(u) for u in unparsed]))
    else:
        st.write("No parsing gaps.")

with tab5:
    skews = skew_summary(conn)
    if skews:
        st.dataframe(pd.DataFrame(skews))
        # Optional before/after chart logic
        st.write("Before/after chart can be rendered here with raw timestamps vs corrected.")
    else:
        st.write("No skew corrections applied.")
