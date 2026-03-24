"""
app.py
------
Streamlit dashboard for the Phishing URL Analysis project.
Run with:  streamlit run app.py

Layout
------
  Sidebar   — source & scheme filters (live-refilter all charts)
  KPI strip — 5 headline numbers
  Finding 1 — URL takedown status (URLhaus)
  Finding 2 — Threat / malware-family distribution
  Finding 3 — Daily URL arrival rates over time
  Finding 4 — TLD abuse + top abused domains
  Finding 5 — Cross-feed domain overlap (Venn breakdown)
  Finding 6 — URL structural fingerprint (length, depth, HTTPS, IP-hosting)
  Footer    — raw data explorer (collapsible)
"""

import logging

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from analyzer import (
    cross_source_overlap,
    daily_arrivals,
    path_depth_distribution,
    status_distribution,
    structural_stats,
    threat_distribution,
    top_domains,
    top_tlds,
    url_length_distribution,
)
from collector import fetch_openphish, fetch_urlhaus
from processor import build_dataset

logging.basicConfig(level=logging.INFO)

# ── colour palette ────────────────────────────────────────────────────────────
COLOURS = {
    "URLhaus":  "#e74c3c",
    "OpenPhish": "#3498db",
    "online":   "#e74c3c",
    "offline":  "#2ecc71",
    "unknown":  "#95a5a6",
    "shared":   "#f39c12",
}

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing URL Intelligence",
    page_icon="🎣",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
  /* tighten up metric cards */
  [data-testid="metric-container"] { background:#1e1e2e; border-radius:8px; padding:12px; }
  /* faint divider colour */
  hr { border-color: #333; }
</style>
""", unsafe_allow_html=True)


# ── data loading (cached – refreshes every hour) ──────────────────────────────
@st.cache_data(ttl=3600, show_spinner=False)
def load_data() -> pd.DataFrame:
    uh = fetch_urlhaus(limit=1000)
    op = fetch_openphish()
    return build_dataset(uh, op)


# ── header ────────────────────────────────────────────────────────────────────
st.title("🎣 Phishing URL Intelligence Dashboard")
st.caption(
    "Live data · **URLhaus** (abuse.ch) & **OpenPhish** community feed · "
    "Cache refreshes every 60 minutes"
)

with st.spinner("Pulling threat-intelligence feeds …"):
    try:
        df_full = load_data()
    except Exception as exc:
        st.error(f"Failed to load data: {exc}")
        st.stop()

# ── sidebar filters ───────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Filters")

    all_sources = sorted(df_full["source"].dropna().unique().tolist())
    sources = st.multiselect(
        "Feed source",
        options=all_sources,
        default=all_sources,
    )

    all_schemes = sorted(df_full["scheme"].dropna().fillna("unknown").unique().tolist())
    schemes = st.multiselect(
        "URL scheme",
        options=all_schemes,
        default=all_schemes,
    )

    st.divider()
    st.caption("Filters apply to all charts below.")

df = df_full[
    df_full["source"].isin(sources) &
    (df_full["scheme"].isin(schemes) | df_full["scheme"].isna())
].copy()

if df.empty:
    st.warning("No data matches the current filters.")
    st.stop()

# ── KPI strip ─────────────────────────────────────────────────────────────────
ov = cross_source_overlap(df)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("🔗 Total URLs",      f"{len(df):,}")
k2.metric("🌐 Unique Domains",  f"{df['registered_domain'].nunique():,}")
k3.metric("🔴 URLhaus",         f"{(df['source']=='URLhaus').sum():,}")
k4.metric("🔵 OpenPhish",       f"{(df['source']=='OpenPhish').sum():,}")
k5.metric("🟡 Shared Domains",  f"{ov['shared']:,}")

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# Finding 1 — URL takedown status
# ══════════════════════════════════════════════════════════════════════════════
col1, col2 = st.columns(2)

with col1:
    st.subheader("Finding 1 — URL Takedown Status")
    st.caption(
        "URLhaus crowdsources takedown reports. The split between *online* and "
        "*offline* URLs reflects how quickly the community neutralises threats."
    )

    status = status_distribution(df)

    if status.empty:
        st.info("No URLhaus data with current filters.")
    else:
        fig1 = px.pie(
            names=status.index,
            values=status.values,
            hole=0.4,
            color=status.index,
            color_discrete_map=COLOURS,
        )
        fig1.update_traces(textinfo="label+percent+value")
        fig1.update_layout(showlegend=True, margin=dict(t=20, b=20))
        st.plotly_chart(fig1, use_container_width=True)

        pct_offline = status.get("offline", 0) / status.sum() * 100
        pct_online  = status.get("online",  0) / status.sum() * 100
        st.info(
            f"**{pct_offline:.1f}%** of URLhaus URLs were already offline at query time — "
            f"but **{pct_online:.1f}%** were still live, representing active threats."
        )

# ══════════════════════════════════════════════════════════════════════════════
# Finding 2 — Threat / malware-family distribution
# ══════════════════════════════════════════════════════════════════════════════
with col2:
    st.subheader("Finding 2 — Threat Type Distribution")
    st.caption(
        "URLhaus tags URLs with malware families (e.g. *Emotet, AgentTesla, "
        "AsyncRAT*) while OpenPhish labels everything *phishing* generically."
    )

    threat = threat_distribution(df)

    fig2 = px.bar(
        x=threat.values,
        y=threat.index,
        orientation="h",
        labels={"x": "URL count", "y": "Threat label"},
        color=threat.values,
        color_continuous_scale="Reds",
    )
    fig2.update_layout(
        showlegend=False,
        coloraxis_showscale=False,
        yaxis={"autorange": "reversed"},
        margin=dict(t=20),
    )
    st.plotly_chart(fig2, use_container_width=True)

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# Finding 3 — Temporal / arrival-rate analysis
# ══════════════════════════════════════════════════════════════════════════════
st.subheader("Finding 3 — Daily URL Arrival Rates")
st.caption(
    "Submission volume over time reveals campaign bursts vs. steady background noise. "
    "Note: OpenPhish URLs have no per-URL timestamp — they all land on the fetch date."
)

arrivals = daily_arrivals(df)

if arrivals.empty:
    st.info("Not enough temporal data with current filters.")
else:
    fig3 = px.bar(
        arrivals,
        x="date",
        y="count",
        color="source",
        barmode="stack",
        labels={"count": "URLs reported", "date": "Date", "source": "Feed"},
        color_discrete_map=COLOURS,
    )
    fig3.update_layout(margin=dict(t=20), legend=dict(orientation="h", y=1.05))
    st.plotly_chart(fig3, use_container_width=True)

    # pull out just URLhaus for a time-series stat
    uh_arrivals = arrivals[arrivals["source"] == "URLhaus"]
    if not uh_arrivals.empty:
        peak_day   = uh_arrivals.loc[uh_arrivals["count"].idxmax()]
        daily_mean = uh_arrivals["count"].mean()
        st.info(
            f"URLhaus average: **{daily_mean:.0f} URLs/day**. "
            f"Peak day: **{peak_day['date']}** with **{int(peak_day['count'])} URLs**."
        )

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# Finding 4 — TLD abuse & top abused domains
# ══════════════════════════════════════════════════════════════════════════════
st.subheader("Finding 4 — Infrastructure: Abused TLDs & Domains")
st.caption(
    "Certain TLDs are disproportionately exploited due to cheap registration, "
    "lax abuse-handling, or anonymous registration policies."
)

col3, col4 = st.columns(2)

with col3:
    st.markdown("**Top 15 TLDs**")
    tld_data = top_tlds(df)
    labels_tld = ["." + t if t != "none" else "(no TLD)" for t in tld_data.index]

    fig4a = px.bar(
        x=tld_data.values,
        y=labels_tld,
        orientation="h",
        labels={"x": "URL count", "y": "TLD"},
        color=tld_data.values,
        color_continuous_scale="Oranges",
    )
    fig4a.update_layout(
        showlegend=False,
        coloraxis_showscale=False,
        yaxis={"autorange": "reversed"},
        margin=dict(t=10),
    )
    st.plotly_chart(fig4a, use_container_width=True)

with col4:
    st.markdown("**Top 15 Registered Domains**")
    dom_data = top_domains(df)

    fig4b = px.bar(
        x=dom_data.values,
        y=dom_data.index,
        orientation="h",
        labels={"x": "URL count", "y": "Domain"},
        color=dom_data.values,
        color_continuous_scale="Purples",
    )
    fig4b.update_layout(
        showlegend=False,
        coloraxis_showscale=False,
        yaxis={"autorange": "reversed"},
        margin=dict(t=10),
    )
    st.plotly_chart(fig4b, use_container_width=True)

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# Finding 5 — Cross-feed overlap
# ══════════════════════════════════════════════════════════════════════════════
st.subheader("Finding 5 — Cross-Feed Domain Overlap")
st.caption(
    "Domains appearing in *both* feeds are high-confidence malicious infrastructure. "
    "Independent corroboration from two sources drastically reduces false-positive risk."
)

col5, col6 = st.columns([1, 2])

with col5:
    labels_venn = ["URLhaus only", "OpenPhish only", "Shared"]
    values_venn = [ov["urlhaus_only"], ov["openphish_only"], ov["shared"]]

    fig5 = go.Figure(go.Pie(
        labels=labels_venn,
        values=values_venn,
        hole=0.35,
        marker_colors=[COLOURS["URLhaus"], COLOURS["OpenPhish"], COLOURS["shared"]],
        textinfo="label+value",
    ))
    fig5.update_layout(showlegend=False, margin=dict(t=20, b=20))
    st.plotly_chart(fig5, use_container_width=True)

with col6:
    st.markdown(
        f"- **URLhaus-only domains:** {ov['urlhaus_only']:,}\n"
        f"- **OpenPhish-only domains:** {ov['openphish_only']:,}\n"
        f"- **Shared (both feeds):** {ov['shared']:,}"
    )
    if ov["shared_examples"]:
        st.markdown("**Sample of domains confirmed by both feeds:**")
        # display in a compact table
        st.dataframe(
            pd.DataFrame(ov["shared_examples"], columns=["domain"]),
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No domain overlap detected with current filters.")

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# Finding 6 — URL structural fingerprint
# ══════════════════════════════════════════════════════════════════════════════
st.subheader("Finding 6 — URL Structural Fingerprint")
st.caption(
    "Structural properties (length, path depth, IP-based hosting, HTTPS usage) "
    "are useful lightweight detection heuristics that don't require visiting the URL."
)

stats = structural_stats(df)

s1, s2, s3, s4, s5 = st.columns(5)
s1.metric("Avg URL length",    f"{stats['avg_url_length']} chars")
s2.metric("IP-based hosting",  f"{stats['pct_ip_host']}%")
s3.metric("Query string",      f"{stats['pct_has_query']}%")
s4.metric("Avg path depth",    stats["avg_path_depth"])
s5.metric("Uses HTTPS",        f"{stats['pct_https']}%")

col7, col8 = st.columns(2)

with col7:
    st.markdown("**Path Depth Distribution**")
    depth_df = path_depth_distribution(df)
    fig6a = px.histogram(
        depth_df,
        x="path_depth",
        color="source",
        nbins=20,
        barmode="overlay",
        opacity=0.75,
        labels={"path_depth": "Path segments", "count": "URLs"},
        color_discrete_map=COLOURS,
    )
    fig6a.update_layout(margin=dict(t=10), legend=dict(orientation="h", y=1.05))
    st.plotly_chart(fig6a, use_container_width=True)

with col8:
    st.markdown("**URL Length Distribution**")
    length_df = url_length_distribution(df)
    fig6b = px.histogram(
        length_df,
        x="url_length",
        color="source",
        nbins=40,
        barmode="overlay",
        opacity=0.75,
        labels={"url_length": "URL length (chars)", "count": "URLs"},
        color_discrete_map=COLOURS,
    )
    fig6b.update_layout(margin=dict(t=10), legend=dict(orientation="h", y=1.05))
    st.plotly_chart(fig6b, use_container_width=True)

st.divider()

# ── written summary ───────────────────────────────────────────────────────────
st.subheader("📄 Summary of Findings")

uh_count = (df["source"] == "URLhaus").sum()
op_count = (df["source"] == "OpenPhish").sum()
status   = status_distribution(df)
pct_off  = (status.get("offline", 0) / status.sum() * 100) if not status.empty else 0

st.markdown(f"""
This analysis combined **{len(df):,} unique URLs** from URLhaus ({uh_count:,}) 
and OpenPhish ({op_count:,}).

**Key takeaways:**

1. **Threat landscape** — Phishing is the dominant threat across both feeds. Within URLhaus,
   multiple malware families appear alongside generic malware-download entries, illustrating
   the diversity of malicious URL infrastructure beyond simple credential-harvesting.

2. **Rapid decay** — {pct_off:.1f}% of URLhaus URLs were already offline at query time,
   consistent with the short average lifespan of disposable phishing infrastructure (often
   measured in hours). Detection must be near-real-time to be actionable.

3. **Temporal bursts** — Submission volume is not uniform; identifiable spikes suggest
   coordinated campaigns rather than isolated incidents. Monitoring arrival-rate anomalies
   is a practical early-warning signal.

4. **Infrastructure concentration** — A small number of TLDs and registered domains
   account for a disproportionate share of abuse. Blocklisting at the domain/TLD level
   can provide coarse but high-recall coverage.

5. **Cross-feed corroboration** — Domains appearing in both feeds carry near-zero
   false-positive risk and should be treated as confirmed IOCs for immediate
   blocking/alerting.

6. **Structural heuristics** — IP-based hosting ({stats['pct_ip_host']}%), 
   long URLs (mean {stats['avg_url_length']} chars), and deep paths are 
   measurably over-represented vs. legitimate web traffic and can inform 
   signature-free detection rules.
""")

# ── raw data explorer (collapsible) ──────────────────────────────────────────
with st.expander("🔍 Raw data explorer"):
    display_cols = [
        "source", "url", "host", "url_status", "threat",
        "tags", "date_added", "tld", "url_length", "is_ip_host",
    ]
    st.dataframe(
        df[display_cols].reset_index(drop=True),
        use_container_width=True,
        height=400,
    )
    st.caption(f"{len(df):,} rows · never click URLs in this table")