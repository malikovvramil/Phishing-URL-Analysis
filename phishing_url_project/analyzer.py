"""
analyzer.py
-----------
Pure analysis functions.  Each function takes a DataFrame (already filtered
by the caller) and returns either a Series, a DataFrame, or a plain dict of
scalars.  No I/O, no side effects — easy to unit-test independently.

Findings produced here:
  1. URL status distribution          (Finding 1)
  2. Threat / malware-family spread   (Finding 2)
  3. Daily arrival rates per source   (Finding 3)
  4. TLD abuse & top domains          (Finding 4)
  5. Cross-feed domain overlap        (Finding 5)
  6. URL structural fingerprint       (Finding 6)
"""

import pandas as pd


# ── Finding 1 ─────────────────────────────────────────────────────────────────
def status_distribution(df: pd.DataFrame) -> pd.Series:
    """
    Count URLhaus URLs by their takedown status: online / offline / unknown.
    OpenPhish is excluded because it only ever reports 'online' (by design).
    """
    uh = df[df["source"] == "URLhaus"]
    return uh["url_status"].value_counts()


# ── Finding 2 ─────────────────────────────────────────────────────────────────
def threat_distribution(df: pd.DataFrame, top_n: int = 12) -> pd.Series:
    """
    Count URLs by threat label across all sources.
    URLhaus labels include 'malware_download', malware family names, etc.
    OpenPhish labels everything 'phishing'.
    """
    return df["threat"].value_counts().head(top_n)


# ── Finding 3 ─────────────────────────────────────────────────────────────────
def daily_arrivals(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group URL counts by calendar date and feed source.
    OpenPhish rows will all land on the fetch day (no per-URL timestamps).
    """
    tmp = df.dropna(subset=["date_added"]).copy()
    tmp["date"] = tmp["date_added"].dt.date
    return (
        tmp.groupby(["date", "source"])
        .size()
        .reset_index(name="count")
        .sort_values("date")
    )


# ── Finding 4 ─────────────────────────────────────────────────────────────────
def top_tlds(df: pd.DataFrame, n: int = 15) -> pd.Series:
    return df["tld"].replace("", "none").value_counts().head(n)


def top_domains(df: pd.DataFrame, n: int = 15) -> pd.Series:
    return (
        df["registered_domain"]
        .replace("", "unknown")
        .value_counts()
        .head(n)
    )


# ── Finding 5 ─────────────────────────────────────────────────────────────────
def cross_source_overlap(df: pd.DataFrame) -> dict:
    """
    Compare the sets of registered domains found in each feed.
    Returns counts for a Venn-style breakdown plus sample overlap domains.
    """
    def domain_set(source: str) -> set:
        s = set(df[df["source"] == source]["registered_domain"].dropna())
        s.discard("")
        return s

    uh = domain_set("URLhaus")
    op = domain_set("OpenPhish")
    shared = uh & op

    return {
        "urlhaus_only":      len(uh - op),
        "openphish_only":    len(op - uh),
        "shared":            len(shared),
        "shared_examples":   sorted(shared)[:10],
        "urlhaus_total":     len(uh),
        "openphish_total":   len(op),
    }


# ── Finding 6 ─────────────────────────────────────────────────────────────────
def structural_stats(df: pd.DataFrame) -> dict:
    """
    Aggregate structural metrics across all URLs in the dataset.
    These can function as lightweight detection heuristics.
    """
    return {
        "avg_url_length":  round(df["url_length"].mean(), 1),
        "pct_ip_host":     round(df["is_ip_host"].mean() * 100, 1),
        "pct_has_query":   round(df["has_query"].mean() * 100, 1),
        "avg_path_depth":  round(df["path_depth"].mean(), 2),
        "pct_https":       round((df["scheme"] == "https").mean() * 100, 1),
        "pct_http":        round((df["scheme"] == "http").mean() * 100, 1),
    }


def path_depth_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Raw path-depth values for a histogram (returned as-is for Plotly)."""
    return df[["path_depth", "source"]].copy()


def url_length_distribution(df: pd.DataFrame) -> pd.DataFrame:
    return df[["url_length", "source"]].copy()
