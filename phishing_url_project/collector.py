"""
collector.py
------------
Fetches raw malicious URL data from two open threat-intelligence feeds:

  - URLhaus  (abuse.ch) — public CSV download, no auth required
  - OpenPhish (community feed) — plain-text feed, one URL per line
"""

import logging
from datetime import datetime, timezone
from io import StringIO
from urllib.parse import urlparse

import pandas as pd
import requests

logger = logging.getLogger(__name__)

URLHAUS_CSV    = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

SHARED_HEADERS = {
    "User-Agent": "PhishingURLResearchProject/1.0 (academy security analysis)"
}

SCHEMA = [
    "url", "host", "ip_address", "url_status",
    "date_added", "threat", "tags", "source",
]


def fetch_urlhaus(limit: int = 1000) -> pd.DataFrame:
    """
    Download URLhaus CSV export (no auth required).
    The header row looks like '# id,dateadded,url,...' so we cannot simply
    drop all '#' lines — we detect and clean that header specifically.
    """
    logger.info("Fetching URLhaus CSV feed ...")

    resp = requests.get(URLHAUS_CSV, headers=SHARED_HEADERS, timeout=30)
    resp.raise_for_status()

    header_line = None
    data_lines  = []

    for line in resp.text.splitlines():
        clean = line.lstrip("#").strip()
        if clean.startswith("id,"):
            header_line = clean          # found the CSV header
        elif line.startswith("#") or not line.strip():
            continue                     # skip pure comments / blanks
        else:
            data_lines.append(line)

    if header_line is None:
        raise RuntimeError(
            "URLhaus CSV header not found. First 300 chars: " + resp.text[:300]
        )

    raw = pd.read_csv(StringIO(header_line + "\n" + "\n".join(data_lines)), quotechar='"')
    raw.columns = raw.columns.str.strip()
    logger.info("URLhaus CSV columns: %s", list(raw.columns))

    records = []
    for _, row in raw.head(limit).iterrows():
        url  = str(row.get("url", "")).strip()
        host = urlparse(url).netloc if url.startswith("http") else ""
        records.append({
            "url":        url,
            "host":       host,
            "ip_address": None,
            "url_status": str(row.get("url_status", "unknown")).strip(),
            "date_added": _parse_ts(str(row.get("dateadded", ""))),
            "threat":     str(row.get("threat", "unknown")).strip() or "unknown",
            "tags":       str(row.get("tags", "")).strip(),
            "source":     "URLhaus",
        })

    df = pd.DataFrame(records, columns=SCHEMA)
    logger.info("URLhaus: %d records loaded", len(df))
    return df


def _parse_ts(raw: str):
    if not raw or raw.lower() in ("nan", "none", ""):
        return None
    try:
        return datetime.strptime(raw.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fetch_openphish() -> pd.DataFrame:
    logger.info("Fetching OpenPhish community feed ...")

    resp = requests.get(OPENPHISH_FEED, headers=SHARED_HEADERS, timeout=30)
    resp.raise_for_status()

    urls = [l.strip() for l in resp.text.splitlines() if l.strip().lower().startswith("http")]
    fetch_time = datetime.now(tz=timezone.utc)

    records = []
    for url in urls:
        parsed = urlparse(url)
        records.append({
            "url":        url,
            "host":       parsed.netloc,
            "ip_address": None,
            "url_status": "online",
            "date_added": fetch_time,
            "threat":     "phishing",
            "tags":       "",
            "source":     "OpenPhish",
        })

    df = pd.DataFrame(records, columns=SCHEMA)
    logger.info("OpenPhish: %d records loaded", len(df))
    return df