"""
processor.py
------------
Takes raw DataFrames from collector.py and produces one clean, enriched
dataset ready for analysis.

Per-URL structural features extracted here:
  scheme, registered_domain, tld, subdomain_depth,
  path_depth, url_length, has_query, is_ip_host
"""

import re
import logging
from urllib.parse import urlparse

import pandas as pd
import tldextract

logger = logging.getLogger(__name__)

# IPv4 pattern used to detect IP-based hosting (a red flag in phishing)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _extract_url_features(url: str) -> dict:
    """
    Pull structural properties out of a single URL string.
    All failures are caught so one bad URL can't crash the whole pipeline.
    """
    try:
        parsed = urlparse(url)
        ext    = tldextract.extract(url)

        # netloc can contain a port — strip it before the IP check
        netloc_no_port = parsed.netloc.split(":")[0]
        is_ip = bool(_IPV4_RE.match(netloc_no_port))

        path_segments = [p for p in parsed.path.split("/") if p]

        return {
            "scheme":            parsed.scheme,
            "registered_domain": ext.registered_domain or netloc_no_port,
            "tld":               ext.suffix or "",
            "subdomain_depth":   len(ext.subdomain.split(".")) if ext.subdomain else 0,
            "path_depth":        len(path_segments),
            "url_length":        len(url),
            "has_query":         bool(parsed.query),
            "is_ip_host":        is_ip,
        }
    except Exception as exc:                          # noqa: BLE001
        logger.debug("Feature extraction failed for %r: %s", url[:80], exc)
        return {
            "scheme":            None,
            "registered_domain": "",
            "tld":               "",
            "subdomain_depth":   0,
            "path_depth":        0,
            "url_length":        len(url) if url else 0,
            "has_query":         False,
            "is_ip_host":        False,
        }


def build_dataset(*frames: pd.DataFrame) -> pd.DataFrame:
    """
    Merge any number of source DataFrames, deduplicate on the raw URL,
    and append per-URL structural features.

    Returns a single, analysis-ready DataFrame.
    """
    combined = pd.concat(frames, ignore_index=True)

    before = len(combined)
    combined = combined.drop_duplicates(subset=["url"])
    dupes = before - len(combined)
    if dupes:
        logger.info("Dropped %d duplicate URL(s) across feeds", dupes)

    # parse timestamps to a consistent tz-aware datetime
    combined["date_added"] = pd.to_datetime(
        combined["date_added"], utc=True, errors="coerce"
    )

    # extract structural features (this is the most expensive step)
    logger.info("Extracting URL features for %d rows …", len(combined))
    features = combined["url"].apply(lambda u: pd.Series(_extract_url_features(u)))
    combined = pd.concat([combined.reset_index(drop=True), features], axis=1)

    logger.info("Dataset ready: %d rows, %d columns", *combined.shape)
    return combined
