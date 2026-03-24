Phishing URL Analysis — Academy Project
========================================

WHAT IT DOES
------------
Pulls live malicious URL data from two open threat-intelligence feeds
(URLhaus and OpenPhish), normalises them into a single dataset, extracts
structural URL features, and displays an interactive analysis dashboard
built with Streamlit.

Six findings are reported:
  1. URL takedown status distribution (online / offline / unknown)
  2. Threat / malware-family breakdown across feeds
  3. Daily URL arrival rates over time (burst detection)
  4. Most-abused TLDs and registered domains
  5. Cross-feed domain overlap (high-confidence IOC corroboration)
  6. URL structural fingerprint (length, path depth, HTTPS, IP-hosting)


FILES
-----
  app.py           — Streamlit entry point; all chart/layout code lives here
  collector.py     — Fetches raw data from URLhaus API and OpenPhish feed
  processor.py     — Merges, deduplicates, and enriches with URL features
  analyzer.py      — Pure analysis functions (no I/O, easy to unit-test)
  requirements.txt — Python dependencies
  readme.txt       — This file


HOW TO RUN
----------
1. Create and activate a virtual environment (recommended):

     python -m venv venv
     source venv/bin/activate        # Windows: venv\Scripts\activate

2. Install dependencies:

     pip install -r requirements.txt

3. Launch the dashboard:

     streamlit run app.py

   Streamlit will open a browser tab automatically (default: localhost:8501).

4. Use the sidebar filters to slice by feed source or URL scheme.
   Data is cached for 60 minutes; reload the page to force a refresh.


DATA SOURCES
------------
- URLhaus  (https://urlhaus.abuse.ch/)
    Public JSON API, no authentication required.
    Returns up to 1 000 recent malicious URLs with metadata:
    status, threat label, tags, IP address, timestamp.

- OpenPhish (https://openphish.com/)
    Plain-text community feed, one URL per line, no auth required.
    No per-URL timestamps in the free tier — all rows are stamped
    with the fetch time (noted in the dashboard caption).


DEPENDENCIES
------------
  streamlit   — dashboard framework
  pandas      — data wrangling
  plotly      — interactive charts
  requests    — HTTP calls to APIs / feeds
  tldextract  — reliable TLD / registered-domain parsing


SAFETY NOTES
------------
- URLs are never visited, clicked, or fetched — only their string
  structure is analysed.
- No personal data is collected or stored.
- Data is held in-memory only; no CSV files are written to disk.
- Rate limits and Terms of Service for both feeds are respected.
