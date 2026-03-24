"""
debug.py
--------
Run with:  python debug.py
Prints exactly what each feed returns so we can see what's failing.
"""

import requests

HEADERS = {"User-Agent": "PhishingURLResearchProject/1.0"}

# ── Test 1: URLhaus CSV ────────────────────────────────────────────────────────
print("=" * 60)
print("TEST 1 — URLhaus CSV feed")
print("=" * 60)
try:
    r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=HEADERS, timeout=30)
    print(f"Status code : {r.status_code}")
    print(f"Content-Type: {r.headers.get('Content-Type')}")
    print(f"First 500 chars of response:")
    print(r.text[:500])
except Exception as e:
    print(f"ERROR: {e}")

print()

# ── Test 2: URLhaus JSON API ───────────────────────────────────────────────────
print("=" * 60)
print("TEST 2 — URLhaus JSON API (old endpoint)")
print("=" * 60)
try:
    r = requests.post(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        data={"limit": 3},
        headers=HEADERS,
        timeout=30,
    )
    print(f"Status code : {r.status_code}")
    print(f"Content-Type: {r.headers.get('Content-Type')}")
    print(f"First 300 chars: {r.text[:300]}")
except Exception as e:
    print(f"ERROR: {e}")

print()

# ── Test 3: OpenPhish ──────────────────────────────────────────────────────────
print("=" * 60)
print("TEST 3 — OpenPhish community feed")
print("=" * 60)
try:
    r = requests.get("https://openphish.com/feed.txt", headers=HEADERS, timeout=30)
    print(f"Status code : {r.status_code}")
    print(f"Content-Type: {r.headers.get('Content-Type')}")
    lines = [l for l in r.text.splitlines() if l.strip()]
    print(f"Total lines : {len(lines)}")
    print(f"First 3 lines:")
    for l in lines[:3]:
        print(f"  {l}")
except Exception as e:
    print(f"ERROR: {e}")

print()
print("Done. Paste the output above back to Claude.")