"""Track latest known-exploited CVEs. Does not fetch or run exploit code."""

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SUMMARY_PATH = Path(__file__).resolve().parent / "summary.json"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def empty_summary():
    return {
        "fetched_at": None,
        "source": "cisa_kev",
        "count": 0,
        "items": [],
        "matched": [],
    }


def load_summary(path=None):
    path = Path(path) if path else SUMMARY_PATH
    if not path.exists() or path.stat().st_size == 0:
        return empty_summary()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return empty_summary()
    if not isinstance(data, dict):
        return empty_summary()
    data.setdefault("items", [])
    data.setdefault("matched", [])
    data.setdefault("count", len(data.get("items") or []))
    data.setdefault("source", "cisa_kev")
    return data


def save_summary(data, path=None):
    path = Path(path) if path else SUMMARY_PATH
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def parse_kev(payload, limit=25):
    vulns = list(payload.get("vulnerabilities") or [])
    items = []
    for entry in vulns[:limit]:
        items.append(
            {
                "cve_id": entry.get("cveID", ""),
                "vendor": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "name": entry.get("vulnerabilityName", ""),
                "date_added": entry.get("dateAdded", ""),
                "description": entry.get("shortDescription", ""),
            }
        )
    return items


def _tokens(values):
    tokens = set()
    for value in values:
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}", str(value).lower()):
            tokens.add(token)
    return tokens


def match_cves(items, fingerprints):
    marks = _tokens(fingerprints)
    if not marks:
        return []

    matched = []
    for item in items:
        haystack = _tokens(
            [
                item.get("vendor", ""),
                item.get("product", ""),
                item.get("name", ""),
                item.get("description", ""),
            ]
        )
        if marks & haystack:
            matched.append(item)
    return matched


def fetch_latest_cves(url=None, path=None, opener=None):
    url = url or CISA_KEV_URL
    opener = opener or urllib.request.urlopen
    try:
        with opener(url, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        cached = load_summary(path)
        cached.setdefault("matched", [])
        return cached

    items = parse_kev(payload)
    summary = {
        "fetched_at": _now(),
        "source": "cisa_kev",
        "count": len(items),
        "items": items,
        "matched": [],
    }
    return save_summary(summary, path)
