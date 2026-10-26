"""Fetch CVE metadata from CISA KEV, NIST NVD, and OSV for cross-checking.

Does not download or run exploit code.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SUMMARY_PATH = Path(__file__).resolve().parent / "summary.json"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NIST_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _now():
    return datetime.now(timezone.utc).isoformat()


def empty_summary():
    return {
        "fetched_at": None,
        "sources": [],
        "source": "multi",
        "count": 0,
        "items": [],
        "matched": [],
        "cross_check": {},
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
    data.setdefault("sources", [])
    data.setdefault("cross_check", {})
    data.setdefault("count", len(data.get("items") or []))
    data.setdefault("source", "multi")
    return data


def save_summary(data, path=None):
    path = Path(path) if path else SUMMARY_PATH
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def _http_json(url, opener, method="GET", body=None, headers=None, timeout=20):
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers=headers
        or {
            "User-Agent": "CyberRiskCouncil/1.0 (security-assessment; research)",
            "Accept": "application/json",
        },
    )
    with opener(request, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


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
                "cvss_score": None,
                "severity": "known_exploited",
                "sources": ["cisa_kev"],
            }
        )
    return items


def parse_nvd(payload, limit=25):
    items = []
    for entry in list(payload.get("vulnerabilities") or [])[:limit]:
        cve = entry.get("cve") or {}
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions") or []
        description = ""
        for item in descriptions:
            if item.get("lang") == "en":
                description = item.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        score = None
        severity = ""
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key) or []
            if not rows:
                continue
            data = (rows[0] or {}).get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or ""
            break

        vendor = ""
        product = ""
        for node in ((cve.get("configurations") or [{}])[0].get("nodes") or []):
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) > 4:
                    vendor = parts[3]
                    product = parts[4]
                    break
            if vendor:
                break

        items.append(
            {
                "cve_id": cve_id,
                "vendor": vendor,
                "product": product,
                "name": cve_id,
                "date_added": (cve.get("published") or "")[:10],
                "description": description[:500],
                "cvss_score": score,
                "severity": (severity or "").lower(),
                "sources": ["nist_nvd"],
            }
        )
    return items


def parse_osv(payload, limit=25):
    items = []
    for entry in list(payload.get("vulns") or [])[:limit]:
        aliases = entry.get("aliases") or []
        cve_id = next((item for item in aliases if str(item).startswith("CVE-")), "")
        if not cve_id:
            cve_id = entry.get("id", "")
        affected = entry.get("affected") or []
        package = ""
        ecosystem = ""
        if affected:
            pkg = (affected[0] or {}).get("package") or {}
            package = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", "")
        severity_score = None
        for row in entry.get("severity") or []:
            if row.get("type") == "CVSS_V3":
                # OSV often stores vector; leave score None unless numeric present
                severity_score = row.get("score") if isinstance(row.get("score"), (int, float)) else None
        items.append(
            {
                "cve_id": cve_id,
                "vendor": ecosystem,
                "product": package,
                "name": entry.get("id", cve_id),
                "date_added": (entry.get("published") or "")[:10],
                "description": (entry.get("summary") or "")[:500],
                "cvss_score": severity_score,
                "severity": "",
                "sources": ["osv"],
            }
        )
    return items


def _merge_items(groups):
    """Cross-check by CVE id; merge source lists and prefer NIST CVSS when present."""
    by_id = {}
    for group in groups:
        for item in group:
            cve_id = (item.get("cve_id") or "").strip()
            if not cve_id:
                continue
            if cve_id not in by_id:
                by_id[cve_id] = dict(item)
                by_id[cve_id]["sources"] = list(item.get("sources") or [])
                continue
            existing = by_id[cve_id]
            for source in item.get("sources") or []:
                if source not in existing["sources"]:
                    existing["sources"].append(source)
            if existing.get("cvss_score") is None and item.get("cvss_score") is not None:
                existing["cvss_score"] = item["cvss_score"]
            if not existing.get("severity") and item.get("severity"):
                existing["severity"] = item["severity"]
            if len(item.get("description") or "") > len(existing.get("description") or ""):
                existing["description"] = item["description"]
            for field in ("vendor", "product", "name"):
                if not existing.get(field) and item.get(field):
                    existing[field] = item[field]
    return list(by_id.values())


def cross_check_summary(items):
    confirmed = [item for item in items if len(item.get("sources") or []) >= 2]
    single = [item for item in items if len(item.get("sources") or []) == 1]
    by_source = {}
    for item in items:
        for source in item.get("sources") or []:
            by_source.setdefault(source, 0)
            by_source[source] += 1
    return {
        "total": len(items),
        "confirmed_by_multiple_sources": len(confirmed),
        "single_source": len(single),
        "by_source": by_source,
        "confirmed_ids": [item["cve_id"] for item in confirmed],
    }


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


def fetch_cisa_kev(opener, limit=25):
    payload = _http_json(CISA_KEV_URL, opener)
    return parse_kev(payload, limit=limit)


def fetch_nist_nvd(opener, limit=25):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    query = urllib.parse.urlencode(
        {
            "resultsPerPage": str(limit),
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        }
    )
    payload = _http_json(f"{NIST_NVD_URL}?{query}", opener, timeout=25)
    return parse_nvd(payload, limit=limit)


def fetch_osv_for_fingerprints(opener, fingerprints, limit=25):
    items = []
    seen = set()
    packages = []
    for mark in fingerprints or []:
        text = str(mark).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        name = text.split("==")[0].split("@")[0].strip()
        if name and len(name) > 1:
            packages.append(name)
        if len(packages) >= 5:
            break

    for name in packages:
        body = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}}).encode("utf-8")
        try:
            payload = _http_json(
                OSV_QUERY_URL,
                opener,
                method="POST",
                body=body,
                headers={
                    "User-Agent": "CyberRiskCouncil/1.0",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError):
            continue
        items.extend(parse_osv(payload, limit=max(1, limit // max(len(packages), 1))))
        if len(items) >= limit:
            break
    return items[:limit]


def fetch_latest_cves(path=None, opener=None, fingerprints=None, limit=25):
    """Fetch from CISA KEV, NIST NVD, and OSV; merge and cross-check by CVE id."""
    opener = opener or urllib.request.urlopen
    groups = []
    sources_ok = []
    errors = {}

    for name, loader in (
        ("cisa_kev", lambda: fetch_cisa_kev(opener, limit=limit)),
        ("nist_nvd", lambda: fetch_nist_nvd(opener, limit=limit)),
        ("osv", lambda: fetch_osv_for_fingerprints(opener, fingerprints or [], limit=limit)),
    ):
        try:
            groups.append(loader())
            sources_ok.append(name)
        except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError, KeyError) as exc:
            errors[name] = str(exc)

    if not groups:
        cached = load_summary(path)
        cached.setdefault("matched", [])
        cached.setdefault("errors", errors)
        return cached

    items = _merge_items(groups)
    summary = {
        "fetched_at": _now(),
        "source": "multi",
        "sources": sources_ok,
        "errors": errors,
        "count": len(items),
        "items": items,
        "matched": [],
        "cross_check": cross_check_summary(items),
    }
    return save_summary(summary, path)
