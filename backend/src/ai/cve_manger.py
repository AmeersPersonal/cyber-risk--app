"""Fetch CVE metadata from CISA KEV, NIST NVD, and OSV for cross-checking.

Does not download or run exploit code.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from packaging.version import InvalidVersion, Version

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


def _norm_ecosystem(value):
    text = str(value or "").strip().lower()
    if text in {"pypi", "pip"}:
        return "pypi"
    if text in {"npm", "node"}:
        return "npm"
    if text in {"go", "golang"}:
        return "go"
    return text


def _norm_name(name, ecosystem):
    text = str(name or "").strip()
    if ecosystem == "pypi":
        return text.lower().replace("_", "-")
    return text


def _parse_version(value):
    text = str(value or "").strip()
    if text in {"", "0"}:
        return Version("0")
    if text[0] in "vV":
        text = text[1:]
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _cmp_version(left, right):
    parsed_left = _parse_version(left)
    parsed_right = _parse_version(right)
    if parsed_left is None or parsed_right is None:
        return None
    return (parsed_left > parsed_right) - (parsed_left < parsed_right)


def _events_include(version, events):
    affected = False
    saw = False
    for event in events or []:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            saw = True
            compared = _cmp_version(version, event.get("introduced"))
            if compared is not None and compared >= 0:
                affected = True
        elif "fixed" in event:
            saw = True
            compared = _cmp_version(version, event.get("fixed"))
            if compared is not None and compared >= 0:
                affected = False
        elif "last_affected" in event:
            saw = True
            compared = _cmp_version(version, event.get("last_affected"))
            if compared is not None and compared > 0:
                affected = False
        elif "limit" in event:
            saw = True
            compared = _cmp_version(version, event.get("limit"))
            if compared is not None and compared >= 0:
                affected = False
    return affected if saw else False


def package_is_affected(item, package):
    """True when this package version sits inside the CVE's affected range."""
    ecosystem = _norm_ecosystem(package.get("ecosystem"))
    name = _norm_name(package.get("name"), ecosystem)
    version = str(package.get("version") or "")
    if not name or not version:
        return False
    for entry in item.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package") or {}
        entry_name = _norm_name(pkg.get("name"), ecosystem)
        entry_eco = _norm_ecosystem(pkg.get("ecosystem") or item.get("vendor") or "")
        if not entry_name or entry_name != name:
            continue
        if entry_eco and entry_eco != ecosystem:
            continue
        listed = {str(value).lstrip("vV") for value in entry.get("versions") or []}
        if version in listed:
            return True
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            if rng.get("type") not in {None, "", "ECOSYSTEM", "SEMVER"}:
                continue
            if _events_include(version, rng.get("events") or []):
                return True
    return False


def match_cves(items, packages):
    """Keep a CVE only when a parsed package version is inside its affected range.

    Name overlap is not enough. Fingerprint strings are ignored.
    """
    if not packages or isinstance(packages[0], str):
        return []
    found = []
    seen = set()
    for item in items or []:
        cve_id = item.get("cve_id") or ""
        if not cve_id or cve_id in seen:
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            if not package_is_affected(item, package):
                continue
            matched = dict(item)
            matched["version_confirmed"] = True
            matched["matched_package"] = package.get("name")
            matched["matched_version"] = package.get("version")
            matched["matched_ecosystem"] = package.get("ecosystem")
            matched["kev"] = "cisa_kev" in (matched.get("sources") or [])
            found.append(matched)
            seen.add(cve_id)
            break
    return found


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


def fetch_kev_ids(opener):
    payload = _http_json(CISA_KEV_URL, opener)
    return {
        entry.get("cveID")
        for entry in (payload.get("vulnerabilities") or [])
        if entry.get("cveID")
    }


def query_osv_version(opener, package, limit=15):
    body = json.dumps(
        {
            "package": {"name": package["name"], "ecosystem": package["ecosystem"]},
            "version": package["version"],
        }
    ).encode("utf-8")
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
    items = []
    for entry in list(payload.get("vulns") or [])[:limit]:
        if isinstance(entry, dict):
            items.append(_osv_item(entry, package))
    return items


def _numeric_cvss(entry):
    for row in entry.get("severity") or []:
        score = row.get("score")
        if isinstance(score, (int, float)):
            return float(score)
    specific = entry.get("database_specific") or {}
    for key in ("cvss_score", "cvss"):
        score = specific.get(key)
        if isinstance(score, (int, float)):
            return float(score)
    return None


def _osv_item(entry, package):
    aliases = entry.get("aliases") or []
    cve_id = next((item for item in aliases if str(item).startswith("CVE-")), "")
    if not cve_id:
        cve_id = entry.get("id", "")
    affected = []
    for row in entry.get("affected") or []:
        if not isinstance(row, dict):
            continue
        affected.append(
            {
                "package": (row.get("package") or {}),
                "ranges": row.get("ranges") or [],
                "versions": row.get("versions") or [],
            }
        )
    if not affected:
        affected = [
            {
                "package": {"name": package["name"], "ecosystem": package["ecosystem"]},
                "ranges": [],
                "versions": [package["version"]],
            }
        ]
    return {
        "cve_id": cve_id,
        "vendor": package.get("ecosystem", ""),
        "product": package.get("name", ""),
        "name": entry.get("id", cve_id),
        "date_added": (entry.get("published") or "")[:10],
        "description": (entry.get("summary") or "")[:500],
        "cvss_score": _numeric_cvss(entry),
        "severity": "",
        "sources": ["osv"],
        "affected": affected,
    }


def fetch_latest_cves(path=None, opener=None, fingerprints=None, packages=None, limit=25):
    """Query OSV for exact package versions and badge hits that are also in CISA KEV.

    A CVE is stored only when OSV returns it for that version. Bulk name overlap
    against NVD or KEV is not used. `fingerprints` is accepted and ignored.
    """
    del fingerprints
    opener = opener or urllib.request.urlopen
    packages = [item for item in (packages or []) if isinstance(item, dict)][:15]
    errors = {}
    sources_ok = []
    kev = set()
    try:
        kev = fetch_kev_ids(opener)
        sources_ok.append("cisa_kev")
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError, KeyError) as exc:
        errors["cisa_kev"] = str(exc)

    groups = []
    if packages:
        try:
            osv_items = []
            for package in packages:
                try:
                    osv_items.extend(query_osv_version(opener, package, limit=limit))
                except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError, KeyError) as exc:
                    errors[f"osv:{package.get('name')}"] = str(exc)
            if osv_items or "osv" not in errors:
                sources_ok.append("osv")
            groups.append(osv_items)
        except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError, KeyError) as exc:
            errors["osv"] = str(exc)

    if not groups and not sources_ok:
        cached = load_summary(path)
        cached.setdefault("matched", [])
        cached.setdefault("errors", errors)
        return cached

    items = _merge_items(groups)
    for item in items:
        if item.get("cve_id") in kev and "cisa_kev" not in (item.get("sources") or []):
            item.setdefault("sources", []).append("cisa_kev")
            item["kev"] = True
    summary = {
        "fetched_at": _now(),
        "source": "version_matched",
        "sources": sources_ok,
        "errors": errors,
        "count": len(items),
        "items": items,
        "packages": packages,
        "matched": [],
        "cross_check": cross_check_summary(items),
    }
    return save_summary(summary, path)
