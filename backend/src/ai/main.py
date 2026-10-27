"""Run a threat analysis through the Meterless council + Zetaris intel."""

import io
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import safety
from ai import cve_manger
from ai.council import ThreatCouncil
from ai.manifests import packages_from_files
from ai.cve_knowledge import (
    initialize_cve_knowledge,
    load_all_cve_knowledge,
    load_cve_entry,
)
from cyber_tools.pen_test import fingerprints_from_target
from report import build_report

# Seed local common CVE list and zero_days/<cve_name>.json files on startup.
initialize_cve_knowledge()

SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".html",
    ".htm",
    ".json",
    ".txt",
    ".mod",
    ".tf",
    ".yml",
    ".yaml",
    ".hcl",
}

_EXTRA_NAMES = {"dockerfile"}


def _tls_facts(resp):
    """Read protocol and certificate expiry from the connection already open."""
    facts = {}
    raw = getattr(getattr(resp, "fp", None), "raw", None)
    sock = getattr(raw, "_sock", None) if raw is not None else None
    if sock is None:
        return facts
    version = getattr(sock, "version", None)
    if callable(version):
        try:
            facts["protocol"] = version() or ""
        except (OSError, ValueError, AttributeError):
            pass
    getpeercert = getattr(sock, "getpeercert", None)
    if callable(getpeercert):
        try:
            cert = getpeercert() or {}
        except (OSError, ValueError, AttributeError):
            cert = {}
        not_after = cert.get("notAfter") if isinstance(cert, dict) else None
        if not_after:
            facts["not_after"] = not_after
    return facts


def fetch_url(url, opener=None, resolve=None):
    safety.check_url(url, resolve=resolve)

    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "CyberRiskSafeScanner/1.0"},
    )
    opener = opener or safety.safe_urlopen(resolve=resolve)
    with opener(request) as resp:
        body = resp.read(200_000).decode("utf-8", errors="replace")
        headers = {key.lower(): value for key, value in resp.headers.items()}
        http = {
            "url": url,
            "status": getattr(resp, "status", 200),
            "headers": headers,
            "body": body,
        }
        tls = _tls_facts(resp)
        if tls:
            http["tls"] = tls
        return http


def files_from_zip(data):
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > 1_000_000:
                continue
            suffix = Path(info.filename).suffix.lower()
            name = Path(info.filename).name.lower()
            if suffix not in SOURCE_SUFFIXES and name not in _EXTRA_NAMES:
                continue
            files[info.filename] = archive.read(info).decode("utf-8", errors="replace")
    return files


def _prepare_target(target, fetcher=None):
    prepared = dict(target)
    if prepared.get("kind") == "url" and "http" not in prepared:
        prepared["http"] = (fetcher or fetch_url)(prepared["url"])
    prepared.setdefault("files", {})
    return prepared


def run_scan(
    target,
    fetcher=None,
    cve_source=None,
    council=None,
    company_hint="",
    stay_inspect=False,
    ownership_token="",
    ownership_store=None,
):
    safety.gate_before_agents(
        target,
        claimed_owner=company_hint,
        token=ownership_token,
        store=ownership_store,
    )
    prepared = _prepare_target(target, fetcher=fetcher)
    prepared["stay_inspect"] = bool(stay_inspect)
    fingerprints = fingerprints_from_target(prepared)
    packages = packages_from_files(prepared.get("files") or {})
    fingerprints.extend(
        f"{item['name']}=={item['version']}" for item in packages
    )

    summary = (
        cve_source
        if cve_source is not None
        else cve_manger.fetch_latest_cves(packages=packages, fingerprints=fingerprints)
    )
    matched = cve_manger.match_cves(summary.get("items") or [], packages)
    local_entries = load_all_cve_knowledge()
    local_map = {entry["cve_name"]: entry for entry in local_entries}
    for item in matched:
        cve_id = item.get("cve_id")
        if cve_id and cve_id not in local_map:
            entry = load_cve_entry(cve_id)
            if entry:
                local_map[cve_id] = entry
    cves = {
        "fetched_at": summary.get("fetched_at"),
        "source": summary.get("source"),
        "sources": summary.get("sources")
        or ([summary["source"]] if summary.get("source") else []),
        "count": summary.get("count", 0),
        "items": summary.get("items") or [],
        "matched": matched,
        "cross_check": summary.get("cross_check")
        or cve_manger.cross_check_summary(summary.get("items") or []),
        "local_knowledge": local_map,
        "local_cve_count": len(local_map),
    }

    board = council or ThreatCouncil()
    session = board.analyze(
        prepared,
        company_hint=company_hint or prepared.get("url") or "uploaded-source",
        fingerprints=fingerprints,
    )

    report = build_report(
        session["tool_results"],
        cves,
        council={
            "debate": session["debate"],
            "memory": session["memory"],
            "intel": session["intel"],
            "engines": session["engines"],
        },
    )
    report["target"] = {
        "kind": prepared.get("kind"),
        "url": prepared.get("url"),
        "file_count": len(prepared.get("files") or {}),
        "company": company_hint or prepared.get("url") or "uploaded-source",
    }
    report["stay_inspect"] = bool(stay_inspect)
    return report
