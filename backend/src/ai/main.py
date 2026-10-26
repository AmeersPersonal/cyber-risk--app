"""Run a threat analysis through the Meterless council + Zetaris intel."""

import io
import ssl
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

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
}


def fetch_url(url, opener=None):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("only http and https urls are allowed")

    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "CyberRiskSafeScanner/1.0"},
    )
    opener = opener or (
        lambda req: urllib.request.urlopen(
            req, timeout=12, context=ssl.create_default_context()
        )
    )
    with opener(request) as resp:
        body = resp.read(200_000).decode("utf-8", errors="replace")
        headers = {key.lower(): value for key, value in resp.headers.items()}
        return {
            "url": url,
            "status": getattr(resp, "status", 200),
            "headers": headers,
            "body": body,
        }


def files_from_zip(data):
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > 1_000_000:
                continue
            suffix = Path(info.filename).suffix.lower()
            if suffix not in SOURCE_SUFFIXES:
                continue
            files[info.filename] = archive.read(info).decode("utf-8", errors="replace")
    return files


def _prepare_target(target, fetcher=None):
    prepared = dict(target)
    if prepared.get("kind") == "url" and "http" not in prepared:
        prepared["http"] = (fetcher or fetch_url)(prepared["url"])
    prepared.setdefault("files", {})
    return prepared


def run_scan(target, fetcher=None, cve_source=None, council=None, company_hint=""):
    prepared = _prepare_target(target, fetcher=fetcher)
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
    return report
