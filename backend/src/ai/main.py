"""Run a threat analysis through the Meterless council + Zetaris intel."""

import io
import ssl
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from ai import cve_manger
from ai.council import ThreatCouncil
from cyber_tools.pen_test import fingerprints_from_target
from report import build_report

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

    summary = cve_source if cve_source is not None else cve_manger.fetch_latest_cves()
    matched = cve_manger.match_cves(summary.get("items") or [], fingerprints)
    cves = {
        "fetched_at": summary.get("fetched_at"),
        "source": summary.get("source"),
        "count": summary.get("count", 0),
        "matched": matched,
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
