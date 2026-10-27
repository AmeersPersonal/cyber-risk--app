"""Hackathon data and security rules.

Section 11.1 lists data this project may use. Section 11.2 lists data it must
refuse. Checks here do not fetch restricted data, store credentials, or run
exploit code.
"""

import re


class DataNotPermitted(Exception):
    """The data source is outside the hackathon data rules."""


PERMITTED = (
    "Publicly available datasets with appropriate licences",
    "Small static datasets committed to the repository",
    "Automated download scripts that need no login or manual steps",
    "Public APIs called at runtime",
    "Synthetic or simulated data, clearly identified",
)

NOT_PERMITTED = (
    "Confidential, proprietary or restricted data the participant is not authorised to use",
    "Personal data without authorisation and appropriate safeguards",
    "Committed API keys, passwords, tokens, certificates or credentials",
    "Datasets used in breach of their licence terms",
    "Malware, exploit code, credential harvesting or harmful automation",
)

PERMITTED_KINDS = frozenset(
    {
        "public_dataset",
        "static_dataset",
        "download_script",
        "public_api",
        "synthetic",
    }
)

BANNED_KINDS = frozenset(
    {
        "malware",
        "exploit",
        "exploit_code",
        "credential_harvesting",
        "harmful_automation",
    }
)

MAX_STATIC_DATASET_BYTES = 1_000_000

SYNTHETIC_NOTICE = "Synthetic or simulated data."

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN CERTIFICATE-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-(?:live|proj|ant)-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(
        r"""(?i)(?:api[_-]?key|password|secret|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]"""
    ),
)

# Sources this repository actually uses. Each one must pass section 11.
PROJECT_SOURCES = {
    "cisa_kev": {
        "kind": "public_api",
        "name": "CISA Known Exploited Vulnerabilities",
        "licence": "public-domain",
        "login": False,
    },
    "nist_nvd": {
        "kind": "public_api",
        "name": "NIST National Vulnerability Database",
        "licence": "public-domain",
        "login": False,
    },
    "osv": {
        "kind": "public_api",
        "name": "OSV",
        "licence": "Apache-2.0",
        "login": False,
    },
    "cve_knowledge": {
        "kind": "static_dataset",
        "name": "Local CVE knowledge",
        "licence": "public-domain",
        "note": "Small static summaries of public CVE records. No exploit steps.",
    },
    "setup_zetaris": {
        "kind": "download_script",
        "name": "Zetaris CVE seed",
        "login": False,
        "manual_steps": False,
        "note": "Downloads the public CVE APIs. No login and no manual step.",
    },
    "zetaris_cve_items": {
        "kind": "public_dataset",
        "name": "Local copy of the public CVE catalog",
        "licence": "public-domain",
        "note": "Queried locally after the public download. Not a private feed.",
    },
    "aegis_demo": {
        "kind": "synthetic",
        "name": "Aegis demo analyses",
        "identified": True,
        "notice": SYNTHETIC_NOTICE,
    },
}


def _licence(source):
    return str(source.get("licence") or source.get("license") or "").strip()


def _flag(source, key):
    return source.get(key) is True


def reject_committed_secrets(text):
    """Refuse API keys, passwords, tokens, and certificates in committed data."""
    sample = str(text or "")
    for pattern in _SECRET_PATTERNS:
        if pattern.search(sample):
            raise DataNotPermitted(NOT_PERMITTED[2])
    return sample


def assert_permitted(source):
    """Allow a section 11.1 source. Refuse a section 11.2 source."""
    if not isinstance(source, dict):
        raise DataNotPermitted("A data source must name its kind and licence.")
    kind = str(source.get("kind") or "").strip()
    if kind in BANNED_KINDS or _flag(source, "harmful"):
        raise DataNotPermitted(NOT_PERMITTED[4])
    if _flag(source, "restricted") and not _flag(source, "authorized"):
        raise DataNotPermitted(NOT_PERMITTED[0])
    if _flag(source, "personal_data") and not (
        _flag(source, "authorized") and _flag(source, "safeguards")
    ):
        raise DataNotPermitted(NOT_PERMITTED[1])
    if _flag(source, "committed_secret") or _flag(source, "contains_credentials"):
        raise DataNotPermitted(NOT_PERMITTED[2])
    if _flag(source, "license_breach"):
        raise DataNotPermitted(NOT_PERMITTED[3])

    if kind == "public_dataset":
        if not _licence(source):
            raise DataNotPermitted(PERMITTED[0])
        return source
    if kind == "static_dataset":
        size = source.get("size_bytes")
        if size is not None and int(size) > MAX_STATIC_DATASET_BYTES:
            raise DataNotPermitted(PERMITTED[1])
        return source
    if kind == "download_script":
        if _flag(source, "login") or _flag(source, "manual_steps"):
            raise DataNotPermitted(PERMITTED[2])
        return source
    if kind == "public_api":
        if _flag(source, "login"):
            raise DataNotPermitted(PERMITTED[3])
        return source
    if kind == "synthetic":
        notice = str(source.get("notice") or "")
        identified = _flag(source, "identified") or (
            "synthetic" in notice.lower() or "simulated" in notice.lower()
        )
        if not identified:
            raise DataNotPermitted(PERMITTED[4])
        return source
    raise DataNotPermitted("That data source is not on the permitted list.")


def permit_project_source(name):
    """Check one source this repository uses."""
    source = PROJECT_SOURCES.get(name)
    if source is None:
        raise DataNotPermitted("That data source is not on the permitted list.")
    return assert_permitted(source)


def assert_static_dataset_text(text, name="cve_knowledge"):
    """A committed dataset must stay small, secret-free, and on the permitted list."""
    permit_project_source(name)
    if len(str(text or "").encode("utf-8")) > MAX_STATIC_DATASET_BYTES:
        raise DataNotPermitted(PERMITTED[1])
    return reject_committed_secrets(text)
