"""Check TLS and HSTS signals. Does not probe old protocol versions."""

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from report import finding

NAME = "tls_posture"
DESCRIPTION = (
    "Checks HSTS max-age, certificate expiry on the fetched connection, and disabled TLS verification in source. "
    "Does not probe old protocol versions."
)

_HSTS = re.compile(r"max-age\s*=\s*(\d+)", re.I)
_MIN_AGE = 15552000
_WEAK_PROTO = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
_WEAK_SOURCE = re.compile(
    r"(PROTOCOL_TLSv1\b|PROTOCOL_SSLv|CERT_NONE|verify\s*=\s*False|"
    r"check_hostname\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"])",
    re.I,
)


def _headers(target):
    raw = (target.get("http") or {}).get("headers") or {}
    return {str(key).lower(): value for key, value in raw.items()}


def _expired(value):
    try:
        expiry = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry <= datetime.now(timezone.utc)


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        headers = _headers(target)
        hsts = headers.get("strict-transport-security") or ""
        match = _HSTS.search(hsts)
        if not match:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "low",
                    "HSTS max-age is missing",
                    "Send Strict-Transport-Security with a max-age of at least 180 days.",
                    target.get("url", ""),
                )
            )
        elif int(match.group(1)) < _MIN_AGE:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "low",
                    "HSTS max-age is shorter than 180 days",
                    "Raise the HSTS max-age to at least 180 days.",
                    hsts[:200],
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "HSTS max-age covers at least 180 days",
                    "The fetched response sets a long HSTS lifetime.",
                )
            )
        tls = (target.get("http") or {}).get("tls") or {}
        protocol = str(tls.get("protocol") or "")
        if protocol in _WEAK_PROTO:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Fetched connection used an old TLS protocol",
                    "Serve the site with TLS 1.2 or newer.",
                    protocol,
                )
            )
        if tls.get("not_after") and _expired(tls.get("not_after")):
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "high",
                    "TLS certificate is expired",
                    "Renew the certificate served on this connection.",
                    str(tls.get("not_after"))[:200],
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    blob = "\n".join((target.get("files") or {}).values())
    if _WEAK_SOURCE.search(blob):
        findings.append(
            finding(
                NAME,
                "high",
                "TLS verification or protocol is weakened in source",
                "Keep certificate verification on and use TLS 1.2 or newer.",
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if not blob.strip():
        findings.append(
            finding(
                NAME,
                "info",
                "No source available for TLS review",
                "No uploaded source was available to check TLS settings.",
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No weakened TLS settings found",
            "Source does not disable certificate checks or select an old protocol.",
        )
    )
    return {"tool": NAME, "status": "pass", "findings": findings}
