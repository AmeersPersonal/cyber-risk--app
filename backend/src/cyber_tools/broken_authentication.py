"""Check authentication hardening signals. Does not crack or bypass auth."""

import re

from report import finding

NAME = "broken_authentication"
DESCRIPTION = (
    "Checks password handling, auth routes, and MFA references in source or headers. "
    "Does not crack credentials or bypass authentication."
)

_WEAK = (
    re.compile(r"md5\s*\(.*password|password.*md5", re.I),
    re.compile(r"sha1\s*\(.*password|password.*sha1", re.I),
    re.compile(r"password\s*=\s*['\"][^'\"]+['\"]", re.I),
    re.compile(r"jwt\.encode\([^)]*alg['\"]?\s*:\s*['\"]none['\"]", re.I),
)
_GOOD = re.compile(
    r"(bcrypt|argon2|scrypt|pbkdf2|mfa|totp|2fa|multi[_-]?factor)",
    re.I,
)
_AUTH_ROUTE = re.compile(r"(login|signin|oauth|password[_-]?reset)", re.I)


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        headers = (target.get("http") or {}).get("headers") or {}
        www = headers.get("www-authenticate", "")
        if www.lower().startswith("basic"):
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "HTTP Basic authentication advertised",
                    "Prefer modern session or token auth over Basic on public sites.",
                    www[:200],
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "No Basic auth challenge on this response",
                    "Authentication quality still depends on login and session design.",
                    target.get("url", ""),
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    weak_hits = []
    for path, text in files.items():
        for index, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in _WEAK):
                weak_hits.append(f"{path}:{index}: {line.strip()[:200]}")

    if weak_hits:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Weak authentication handling pattern",
                "Use a modern password hash and avoid hard-coded credentials.",
                weak_hits[0],
            )
        )
    if _AUTH_ROUTE.search(blob) and not _GOOD.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Auth routes without strong hash or MFA signals",
                "Use bcrypt/argon2 and consider MFA on authentication flows.",
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No weak authentication patterns found",
                "No hard-coded passwords or weak password hashes were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
