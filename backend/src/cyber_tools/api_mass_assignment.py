"""Check mass-assignment risks. Does not over-post to live APIs."""

import re

from report import finding

NAME = "api_mass_assignment"
DESCRIPTION = (
    "Looks for request bodies bound wholesale into models or updates. "
    "Does not over-post fields to a live API."
)

_RISKY = (
    re.compile(r"\.update\(\s*\*\*?(request\.|req\.|data|body|payload)", re.I),
    re.compile(r"Model\(\s*\*\*(request\.|req\.|data|kwargs)", re.I),
    re.compile(r"assign\([^)]*req\.body|Object\.assign\([^,]+,\s*req\.body", re.I),
    re.compile(r"serializer\.save\(\s*\*\*|update_fields\s*=\s*None", re.I),
)
_SAFE = re.compile(
    r"(allowlist|fields\s*=\s*\[|exclude\s*=|only\(|pick\(|select\()",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live mass-assignment tests are not run",
                "This tool only reviews uploaded source for wholesale request binding.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    status = "pass"
    hits = []
    for path, text in (target.get("files") or {}).items():
        for index, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in _RISKY) and not _SAFE.search(line):
                hits.append(f"{path}:{index}: {line.strip()[:200]}")

    if hits:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Possible mass assignment",
                "Bind only allowlisted fields from request bodies into models.",
                hits[0],
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "No mass-assignment patterns found",
                "No wholesale request-to-model binding patterns were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
