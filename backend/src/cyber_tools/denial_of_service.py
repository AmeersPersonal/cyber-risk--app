"""Check DoS hardening signals. Does not flood or exhaust services."""

import re

from report import finding

NAME = "denial_of_service"
DESCRIPTION = (
    "Looks for missing rate limits and expensive unbounded work in source or headers. "
    "Does not flood, slow-loris, or exhaust a live service."
)

_RATE = re.compile(
    r"(rate[_-]?limit|throttle|SlowAPI|flask_limiter|aiolimiter|leaky[_-]?bucket)",
    re.I,
)
_EXPENSIVE = re.compile(
    r"(while\s+True|for\s+\w+\s+in\s+range\(\s*\d{6,}|recursive|zipfile\.extractall|"
    r"xml\.etree|pickle\.loads)",
    re.I,
)


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        headers = (target.get("http") or {}).get("headers") or {}
        if headers.get("retry-after") or headers.get("x-ratelimit-limit"):
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Rate-limit headers present",
                    "The response advertises rate limiting.",
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "low",
                    "No rate-limit headers on this response",
                    "Consider rate limiting public endpoints.",
                    target.get("url", ""),
                )
            )
            status = "fail"
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    expensive = []
    for path, text in files.items():
        for index, line in enumerate(text.splitlines(), start=1):
            if _EXPENSIVE.search(line):
                expensive.append(f"{path}:{index}: {line.strip()[:200]}")

    if not _RATE.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "No rate limiting found in source",
                "Add throttling on authentication and other expensive public routes.",
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "Rate limiting references found",
                "Source mentions rate limiting or throttling.",
            )
        )

    if expensive:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Possibly expensive unbounded work",
                "Bound loops, uploads, and recursive or costly parsers.",
                expensive[0],
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No DoS markers found",
                "No missing rate-limit or expensive-work patterns were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
