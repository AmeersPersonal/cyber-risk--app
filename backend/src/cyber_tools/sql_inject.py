"""Check source for unsafe SQL construction. Does not send injection payloads."""

import re

from report import finding

NAME = "sql_inject"
DESCRIPTION = (
    "Looks for string-built SQL in uploaded source. "
    "Does not send SQL injection payloads to a live site."
)

_UNSAFE = (
    re.compile(
        r"f['\"].*\b(SELECT|INSERT|UPDATE|DELETE|FROM)\b.*\{",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*['\"]\s*\+",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*%\s*\(",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\.(execute|executemany|raw)\(\s*f['\"]",
        re.IGNORECASE,
    ),
    re.compile(
        r"(cursor\.execute|connection\.execute)\([^)]*\+",
        re.IGNORECASE | re.DOTALL,
    ),
)

_SAFE = re.compile(
    r"\.(execute|executemany)\(\s*['\"][^'\"]+\?\s*['\"]|"
    r"%\s*\(\s*\w+\s*\)s|"
    r"parameterized|prepared statement|text\(\s*['\"].*:(\w+)",
    re.IGNORECASE,
)


def _line_hits(text):
    hits = []
    for index, line in enumerate(text.splitlines(), start=1):
        if any(pattern.search(line) for pattern in _UNSAFE):
            hits.append((index, line.strip()[:200]))
    return hits


def run(target):
    findings = []

    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live SQL injection tests are not run",
                "This tool only reviews uploaded source for unsafe query construction.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    files = target.get("files") or {}
    total_hits = 0
    for path, text in files.items():
        hits = _line_hits(text)
        total_hits += len(hits)
        for line_no, line in hits:
            findings.append(
                finding(
                    NAME,
                    "high",
                    "Possible string-built SQL",
                    "Use bound parameters instead of concatenating or interpolating SQL.",
                    f"{path}:{line_no}: {line}",
                )
            )

    if total_hits == 0:
        evidence = ""
        if any(_SAFE.search(text) for text in files.values()):
            evidence = "Parameterized query usage found."
        findings.append(
            finding(
                NAME,
                "info",
                "No string-built SQL found",
                "No concatenation or f-string SQL patterns were detected.",
                evidence,
            )
        )
        status = "pass"
    else:
        status = "fail"

    return {"tool": NAME, "status": status, "findings": findings}
