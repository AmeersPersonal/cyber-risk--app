"""Check source for unsafe injection sinks. Does not send injection payloads."""

import re

from report import finding

NAME = "injection"
DESCRIPTION = (
    "Looks for string-built SQL, shell, NoSQL, and LDAP queries in source. "
    "Does not send injection payloads to a live site."
)

_PATTERNS = (
    (
        "sql",
        re.compile(
            r"(execute|executemany|raw)\(\s*f['\"]|"
            r"['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*['\"]\s*\+|"
            r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*%\s*\(",
            re.I | re.S,
        ),
    ),
    (
        "command",
        re.compile(
            r"(os\.system|subprocess\.(call|run|Popen)|popen)\([^)]*(\+|%|f['\"])",
            re.I | re.S,
        ),
    ),
    (
        "nosql",
        re.compile(
            r"(\$where|find_one\(|find\().*(\+|format\(|f['\"])|"
            r"eval\s*\(.*request",
            re.I | re.S,
        ),
    ),
    (
        "ldap",
        re.compile(
            r"(ldap|search_s|search_ext)\([^)]*(\+|%|f['\"])",
            re.I | re.S,
        ),
    ),
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live injection tests are not run",
                "This tool only reviews uploaded source for unsafe query construction.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    hits = 0
    for path, text in (target.get("files") or {}).items():
        for index, line in enumerate(text.splitlines(), start=1):
            for kind, pattern in _PATTERNS:
                if pattern.search(line):
                    hits += 1
                    findings.append(
                        finding(
                            NAME,
                            "high",
                            f"Possible {kind} injection sink",
                            "Use bound parameters or safe APIs instead of concatenating untrusted input.",
                            f"{path}:{index}: {line.strip()[:200]}",
                        )
                    )
                    break

    if hits == 0:
        findings.append(
            finding(
                NAME,
                "info",
                "No common injection sinks found",
                "No string-built SQL, shell, NoSQL, or LDAP patterns were detected.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    return {"tool": NAME, "status": "fail", "findings": findings}
