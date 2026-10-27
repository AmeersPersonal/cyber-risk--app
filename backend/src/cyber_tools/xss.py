"""Check for XSS-related weaknesses. Does not inject or execute scripts."""

import re

from report import finding

NAME = "xss"
DESCRIPTION = (
    "Checks CSP script controls and unsafe HTML rendering in source. "
    "Does not inject or execute scripts in a browser."
)

_UNSAFE = (
    re.compile(r"innerHTML\s*=", re.I),
    re.compile(r"document\.write\s*\(", re.I),
    re.compile(r"dangerouslySetInnerHTML", re.I),
    re.compile(r"\|\s*safe\b", re.I),
    re.compile(r"mark_safe\s*\(|Markup\s*\(", re.I),
    re.compile(r"v-html\s*=", re.I),
)


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        headers = (target.get("http") or {}).get("headers") or {}
        csp = (headers.get("content-security-policy") or "").lower()
        if not csp:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "No Content-Security-Policy for scripts",
                    "Set a CSP that limits script sources.",
                    target.get("url", ""),
                )
            )
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "CSP allows unsafe script behavior",
                    "Avoid script-src unsafe-inline and unsafe-eval when possible.",
                    csp[:200],
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "CSP script policy present",
                    "A Content-Security-Policy header was found.",
                    csp[:200],
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    hits = []
    for path, text in (target.get("files") or {}).items():
        for index, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in _UNSAFE):
                hits.append((path, index, line.strip()[:200]))

    if hits:
        status = "fail"
        path, index, line = hits[0]
        findings.append(
            finding(
                NAME,
                "high",
                "Unsafe HTML rendering pattern",
                "Escape or sanitize untrusted data before rendering HTML.",
                f"{path}:{index}: {line}",
            )
        )
        if len(hits) > 1:
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Additional unsafe rendering sites",
                    f"{len(hits) - 1} more similar patterns were found.",
                )
            )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "No common XSS rendering sinks found",
                "No innerHTML, dangerouslySetInnerHTML, or mark_safe patterns were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
