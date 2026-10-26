"""Check SSRF-prone request patterns. Does not make attacker-controlled requests."""

import re

from report import finding

NAME = "ssrf"
DESCRIPTION = (
    "Looks for server-side fetches of user-supplied URLs in source. "
    "Does not issue requests to attacker-controlled or internal hosts."
)

_FETCH = re.compile(
    r"(requests\.(get|post|request)|urllib\.request\.urlopen|httpx\.(get|post)|"
    r"fetch\(|axios\.(get|post)|curl_exec)\(",
    re.I,
)
_USER_INPUT = re.compile(
    r"(request\.(args|GET|POST|json|data|query)|req\.(query|body|params))",
    re.I,
)
_ALLOWLIST = re.compile(r"(allowlist|whitelist|allowed_hosts|urlparse)", re.I)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live SSRF tests are not run",
                "This tool only reviews uploaded source for user-controlled server fetches.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    status = "pass"
    risky = []
    for path, text in (target.get("files") or {}).items():
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if not _FETCH.search(line):
                continue
            window = "\n".join(lines[max(0, index - 5) : index + 6])
            if _USER_INPUT.search(window) and not _ALLOWLIST.search(window):
                risky.append(f"{path}:{index + 1}: {line.strip()[:200]}")

    if risky:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Possible SSRF sink",
                "Do not fetch user-supplied URLs without an allowlist and private-IP block.",
                risky[0],
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "No obvious SSRF sinks found",
                "No user-controlled server-side fetch patterns were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
