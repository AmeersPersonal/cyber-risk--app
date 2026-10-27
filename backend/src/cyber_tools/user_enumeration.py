"""Check for account-existence oracles. Does not try usernames against a live site."""

import re

from report import finding

NAME = "user_enumeration"
DESCRIPTION = (
    "Looks for login, signup, and reset messages that reveal whether an account exists. "
    "Does not guess usernames or measure live response timing."
)

_AUTH = re.compile(
    r"(login|signin|sign[_-]?up|signup|register|forgot[_-]?password|password[_-]?reset)",
    re.I,
)
_ORACLE = re.compile(
    r"(user(name)?\s+not\s+found|no\s+such\s+(user|account)|account\s+does\s+not\s+exist|"
    r"email\s+already\s+(registered|exists|in\s+use)|username\s+(taken|already)|"
    r"unknown\s+user(name)?|invalid\s+user(name)?\b)",
    re.I,
)
_GENERIC = re.compile(
    r"(invalid\s+(email\s+or\s+password|credentials)|"
    r"if\s+an\s+account\s+exists|same\s+response\s+whether)",
    re.I,
)


def run(target):
    findings = []

    if target.get("kind") == "url":
        body = ((target.get("http") or {}).get("body") or "")
        if _ORACLE.search(body):
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Page text reveals whether an account exists",
                    "Use the same message for known and unknown accounts on login, signup, and reset.",
                    target.get("url", ""),
                )
            )
            return {"tool": NAME, "status": "fail", "findings": findings}
        findings.append(
            finding(
                NAME,
                "info",
                "Live username checks are not run",
                "This tool only reviews the fetched page and uploaded source for account-existence messages.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    has_auth = bool(_AUTH.search(blob))
    has_generic = bool(_GENERIC.search(blob))
    oracle_hits = []
    for path, text in files.items():
        for index, line in enumerate(text.splitlines(), start=1):
            if _ORACLE.search(line):
                oracle_hits.append(f"{path}:{index}: {line.strip()[:200]}")

    if oracle_hits:
        findings.append(
            finding(
                NAME,
                "medium",
                "Distinct message reveals whether an account exists",
                "Return one generic message for failed login, signup, and password reset.",
                oracle_hits[0],
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if has_auth and has_generic:
        findings.append(
            finding(
                NAME,
                "info",
                "Auth flow uses a generic account message",
                "Login, signup, or reset text does not confirm that an account exists.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No account-existence messages found",
            "No login, signup, or reset text confirming an account was detected.",
        )
    )
    return {
        "tool": NAME,
        "status": "info" if not has_auth else "pass",
        "findings": findings,
    }
