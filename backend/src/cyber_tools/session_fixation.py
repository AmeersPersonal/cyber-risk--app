"""Check session rotation at login. Does not replay session identifiers."""

import re

from report import finding

NAME = "session_fixation"
DESCRIPTION = (
    "Looks for login that keeps the session id from before authentication. "
    "Does not replay session identifiers."
)

_LOGIN = re.compile(r"(def\s+login|function\s+login|/login)", re.I)
_ASSIGN = re.compile(r"(session\[\s*['\"]user|req\.session\.user\s*=|session\[.user_id)", re.I)
_ROTATE = re.compile(
    r"(session\.regenerate|cycle_key|session_regenerate_id|rotate_session|req\.session\.regenerate)",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live session rotation checks are not run",
                "This tool only reviews uploaded source for session rotation during login.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    blob = "\n".join((target.get("files") or {}).values())
    if _LOGIN.search(blob) and _ASSIGN.search(blob) and not _ROTATE.search(blob):
        findings.append(
            finding(
                NAME,
                "medium",
                "Login keeps the existing session id",
                "Issue a new session id when authentication succeeds.",
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if _LOGIN.search(blob) and _ROTATE.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "Login rotates the session id",
                "Source issues a new session id during login.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No login session assignment found",
            "No login path both authenticates and stores the user on the existing session.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
