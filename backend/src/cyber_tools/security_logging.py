"""Check audit logs on auth paths. Does not read production logs."""

import re

from report import finding

NAME = "security_logging"
DESCRIPTION = (
    "Looks for login, reset, and access-denied paths without an audit log. "
    "Does not read production logs."
)

_AUTH = re.compile(r"(def\s+login|/login|password[_-]?reset|access[_-]?denied)", re.I)
_LOG = re.compile(r"(logger\.|logging\.|audit_log|log\.info|log\.warning)", re.I)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live log checks are not run",
                "This tool only reviews uploaded source for audit logs on authentication paths.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    blob = "\n".join((target.get("files") or {}).values())
    if _AUTH.search(blob) and not _LOG.search(blob):
        findings.append(
            finding(
                NAME,
                "medium",
                "Auth path has no audit log",
                "Log login, password reset, and access-denied events.",
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if _AUTH.search(blob) and _LOG.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "Auth path writes a log",
                "Source mentions a logger on an authentication path.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No auth path found to log",
            "No login, reset, or access-denied path was detected.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
