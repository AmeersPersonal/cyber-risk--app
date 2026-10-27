"""Check access-control patterns. Does not probe or escalate privileges."""

import re

from report import finding

NAME = "access_control"
DESCRIPTION = (
    "Looks for missing auth checks and direct object references in source. "
    "Does not probe endpoints or escalate privileges."
)

_ROUTE = re.compile(
    r"@(app|router)\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"]",
    re.I,
)
_AUTH = re.compile(
    r"(login_required|require_auth|IsAuthenticated|authorize|permission_required|depends\()",
    re.I,
)
_IDOR = re.compile(
    r"(find_by_id|get_object_or_404|objects\.get)\([^)]*request\.(GET|POST|args|json)",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live access-control probing is not run",
                "This tool only reviews uploaded source for auth and object-access patterns.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    status = "pass"
    unprotected = []
    idor_hits = []
    for path, text in (target.get("files") or {}).items():
        lines = text.splitlines()
        for index, line in enumerate(lines):
            route = _ROUTE.search(line)
            if route:
                window = "\n".join(lines[max(0, index - 3) : index + 8])
                if not _AUTH.search(window):
                    unprotected.append(f"{path}:{index + 1}: {route.group(0)}")
            if _IDOR.search(line):
                idor_hits.append(f"{path}:{index + 1}: {line.strip()[:200]}")

    if unprotected:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Route without nearby auth check",
                "Require authentication or authorization on sensitive routes.",
                unprotected[0][:200],
            )
        )
    if idor_hits:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Possible direct object reference",
                "Authorize that the caller owns or may access the loaded object.",
                idor_hits[0],
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No obvious access-control gaps found",
                "No unprotected route or direct object-reference patterns were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
