"""Check session cookie flags. Does not steal or forge sessions."""

import re

from report import finding

NAME = "session"
DESCRIPTION = (
    "Checks Secure, HttpOnly, and SameSite on session cookies. "
    "Does not capture, replay, or forge session values."
)

_SET_COOKIE = re.compile(r"set_cookie\(|Set-Cookie|cookies\.set|setcookie\(", re.I)
_SESSION_NAME = re.compile(
    r"(session|sid|auth|token|jwt)",
    re.I,
)


def _flags(value):
    lowered = value.lower()
    return {
        "httponly": "httponly" in lowered,
        "secure": "secure" in lowered,
        "samesite": "samesite" in lowered,
    }


def _cookie_headers(headers):
    raw = []
    headers = headers or {}
    if "set-cookie" in headers:
        raw.append(headers["set-cookie"])
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            raw.append(value)
    return raw


def _source_cookie_calls(files):
    calls = []
    for path, text in (files or {}).items():
        for index, line in enumerate(text.splitlines(), start=1):
            if _SET_COOKIE.search(line) and _SESSION_NAME.search(line):
                calls.append((path, index, line.strip()[:200]))
    return calls


def run(target):
    findings = []

    if target.get("kind") == "url":
        cookies = _cookie_headers((target.get("http") or {}).get("headers"))
        if not cookies:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "No Set-Cookie header on this response",
                    "Session flags can only be checked when the server sets a cookie.",
                    target.get("url", ""),
                )
            )
            return {"tool": NAME, "status": "info", "findings": findings}

        status = "pass"
        for cookie in cookies:
            flags = _flags(cookie)
            missing = [name for name, present in flags.items() if not present]
            if missing:
                status = "fail"
                findings.append(
                    finding(
                        NAME,
                        "medium",
                        "Session cookie missing flags",
                        "Set Secure, HttpOnly, and SameSite on session cookies.",
                        f"missing={','.join(missing)}",
                    )
                )
            else:
                findings.append(
                    finding(
                        NAME,
                        "info",
                        "Session cookie flags present",
                        "Secure, HttpOnly, and SameSite are set.",
                        cookie[:200],
                    )
                )
        return {"tool": NAME, "status": status, "findings": findings}

    calls = _source_cookie_calls(target.get("files") or {})
    if not calls:
        findings.append(
            finding(
                NAME,
                "info",
                "No session cookie assignment found",
                "No set-cookie style calls with a session-like name were found.",
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    status = "pass"
    for path, line_no, line in calls:
        flags = _flags(line)
        missing = [name for name, present in flags.items() if not present]
        if missing:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Session cookie assignment missing flags",
                    "Set Secure, HttpOnly, and SameSite when creating session cookies.",
                    f"{path}:{line_no}: {line}",
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Session cookie assignment sets flags",
                    "This assignment includes Secure, HttpOnly, and SameSite.",
                    f"{path}:{line_no}: {line}",
                )
            )
    return {"tool": NAME, "status": status, "findings": findings}
