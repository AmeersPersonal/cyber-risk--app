"""Check CORS policy. Does not send cross-origin requests."""

import re

from report import finding

NAME = "cors"
DESCRIPTION = (
    "Checks wildcard or reflected origins, including credentialed responses. "
    "Does not send cross-origin requests."
)

_STAR = re.compile(r"access-control-allow-origin.{0,60}\*", re.I)
_REFLECT = re.compile(
    r"access-control-allow-origin.{0,80}(request\.headers|origin)",
    re.I,
)
_CREDS = re.compile(r"access-control-allow-credentials.{0,40}true", re.I)
_ALLOW = re.compile(r"(allowed_origins|cors_origins|cors_allowed)", re.I)


def _headers(target):
    raw = (target.get("http") or {}).get("headers") or {}
    return {str(key).lower(): value for key, value in raw.items()}


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        headers = _headers(target)
        origin = (headers.get("access-control-allow-origin") or "").strip()
        creds = (headers.get("access-control-allow-credentials") or "").strip().lower()
        if origin == "*" and creds == "true":
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "high",
                    "Credentialed wildcard CORS origin",
                    "Allow a specific origin list, and keep credentials off a wildcard origin.",
                    target.get("url", ""),
                )
            )
        elif origin == "*":
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Wildcard CORS origin",
                    "Replace the wildcard origin with an allowlist.",
                    target.get("url", ""),
                )
            )
        elif origin:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Specific CORS origin advertised",
                    "The response names an origin instead of a wildcard.",
                    origin[:200],
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "No CORS allow-origin header on this response",
                    "Same-origin responses do not need a CORS allow header.",
                    target.get("url", ""),
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    reflected = bool(_REFLECT.search(blob)) and not _ALLOW.search(blob)
    starred = bool(_STAR.search(blob)) and not _ALLOW.search(blob)
    if (starred or reflected) and _CREDS.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Credentialed CORS origin is wildcard or reflected",
                "Allowlist origins and do not combine credentials with a reflected origin.",
            )
        )
    elif starred or reflected:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "CORS origin is wildcard or taken from the request",
                "Set an explicit origin allowlist.",
            )
        )
    elif _ALLOW.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "CORS allowlist referenced",
                "Source names an origin allowlist.",
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "No CORS policy found",
                "No wildcard, reflected, or allowlist CORS policy was detected.",
            )
        )
        status = "info"
    return {"tool": NAME, "status": status, "findings": findings}
