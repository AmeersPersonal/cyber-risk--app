"""Check rate-limit policy. Does not send repeated requests."""

import re

from report import finding

NAME = "rate_limit"
DESCRIPTION = (
    "Checks auth and API routes for a limiter, and responses for a complete rate-limit policy. "
    "Does not send repeated requests to see when a limit trips."
)

_AUTH = re.compile(
    r"(login|signin|signup|register|forgot|password[_-]?reset|/otp|api[_-]?key)",
    re.I,
)
_LIMIT = re.compile(
    r"(rate[_-]?limit|throttle|SlowAPI|flask_limiter|Limiter\(|@limiter|"
    r"aiolimiter|express-rate-limit|django[_-]ratelimit|slowapi)",
    re.I,
)
_DISABLED = re.compile(
    r"(RATELIMIT_ENABLED\s*=\s*False|limiter\s*=\s*None)",
    re.I,
)
_POLICY_HEADERS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
)


def _headers(target):
    raw = (target.get("http") or {}).get("headers") or {}
    return {str(key).lower(): value for key, value in raw.items()}


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        http = target.get("http") or {}
        headers = _headers(target)
        present = [name for name in _POLICY_HEADERS if headers.get(name)]
        if http.get("status") == 429:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Response status shows rate limiting",
                    "This response already indicates the limit was applied.",
                    target.get("url", ""),
                )
            )
        elif present and len(present) < len(_POLICY_HEADERS):
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "low",
                    "Incomplete rate-limit policy headers",
                    "Advertise the limit, the remaining quota, and when to retry.",
                    ", ".join(present),
                )
            )
        elif not present:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "low",
                    "Response does not include a rate-limit policy",
                    "Publish rate-limit headers on public and authentication routes.",
                    target.get("url", ""),
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Rate-limit policy headers present",
                    "The response includes limit, remaining, and retry guidance.",
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    has_auth = bool(_AUTH.search(blob))
    has_limit = bool(_LIMIT.search(blob))
    disabled = bool(_DISABLED.search(blob))

    if disabled:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Rate limiting is turned off",
                "Enable the limiter on authentication and public API routes.",
            )
        )
    elif has_auth and not has_limit:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Auth or API route has no rate limiter",
                "Throttle login, signup, password reset, and API key routes.",
            )
        )
    elif has_limit:
        findings.append(
            finding(
                NAME,
                "info",
                "Rate limiter referenced in source",
                "Source mentions a limiter or throttle on the application.",
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "No auth route or rate limiter found",
                "No login, signup, reset, or limiter configuration was detected.",
            )
        )
        status = "info"
    return {"tool": NAME, "status": status, "findings": findings}
