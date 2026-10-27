"""Check common security misconfigurations. Does not exploit open panels."""

from report import finding

NAME = "misconfiguration"
DESCRIPTION = (
    "Checks HTTPS, security headers, and debug or default-config signals. "
    "Does not exploit open admin panels or default credentials."
)

_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

_DEBUG = (
    "debug = true",
    "debug=true",
    "app.debug",
    "flask_env = development",
    "django_debug",
)


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        url = target.get("url") or ""
        headers = {
            key.lower(): value
            for key, value in ((target.get("http") or {}).get("headers") or {}).items()
        }
        if url.startswith("http://"):
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "URL is not HTTPS",
                    "Serve the site over HTTPS.",
                    url,
                )
            )
        missing = [name for name in _SECURITY_HEADERS if not headers.get(name)]
        if missing:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Security headers missing",
                    "Add the missing response headers.",
                    ",".join(missing),
                )
            )
        for name in ("server", "x-powered-by"):
            if headers.get(name):
                findings.append(
                    finding(
                        NAME,
                        "low",
                        "Stack header disclosed",
                        "Avoid exposing server product banners.",
                        f"{name}: {headers[name][:200]}",
                    )
                )
        if not findings:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Common security headers present",
                    "HTTPS and baseline security headers look configured.",
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    for path, text in (target.get("files") or {}).items():
        lowered = text.lower()
        for marker in _DEBUG:
            if marker in lowered:
                status = "fail"
                findings.append(
                    finding(
                        NAME,
                        "high",
                        "Debug mode enabled in source",
                        "Disable debug mode outside local development.",
                        f"{path}: {marker}",
                    )
                )
                break

    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No debug misconfiguration found",
                "No debug=true style settings were detected in source.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
