"""Read-only surface check. Does not run exploits or payloads."""

from report import finding

NAME = "pen_test"
DESCRIPTION = (
    "Reads security headers, HTTPS use, and stack disclosure. "
    "Does not run exploits or attack procedures."
)

_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

_STACK_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


def fingerprints_from_target(target):
    marks = []
    http = target.get("http") or {}
    headers = {key.lower(): value for key, value in (http.get("headers") or {}).items()}
    for name in _STACK_HEADERS:
        value = headers.get(name)
        if value:
            marks.append(value)
    for path, text in (target.get("files") or {}).items():
        lower = path.lower()
        if lower.endswith("requirements.txt"):
            marks.extend(line.strip() for line in text.splitlines() if line.strip())
        if lower.endswith("package.json"):
            marks.append(text[:2000])
        if lower.endswith("go.mod"):
            marks.extend(line.strip() for line in text.splitlines()[:20])
    return [item for item in marks if item]


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        url = target.get("url") or ""
        http = target.get("http") or {}
        headers = {key.lower(): value for key, value in (http.get("headers") or {}).items()}

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
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Common security headers present",
                    "CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy are set.",
                )
            )

        for name in _STACK_HEADERS:
            value = headers.get(name)
            if value:
                findings.append(
                    finding(
                        NAME,
                        "low",
                        "Stack header disclosed",
                        "Avoid exposing server product and version banners.",
                        f"{name}: {value[:200]}",
                    )
                )
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    if not files:
        findings.append(
            finding(
                NAME,
                "info",
                "No source files to review",
                "Upload source or provide a URL.",
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    marks = fingerprints_from_target(target)
    if marks:
        findings.append(
            finding(
                NAME,
                "info",
                "Stack fingerprints from source",
                "Dependency and config files were used to match known CVEs.",
                "; ".join(marks[:8])[:300],
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "No dependency manifest found",
                "Add requirements.txt, package.json, or go.mod for CVE matching.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
