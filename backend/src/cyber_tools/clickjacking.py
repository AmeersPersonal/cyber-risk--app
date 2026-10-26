"""Check clickjacking protections. Does not build or send attack pages."""

from report import finding

NAME = "clickjacking"
DESCRIPTION = (
    "Checks X-Frame-Options and CSP frame-ancestors. "
    "Does not generate clickjacking pages or overlays."
)


def _header(headers, name):
    return (headers or {}).get(name.lower(), "")


def _has_frame_protection(headers, body=""):
    xfo = _header(headers, "x-frame-options").lower()
    if xfo in {"deny", "sameorigin"} or xfo.startswith("allow-from"):
        return True, xfo

    csp = _header(headers, "content-security-policy").lower()
    if "frame-ancestors" in csp and "frame-ancestors *" not in csp:
        return True, csp

    lowered = (body or "").lower()
    if 'http-equiv="x-frame-options"' in lowered or "frame-ancestors" in lowered:
        return True, "markup"

    return False, ""


def run(target):
    findings = []
    if target.get("kind") == "url":
        http = target.get("http") or {}
        protected, evidence = _has_frame_protection(http.get("headers"), http.get("body", ""))
        if protected:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Clickjacking protection present",
                    "The response sets a frame-control header or policy.",
                    evidence,
                )
            )
            return {"tool": NAME, "status": "pass", "findings": findings}
        findings.append(
            finding(
                NAME,
                "medium",
                "Clickjacking protection missing",
                "Set X-Frame-Options to DENY or SAMEORIGIN, or CSP frame-ancestors.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values()).lower()
    protected, evidence = _has_frame_protection({}, blob)
    if protected:
        findings.append(
            finding(
                NAME,
                "info",
                "Clickjacking protection found in source",
                "Source references a frame-control header or CSP directive.",
                evidence,
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "medium",
            "No clickjacking protection in source",
            "Add X-Frame-Options or CSP frame-ancestors when serving HTML.",
        )
    )
    return {"tool": NAME, "status": "fail", "findings": findings}
