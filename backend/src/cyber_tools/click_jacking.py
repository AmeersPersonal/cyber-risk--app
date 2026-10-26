"""Check clickjacking protections. Does not build or send attack pages."""

from report import finding

NAME = "click_jacking"
DESCRIPTION = (
    "Checks X-Frame-Options and CSP frame-ancestors. "
    "Does not generate clickjacking pages or overlays."
)


def _header(headers, name):
    return (headers or {}).get(name.lower(), "")


def _has_frame_protection(headers, body=""):
    xfo = _header(headers, "x-frame-options").lower()
    if xfo in {"deny", "sameorigin"} or xfo.startswith("allow-from"):
        return True, "x-frame-options", xfo

    csp = _header(headers, "content-security-policy").lower()
    if "frame-ancestors" in csp and "frame-ancestors *" not in csp:
        return True, "content-security-policy", csp

    lowered = (body or "").lower()
    if 'http-equiv="x-frame-options"' in lowered or "frame-ancestors" in lowered:
        return True, "markup", "meta or CSP in document"

    return False, "", ""


def _scan_source(files):
    blob = "\n".join(files.values()).lower()
    return _has_frame_protection({}, blob)


def run(target):
    findings = []
    kind = target.get("kind")

    if kind == "url":
        http = target.get("http") or {}
        protected, source, evidence = _has_frame_protection(
            http.get("headers"), http.get("body", "")
        )
        if protected:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Clickjacking protection present",
                    "The response sets a frame-control header or policy.",
                    evidence or source,
                )
            )
            status = "pass"
        else:
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Clickjacking protection missing",
                    "Set X-Frame-Options to DENY or SAMEORIGIN, or CSP frame-ancestors.",
                    target.get("url", ""),
                )
            )
            status = "fail"
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    protected, source, evidence = _scan_source(files)
    if protected:
        findings.append(
            finding(
                NAME,
                "info",
                "Clickjacking protection found in source",
                "Source references a frame-control header or CSP directive.",
                evidence or source,
            )
        )
        status = "pass"
    else:
        findings.append(
            finding(
                NAME,
                "medium",
                "No clickjacking protection in source",
                "Add X-Frame-Options or CSP frame-ancestors when serving HTML.",
            )
        )
        status = "fail"
    return {"tool": NAME, "status": status, "findings": findings}
