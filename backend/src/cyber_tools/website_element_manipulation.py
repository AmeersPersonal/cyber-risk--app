"""Check page hardening against element abuse. Does not alter live pages."""

import re
from html.parser import HTMLParser

from report import finding

NAME = "website_element_manipulation"
DESCRIPTION = (
    "Checks CSP, script integrity, and form CSRF tokens. "
    "Does not modify or inject elements on a live page."
)

_CSRF_NAME = re.compile(
    r"(csrf|authenticity_token|_token|__requestverificationtoken)",
    re.I,
)


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        attrs = {key.lower(): (value or "") for key, value in attrs}
        if tag == "script":
            self.scripts.append(attrs)
        if tag == "form":
            self._form = {"attrs": attrs, "inputs": []}
            self.forms.append(self._form)
        if tag == "input" and self._form is not None:
            self._form["inputs"].append(attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _parse(html):
    parser = _Page()
    try:
        parser.feed(html or "")
    except Exception:
        return [], []
    return parser.scripts, parser.forms


def _form_has_csrf(form):
    for item in form.get("inputs", []):
        name = item.get("name", "")
        if _CSRF_NAME.search(name):
            return True
    return False


def run(target):
    findings = []
    html = ""
    headers = {}

    if target.get("kind") == "url":
        http = target.get("http") or {}
        html = http.get("body") or ""
        headers = http.get("headers") or {}
    else:
        files = target.get("files") or {}
        html = "\n".join(
            text for path, text in files.items() if path.lower().endswith((".html", ".htm"))
        )
        blob = "\n".join(files.values())
        if "content-security-policy" in blob.lower():
            headers = {"content-security-policy": "present-in-source"}

    scripts, forms = _parse(html)
    status = "pass"

    csp = (headers.get("content-security-policy") or "").strip()
    if not csp:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Content-Security-Policy missing",
                "Set a CSP to limit script and style sources.",
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "Content-Security-Policy present",
                "A CSP header or source reference was found.",
                csp[:200],
            )
        )

    remote_scripts = [
        attrs
        for attrs in scripts
        if attrs.get("src") and not attrs.get("integrity")
    ]
    if remote_scripts:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "low",
                "Script missing integrity",
                "Add a subresource integrity hash on third-party scripts.",
                remote_scripts[0].get("src", "")[:200],
            )
        )

    for form in forms:
        method = (form.get("attrs") or {}).get("method", "get").lower()
        if method == "post" and not _form_has_csrf(form):
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "POST form missing CSRF token",
                    "Include a CSRF hidden field on state-changing forms.",
                    str((form.get("attrs") or {}).get("action", ""))[:200],
                )
            )

    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No HTML elements to review",
                "No scripts or forms were found in the target.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
