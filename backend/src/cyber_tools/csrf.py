"""Check CSRF protections on forms. Does not forge or send cross-site requests."""

import re
from html.parser import HTMLParser

from report import finding

NAME = "csrf"
DESCRIPTION = (
    "Checks POST forms and source for CSRF tokens or middleware. "
    "Does not forge or send cross-site requests."
)

_TOKEN = re.compile(
    r"(csrf|authenticity_token|_token|__requestverificationtoken)",
    re.I,
)
_MIDDLEWARE = re.compile(
    r"(CsrfViewMiddleware|csrf_protect|VerifyCsrfToken|csurf|csrf_exempt)",
    re.I,
)


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        attrs = {key.lower(): (value or "") for key, value in attrs}
        if tag == "form":
            self._form = {"attrs": attrs, "inputs": []}
            self.forms.append(self._form)
        if tag == "input" and self._form is not None:
            self._form["inputs"].append(attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _parse(html):
    parser = _Forms()
    try:
        parser.feed(html or "")
    except Exception:
        return []
    return parser.forms


def _has_token(form):
    for item in form.get("inputs", []):
        if _TOKEN.search(item.get("name", "")):
            return True
    return False


def run(target):
    findings = []
    status = "pass"
    html = ""
    files = target.get("files") or {}

    if target.get("kind") == "url":
        html = ((target.get("http") or {}).get("body")) or ""
    else:
        html = "\n".join(
            text for path, text in files.items() if path.lower().endswith((".html", ".htm"))
        )
        blob = "\n".join(files.values())
        if _MIDDLEWARE.search(blob) and "csrf_exempt" not in blob.lower():
            findings.append(
                finding(
                    NAME,
                    "info",
                    "CSRF middleware found in source",
                    "Source references CSRF protection middleware.",
                )
            )
        if "csrf_exempt" in blob.lower():
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "CSRF exemption found",
                    "Review csrf_exempt or equivalent bypasses on state-changing routes.",
                )
            )

    for form in _parse(html):
        method = (form.get("attrs") or {}).get("method", "get").lower()
        if method == "post" and not _has_token(form):
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
                "No CSRF issues found on reviewed forms",
                "No unprotected POST forms were detected in the target.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
