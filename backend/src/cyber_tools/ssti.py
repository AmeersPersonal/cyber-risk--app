"""Check template engines that render request data. Does not render templates."""

import re

from report import finding

NAME = "ssti"
DESCRIPTION = (
    "Looks for template engines rendering request data. "
    "Does not render templates."
)

_SINK = re.compile(
    r"(render_template_string|Environment\(\)\.from_string|jinja2\.Template\s*\(|"
    r"from_string\s*\(|MakoTemplate\s*\()",
    re.I,
)
_REQUEST = re.compile(r"(request\.|req\.body|req\.query|params\[|form\[)", re.I)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live template checks are not run",
                "This tool only reviews uploaded source for request data passed to a template engine.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    hits = []
    for path, text in (target.get("files") or {}).items():
        if not _REQUEST.search(text):
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            if _SINK.search(line):
                hits.append(f"{path}:{index}: {line.strip()[:200]}")
    if hits:
        findings.append(
            finding(
                NAME,
                "high",
                "Request data rendered as a template",
                "Render a fixed template file and pass request data as variables.",
                hits[0],
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No request-rendered template found",
            "No template constructor was given request data.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
