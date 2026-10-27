"""Check file paths built from request data. Does not read files outside the upload."""

import re

from report import finding

NAME = "path_traversal"
DESCRIPTION = (
    "Looks for request data joined into a filesystem path. "
    "Does not request files outside the uploaded source."
)

_SINK = re.compile(
    r"(open|send_file|send_from_directory|os\.path\.join|pathlib\.Path)\s*\("
    r"[^)\n]*(request|filename|user_path|params|args|form)",
    re.I,
)
_GUARD = re.compile(r"(secure_filename|commonpath|realpath|basename)", re.I)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live path checks are not run",
                "This tool only reviews uploaded source for request data used as a file path.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    files = target.get("files") or {}
    hits = []
    guarded = False
    for path, text in files.items():
        if _GUARD.search(text):
            guarded = True
        for index, line in enumerate(text.splitlines(), start=1):
            if _SINK.search(line):
                hits.append(f"{path}:{index}: {line.strip()[:200]}")
    if hits and not guarded:
        findings.append(
            finding(
                NAME,
                "high",
                "Request data used in a file path",
                "Normalize the path and keep it inside a known directory.",
                hits[0],
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if hits and guarded:
        findings.append(
            finding(
                NAME,
                "info",
                "File path uses a containment check",
                "Source mentions a filename or path containment helper.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No request-built file paths found",
            "No open or send_file call built from request data was detected.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
