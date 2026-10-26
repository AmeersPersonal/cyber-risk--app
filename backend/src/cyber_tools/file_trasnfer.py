"""Check file upload handling. Does not transfer or exfiltrate files."""

import re

from report import finding

NAME = "file_trasnfer"
DESCRIPTION = (
    "Checks upload forms and handlers for type or size checks. "
    "Does not upload, download, or exfiltrate files."
)

_FILE_INPUT = re.compile(r"<input[^>]*type=['\"]file['\"][^>]*>", re.I)
_ACCEPT = re.compile(r"accept=", re.I)
_UPLOAD = re.compile(
    r"(\.save\(|upload_file|FileStorage|multipart|request\.files|Transfer-Encoding)",
    re.I,
)
_VALIDATION = re.compile(
    r"(content_type|mimetype|content-type|max_length|MAX_CONTENT_LENGTH|file_size|allowed_ext)",
    re.I,
)


def run(target):
    findings = []

    if target.get("kind") == "url":
        body = ((target.get("http") or {}).get("body")) or ""
        inputs = _FILE_INPUT.findall(body)
        if not inputs:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "No file upload control on this page",
                    "No input type=file was found in the fetched HTML.",
                    target.get("url", ""),
                )
            )
            return {"tool": NAME, "status": "info", "findings": findings}

        status = "pass"
        for tag in inputs:
            if not _ACCEPT.search(tag):
                status = "fail"
                findings.append(
                    finding(
                        NAME,
                        "low",
                        "File input has no accept filter",
                        "Restrict upload controls with accept and enforce type and size on the server.",
                        tag[:200],
                    )
                )
        if status == "pass":
            findings.append(
                finding(
                    NAME,
                    "info",
                    "File inputs declare an accept filter",
                    "The page lists accepted file types. Still enforce checks on the server.",
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    upload_hits = []
    has_validation = False
    for path, text in files.items():
        if _VALIDATION.search(text):
            has_validation = True
        for index, line in enumerate(text.splitlines(), start=1):
            if _UPLOAD.search(line):
                upload_hits.append((path, index, line.strip()[:200]))

    if not upload_hits:
        findings.append(
            finding(
                NAME,
                "info",
                "No upload handler found",
                "No common file upload APIs were found in the source.",
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    if has_validation:
        findings.append(
            finding(
                NAME,
                "info",
                "Upload validation references found",
                "Source mentions content type, size, or extension checks.",
            )
        )
        status = "pass"
    else:
        findings.append(
            finding(
                NAME,
                "medium",
                "Upload handler without type or size checks",
                "Validate MIME type, extension, and size before saving uploads.",
                upload_hits[0][0] + f":{upload_hits[0][1]}: {upload_hits[0][2]}",
            )
        )
        status = "fail"
    return {"tool": NAME, "status": status, "findings": findings}
