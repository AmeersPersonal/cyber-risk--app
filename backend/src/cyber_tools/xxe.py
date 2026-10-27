"""Check XML parser settings. Does not submit XML documents."""

import re

from report import finding

NAME = "xxe"
DESCRIPTION = (
    "Looks for XML parsers without external-entity protections. "
    "Does not submit XML documents."
)

_XML = re.compile(
    r"(etree\.parse|etree\.fromstring|XMLParser\s*\(|DocumentBuilder|"
    r"SAXParser|simplexml_load|xmltodict\.parse|lxml)",
    re.I,
)
_SAFE = re.compile(
    r"(defusedxml|resolve_entities\s*=\s*False|FEATURE_SECURE_PROCESSING|"
    r"disallow-doctype-decl|XMLConstants\.FEATURE_SECURE_PROCESSING)",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live XML checks are not run",
                "This tool only reviews uploaded source for XML parser settings.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    blob = "\n".join((target.get("files") or {}).values())
    if _XML.search(blob) and not _SAFE.search(blob):
        findings.append(
            finding(
                NAME,
                "high",
                "XML parser without external-entity protection",
                "Disable external entities or use a parser that refuses them.",
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if _XML.search(blob) and _SAFE.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "XML parser protection referenced",
                "Source mentions a hardened XML parser or disabled external entities.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No XML parser found",
            "No XML parse call was detected.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
