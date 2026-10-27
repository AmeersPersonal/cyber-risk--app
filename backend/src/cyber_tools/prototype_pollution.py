"""Check object merges of request data. Does not send crafted objects."""

import re

from report import finding

NAME = "prototype_pollution"
DESCRIPTION = (
    "Looks for request objects merged into application objects. "
    "Does not send crafted objects."
)

_MERGE = re.compile(
    r"(Object\.assign\s*\(\s*\{[^)\n]*\}\s*,\s*(req|request)\.(body|query)|"
    r"_\.(merge|defaultsDeep)\s*\([^)\n]*(req|request)\.(body|query))",
    re.I,
)
_GUARD = re.compile(r"(forbidden_keys|block_proto|drop_proto)", re.I)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live object-merge checks are not run",
                "This tool only reviews uploaded source for request objects merged into other objects.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    blob = "\n".join((target.get("files") or {}).values())
    if _MERGE.search(blob) and not _GUARD.search(blob):
        findings.append(
            finding(
                NAME,
                "high",
                "Request object merged into another object",
                "Copy named fields instead of merging the whole request object.",
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if _MERGE.search(blob) and _GUARD.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "Object merge mentions a key filter",
                "Source merges request data and mentions a key filter.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No request object merge found",
            "No Object.assign or lodash merge of request data was detected.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
