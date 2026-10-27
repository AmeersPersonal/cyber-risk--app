"""Check untrusted deserialization. Does not send serialized objects."""

import re

from report import finding

NAME = "insecure_deserialization"
DESCRIPTION = (
    "Looks for pickle, unsafe YAML, PHP unserialize, and Java object streams on request data. "
    "Does not send serialized objects."
)

_BAD = re.compile(
    r"(pickle\.loads|pickle\.load\s*\(|marshal\.loads|unserialize\s*\(|"
    r"ObjectInputStream|jsonpickle\.decode|yaml\.load\s*\()",
    re.I,
)
_SAFE_LINE = re.compile(r"yaml\.load\s*\([^)\n]*SafeLoader|yaml\.safe_load", re.I)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live deserialization checks are not run",
                "This tool only reviews uploaded source for unsafe deserializers.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    hits = []
    safe_only = False
    for path, text in (target.get("files") or {}).items():
        if _SAFE_LINE.search(text) and not re.search(r"pickle\.|unserialize|ObjectInputStream|marshal\.loads", text, re.I):
            safe_only = True
        for index, line in enumerate(text.splitlines(), start=1):
            if _SAFE_LINE.search(line):
                continue
            if _BAD.search(line):
                hits.append(f"{path}:{index}: {line.strip()[:200]}")
    if hits:
        findings.append(
            finding(
                NAME,
                "high",
                "Unsafe deserializer on application data",
                "Refuse pickle, unsafe YAML, and native object streams for request data.",
                hits[0],
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    if safe_only:
        findings.append(
            finding(
                NAME,
                "info",
                "Safe YAML loader referenced",
                "Source uses a safe YAML loader.",
            )
        )
        return {"tool": NAME, "status": "pass", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No unsafe deserializer found",
            "No pickle, unsafe YAML, unserialize, or Java object stream was detected.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
