"""Check API responses for sensitive fields. Does not query live records."""

import re

from report import finding

NAME = "sensitive_data"
DESCRIPTION = (
    "Looks for responses that return password hashes, card numbers, or government identifiers. "
    "Does not query live records."
)

_LEAK = re.compile(
    r"(return|jsonify|res\.json|Response)\s*\(?[^\n]*"
    r"(password_hash|card_number|credit_card|social_security|\bssn\b|\bcvv\b)",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        body = ((target.get("http") or {}).get("body") or "")
        if _LEAK.search(body):
            findings.append(
                finding(
                    NAME,
                    "high",
                    "Fetched body contains a sensitive field",
                    "Remove password hashes, card numbers, and government identifiers from responses.",
                    target.get("url", ""),
                )
            )
            return {"tool": NAME, "status": "fail", "findings": findings}
        findings.append(
            finding(
                NAME,
                "info",
                "Live record queries are not run",
                "This tool reviews the fetched body and uploaded source for sensitive response fields.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    hits = []
    for path, text in (target.get("files") or {}).items():
        for index, line in enumerate(text.splitlines(), start=1):
            if _LEAK.search(line):
                hits.append(f"{path}:{index}: {line.strip()[:200]}")
    if hits:
        findings.append(
            finding(
                NAME,
                "high",
                "Response includes a sensitive field",
                "Return only the fields a client needs. Leave password hashes and card data out.",
                hits[0],
            )
        )
        return {"tool": NAME, "status": "fail", "findings": findings}
    findings.append(
        finding(
            NAME,
            "info",
            "No sensitive response field found",
            "No response line returned a password hash, card number, or government identifier.",
        )
    )
    return {"tool": NAME, "status": "info", "findings": findings}
