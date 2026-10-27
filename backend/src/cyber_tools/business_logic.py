"""Check business-logic risk markers. Does not abuse workflows or race them."""

import re

from report import finding

NAME = "business_logic"
DESCRIPTION = (
    "Looks for price, quantity, coupon, and balance fields trusted from the client. "
    "Does not abuse checkout flows or race conditions."
)

_CLIENT_TRUST = re.compile(
    r"(price|quantity|qty|discount|coupon|balance|amount|total)\s*=\s*"
    r"(request\.(json|POST|GET|data|args)|req\.(body|query|params))",
    re.I,
)
_SERVER_CHECK = re.compile(
    r"(recalculate|server[_-]?price|canonical[_-]?price|validate_coupon|check_inventory)",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live business-logic abuse tests are not run",
                "This tool only reviews uploaded source for client-trusted money or quantity fields.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    status = "pass"
    hits = []
    blob_has_check = False
    for path, text in (target.get("files") or {}).items():
        if _SERVER_CHECK.search(text):
            blob_has_check = True
        for index, line in enumerate(text.splitlines(), start=1):
            if _CLIENT_TRUST.search(line):
                hits.append(f"{path}:{index}: {line.strip()[:200]}")

    if hits and not blob_has_check:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Client-trusted price or quantity field",
                "Derive prices and limits on the server; do not trust client-supplied totals.",
                hits[0],
            )
        )
    elif hits:
        findings.append(
            finding(
                NAME,
                "low",
                "Client field with possible server validation",
                "Client-supplied money or quantity fields were found; confirm server recalculation.",
                hits[0],
            )
        )
    else:
        findings.append(
            finding(
                NAME,
                "info",
                "No client-trusted commerce fields found",
                "No price, quantity, coupon, or balance assignments from request input were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
