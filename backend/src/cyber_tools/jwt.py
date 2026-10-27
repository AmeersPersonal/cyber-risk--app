"""Check JWT storage and expiry. Does not forge or crack tokens."""

import re

from report import finding

NAME = "jwt"
DESCRIPTION = (
    "Checks browser token storage, missing expiry, and hardcoded HMAC secrets. "
    "Does not forge or crack tokens."
)

_STORE = re.compile(r"localStorage\.setItem\([^)\n]*(token|jwt)", re.I)
_SIGN = re.compile(r"(jwt\.encode|jwt\.sign|jsonwebtoken)", re.I)
_EXP = re.compile(r"(\bexp\b|expiresIn|expires_in)", re.I)
_SECRET = re.compile(
    r"(jwt\.(encode|sign)|jsonwebtoken).{0,120}['\"][^'\"]{6,}['\"]",
    re.I | re.S,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live token checks are not run",
                "This tool only reviews uploaded source for JWT storage, expiry, and hardcoded secrets.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    status = "pass"
    if _STORE.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "JWT stored in localStorage",
                "Keep session tokens in an HttpOnly cookie.",
            )
        )
    if _SIGN.search(blob) and not _EXP.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "JWT is signed without an expiry",
                "Set an expiration on every signed token.",
            )
        )
    if _SECRET.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Hardcoded JWT secret",
                "Load the HMAC secret from a secret store.",
            )
        )
    if not findings and _SIGN.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "JWT signing includes an expiry",
                "Source signs a token and mentions an expiry.",
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No JWT handling found",
                "No JWT sign, localStorage token, or hardcoded JWT secret was detected.",
            )
        )
        status = "info"
    return {"tool": NAME, "status": status, "findings": findings}
