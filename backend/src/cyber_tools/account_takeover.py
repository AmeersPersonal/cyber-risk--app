"""Check account-takeover hardening. Does not phish or reset accounts."""

import re

from report import finding

NAME = "account_takeover"
DESCRIPTION = (
    "Looks for password-reset and login flows missing rate limits or token hashing. "
    "Does not phish users or abuse reset flows."
)

_RESET = re.compile(
    r"(password[_-]?reset|forgot[_-]?password|reset[_-]?token|change[_-]?email)",
    re.I,
)
_TOKEN_STORE = re.compile(
    r"(reset_token\s*=\s*['\"]|token\s*=\s*str\(uuid|secrets\.token)",
    re.I,
)
_PROTECT = re.compile(
    r"(rate[_-]?limit|throttle|hash.*token|token.*hash|expir|mfa|2fa)",
    re.I,
)
_OPEN_REDIRECT = re.compile(
    r"(next|redirect|return_to)\s*=\s*request\.(GET|args|query)",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live account-takeover tests are not run",
                "This tool only reviews uploaded source for reset and login hardening.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    status = "pass"
    files = target.get("files") or {}
    blob = "\n".join(files.values())
    has_reset = bool(_RESET.search(blob))
    has_protect = bool(_PROTECT.search(blob))

    if has_reset and not has_protect:
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Password reset without rate limit or token hardening",
                "Rate-limit resets, hash stored tokens, and expire them quickly.",
            )
        )

    for path, text in files.items():
        for index, line in enumerate(text.splitlines(), start=1):
            if _OPEN_REDIRECT.search(line):
                status = "fail"
                findings.append(
                    finding(
                        NAME,
                        "medium",
                        "Possible open redirect after login",
                        "Allowlist post-login redirect targets.",
                        f"{path}:{index}: {line.strip()[:200]}",
                    )
                )
                break
        if _TOKEN_STORE.search(text) and "hash" not in text.lower():
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Reset token may be stored in cleartext",
                    "Store only a hash of password-reset tokens.",
                    path,
                )
            )

    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No account-takeover patterns found",
                "No weak reset or open-redirect patterns were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
