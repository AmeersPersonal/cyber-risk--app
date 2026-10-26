"""Check crypto and secret handling. Does not break cryptography."""

import re

from report import finding

NAME = "cryptographic_failures"
DESCRIPTION = (
    "Looks for hard-coded secrets, weak crypto, and cleartext sensitive data. "
    "Does not crack keys or break cryptography."
)

_SECRET = re.compile(
    r"(api[_-]?key|secret[_-]?key|password|private[_-]?key|aws_secret)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.I,
)
_WEAK = re.compile(
    r"(md5\(|sha1\(|DES|RC4|verify\s*=\s*False|ssl\._create_unverified_context)",
    re.I,
)
_CLEAR = re.compile(
    r"(http://).*(password|token|secret)|password=.+&",
    re.I,
)


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        url = target.get("url") or ""
        if url.startswith("http://"):
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Sensitive traffic may be cleartext",
                    "Use HTTPS for all authenticated and sensitive pages.",
                    url,
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "URL uses HTTPS",
                    "Transport encryption is present for this target URL.",
                    url,
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    for path, text in (target.get("files") or {}).items():
        for index, line in enumerate(text.splitlines(), start=1):
            evidence = f"{path}:{index}: {line.strip()[:200]}"
            if _SECRET.search(line):
                status = "fail"
                findings.append(
                    finding(
                        NAME,
                        "high",
                        "Hard-coded secret",
                        "Load secrets from the environment or a secret manager.",
                        evidence,
                    )
                )
            elif _WEAK.search(line):
                status = "fail"
                findings.append(
                    finding(
                        NAME,
                        "medium",
                        "Weak or disabled cryptography",
                        "Prefer modern hashes and verified TLS.",
                        evidence,
                    )
                )
            elif _CLEAR.search(line):
                status = "fail"
                findings.append(
                    finding(
                        NAME,
                        "medium",
                        "Possible cleartext sensitive data",
                        "Do not put secrets in cleartext URLs or logs.",
                        evidence,
                    )
                )

    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No cryptographic failures found",
                "No hard-coded secrets or weak crypto patterns were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
