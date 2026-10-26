"""Check dependency and third-party script risk. Does not install packages."""

import re

from report import finding

NAME = "supply_chain"
DESCRIPTION = (
    "Reviews dependency manifests and third-party scripts without integrity. "
    "Does not install packages or alter the supply chain."
)

_CDN_SCRIPT = re.compile(
    r"<script[^>]+src=['\"]https?://[^'\"]+['\"][^>]*>",
    re.I,
)
_INTEGRITY = re.compile(r"integrity=", re.I)
_LOCK = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock")


def run(target):
    findings = []
    status = "pass"
    files = target.get("files") or {}
    html = ""

    if target.get("kind") == "url":
        html = ((target.get("http") or {}).get("body")) or ""
    else:
        html = "\n".join(
            text for path, text in files.items() if path.lower().endswith((".html", ".htm"))
        )
        manifests = [
            path
            for path in files
            if path.lower().endswith(("requirements.txt", "package.json", "go.mod", "gemfile"))
        ]
        locks = [path for path in files if any(path.endswith(name) for name in _LOCK)]
        if manifests and not locks:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Dependency manifest without a lockfile",
                    "Commit a lockfile so installs are reproducible.",
                    manifests[0],
                )
            )
        elif manifests:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Dependency lockfile present",
                    "A lockfile accompanies the dependency manifest.",
                )
            )

    for tag in _CDN_SCRIPT.findall(html):
        if not _INTEGRITY.search(tag):
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Third-party script missing integrity",
                    "Add a subresource integrity hash on remote scripts.",
                    tag[:200],
                )
            )
            break

    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No supply-chain issues found",
                "No unlocked manifests or unsigned third-party scripts were detected.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
