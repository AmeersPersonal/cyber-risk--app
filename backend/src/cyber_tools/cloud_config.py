"""Check container and cloud config. Does not change cloud resources."""

import re

from report import finding

NAME = "cloud_config"
DESCRIPTION = (
    "Looks for containers running as root, secrets in image ENV, privileged mode, and public storage ACLs. "
    "Does not change cloud resources."
)

_USER = re.compile(r"(?m)^USER\s+(\S+)")
_ENV_SECRET = re.compile(
    r"(?m)^ENV\s+\S*(SECRET|PASSWORD|API_KEY|TOKEN)\S*\s+\S+",
    re.I,
)
_PUBLIC = re.compile(
    r"(acl\s*=\s*['\"]public-read|block_public_acls\s*=\s*false|public-read-write)",
    re.I,
)
_PRIVILEGED = re.compile(r"privileged\s*:\s*true", re.I)


def run(target):
    findings = []
    if target.get("kind") == "url":
        findings.append(
            finding(
                NAME,
                "info",
                "Live cloud resources are not changed",
                "This tool only reviews uploaded Docker, compose, and infrastructure files.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    status = "pass"
    users = _USER.findall(blob)
    dockerish = any(
        "dockerfile" in path.lower() or path.lower().endswith((".tf", ".yml", ".yaml"))
        for path in files
    ) or bool(users or _ENV_SECRET.search(blob) or _PUBLIC.search(blob) or _PRIVILEGED.search(blob))
    if users and any(user.lower() == "root" for user in users):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Container runs as root",
                "Set a non-root USER in the image.",
            )
        )
    elif dockerish and not users and any("dockerfile" in path.lower() for path in files):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Container image has no USER",
                "Set a non-root USER in the image.",
            )
        )
    if _ENV_SECRET.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Secret stored in an image ENV instruction",
                "Inject secrets at runtime from a secret store.",
            )
        )
    if _PUBLIC.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Storage ACL allows public reads",
                "Keep bucket and object ACLs private.",
            )
        )
    if _PRIVILEGED.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "Container is privileged",
                "Run the container without privileged mode.",
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No risky container or storage setting found",
                "No root user, image secret, public ACL, or privileged container was detected.",
            )
        )
        if not dockerish:
            status = "info"
    return {"tool": NAME, "status": status, "findings": findings}
