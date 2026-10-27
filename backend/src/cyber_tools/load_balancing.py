"""Check load-balancer configuration. Does not generate load or fail nodes."""

import re

from report import finding

NAME = "load_balancing"
DESCRIPTION = (
    "Checks balancer headers, trusted-proxy handling, and shared session state. "
    "Does not generate load or take backends out of service."
)

_LB_HEADERS = (
    "via",
    "x-cache",
    "x-served-by",
    "x-backend-server",
    "x-lb",
)
_FORWARDED = re.compile(r"(x-forwarded-for|http_x_forwarded_for)", re.I)
_TRUSTED_PROXY = re.compile(
    r"(trusted_prox|ProxyFix|trust_proxy|real_ip_header|set_real_ip_from)",
    re.I,
)
_LB_CONFIG = re.compile(
    r"(upstream\s+\w+|proxy_pass|load[_-]?balancer|LoadBalancer|target_group)",
    re.I,
)
_MEMORY_SESSION = re.compile(r"(session\[|MemoryStore|session\.MemoryStore)", re.I)
_SHARED_SESSION = re.compile(
    r"(redis|memcached|sticky|session[_-]?affinity|SESSION_ENGINE)",
    re.I,
)


def _headers(target):
    raw = (target.get("http") or {}).get("headers") or {}
    return {str(key).lower(): value for key, value in raw.items()}


def run(target):
    findings = []
    status = "pass"

    if target.get("kind") == "url":
        headers = _headers(target)
        present = [name for name in _LB_HEADERS if headers.get(name)]
        if present:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Load balancer header present",
                    "The response shows a proxy or balancer in front of the app.",
                    present[0],
                )
            )
        else:
            findings.append(
                finding(
                    NAME,
                    "info",
                    "This response does not show a load balancer",
                    "A single origin is valid. Review proxy trust and shared sessions when more than one backend is used.",
                    target.get("url", ""),
                )
            )
            status = "info"
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    if _FORWARDED.search(blob) and not _TRUSTED_PROXY.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "Forwarded client address is used without a trusted proxy list",
                "Only accept forwarded addresses from known load balancers.",
            )
        )
    if (
        _LB_CONFIG.search(blob)
        and _MEMORY_SESSION.search(blob)
        and not _SHARED_SESSION.search(blob)
    ):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "In-memory sessions behind a load balancer",
                "Store sessions in a shared store or pin a client to one backend.",
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No load-balancer misconfiguration found",
                "No untrusted forwarded address or in-memory session behind a balancer was detected.",
            )
        )
        if not _LB_CONFIG.search(blob) and not _FORWARDED.search(blob):
            status = "info"
    return {"tool": NAME, "status": status, "findings": findings}
