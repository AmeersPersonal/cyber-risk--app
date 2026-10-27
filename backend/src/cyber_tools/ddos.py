"""Check DDoS hardening signals. Does not generate flood or disruption traffic."""

import re

from report import finding

NAME = "ddos"
DESCRIPTION = (
    "Looks for edge-protection headers and request size or connection caps. "
    "Does not generate flood traffic or disrupt a live service."
)

_EDGE_HEADERS = (
    "cf-ray",
    "cf-cache-status",
    "x-akamai-request-id",
    "x-sucuri-id",
    "x-cdn",
    "x-iinfo",
)
_EDGE_VALUE = re.compile(
    r"(cloudflare|akamai|sucuri|fastly|incapsula|imperva)",
    re.I,
)
_CAPS = re.compile(
    r"(MAX_CONTENT_LENGTH|client_max_body_size|LimitRequestBody|maxRequestLength|"
    r"bodyParser\.json\(\s*\{\s*limit|limit_conn|worker_connections|"
    r"max_connections|connection[_-]?limit)",
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
        edge = [name for name in _EDGE_HEADERS if headers.get(name)]
        server = headers.get("server", "")
        if edge or _EDGE_VALUE.search(server):
            findings.append(
                finding(
                    NAME,
                    "info",
                    "Edge protection header present",
                    "The response advertises a CDN or WAF in front of the origin.",
                    (edge[0] if edge else "server")[:200],
                )
            )
        else:
            status = "fail"
            findings.append(
                finding(
                    NAME,
                    "low",
                    "No DDoS edge protection signal on this response",
                    "Put a CDN or WAF in front of public origins and cap request size.",
                    target.get("url", ""),
                )
            )
        return {"tool": NAME, "status": status, "findings": findings}

    files = target.get("files") or {}
    blob = "\n".join(files.values())
    if files and not _CAPS.search(blob) and not _EDGE_VALUE.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "No request-size or connection cap found",
                "Cap body size and concurrent connections at the app or reverse proxy.",
            )
        )
    elif _CAPS.search(blob) or _EDGE_VALUE.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "Request cap or edge protection referenced",
                "Source mentions a body or connection limit, or an edge provider.",
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "No DDoS hardening markers to review",
                "No uploaded source was available to check for request caps.",
            )
        )
        status = "info"
    return {"tool": NAME, "status": status, "findings": findings}
