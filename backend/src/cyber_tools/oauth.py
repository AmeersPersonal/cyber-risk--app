"""Check OAuth and OIDC settings. Does not start an authorization flow."""

import re

from report import finding

NAME = "oauth"
DESCRIPTION = (
    "Looks for OAuth or OIDC flows missing state, using an open redirect_uri, "
    "or placing tokens in the query string. Does not start an authorization flow."
)

_OAUTH = re.compile(r"(oauth|openid|redirect_uri)", re.I)
_STATE = re.compile(r"\bstate\b", re.I)
_OPEN_URI = re.compile(
    r"redirect_uri\s*=\s*request\.(args|GET|query|params|form|values)",
    re.I,
)
_TOKEN_QUERY = re.compile(
    r"[?&](access_token|id_token)=|location\.search.{0,40}(access_token|id_token)",
    re.I,
)


def run(target):
    findings = []
    if target.get("kind") == "url":
        body = ((target.get("http") or {}).get("body") or "")
        if _TOKEN_QUERY.search(body):
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Token appears in a URL query",
                    "Keep access and id tokens out of query strings.",
                    target.get("url", ""),
                )
            )
            return {"tool": NAME, "status": "fail", "findings": findings}
        findings.append(
            finding(
                NAME,
                "info",
                "Live OAuth flows are not started",
                "This tool reviews the fetched page and uploaded source for OAuth settings.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    blob = "\n".join((target.get("files") or {}).values())
    status = "pass"
    if not _OAUTH.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "No OAuth flow found",
                "No OAuth, OpenID, or redirect_uri handling was detected.",
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}
    if _OPEN_URI.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "high",
                "OAuth redirect URI taken from the request",
                "Allowlist redirect URIs for each client.",
            )
        )
    if not _STATE.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "OAuth flow without a state value",
                "Send and verify a state value on the authorization response.",
            )
        )
    if _TOKEN_QUERY.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "OAuth token placed in a query string",
                "Return tokens in a fragment or a back-channel response, not the query string.",
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "OAuth flow includes state",
                "Source mentions OAuth and a state value, without an open redirect URI.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
