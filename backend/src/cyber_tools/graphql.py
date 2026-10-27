"""Check GraphQL exposure and query limits. Does not send GraphQL queries."""

import re

from report import finding

NAME = "graphql"
DESCRIPTION = (
    "Looks for GraphQL introspection left on and queries without a depth limit. "
    "Does not send GraphQL queries."
)

_GQL = re.compile(r"(graphql|ApolloServer|graphene)", re.I)
_INTRO_ON = re.compile(r"introspection\s*[:=]\s*true", re.I)
_INTRO_OFF = re.compile(r"introspection\s*[:=]\s*false", re.I)
_LIMIT = re.compile(r"(depthLimit|depth_limit|query[_-]?complexity|max_depth|costLimit)", re.I)
_SCHEMA = re.compile(r"__schema", re.I)


def run(target):
    findings = []
    status = "pass"
    if target.get("kind") == "url":
        body = ((target.get("http") or {}).get("body") or "")
        if _SCHEMA.search(body):
            findings.append(
                finding(
                    NAME,
                    "medium",
                    "Fetched page includes a GraphQL schema listing",
                    "Turn introspection off for public clients.",
                    target.get("url", ""),
                )
            )
            return {"tool": NAME, "status": "fail", "findings": findings}
        findings.append(
            finding(
                NAME,
                "info",
                "GraphQL queries are not sent",
                "This tool reviews the fetched page and uploaded source for introspection and query limits.",
                target.get("url", ""),
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}

    blob = "\n".join((target.get("files") or {}).values())
    if not _GQL.search(blob):
        findings.append(
            finding(
                NAME,
                "info",
                "No GraphQL server found",
                "No GraphQL server setup was detected.",
            )
        )
        return {"tool": NAME, "status": "info", "findings": findings}
    if _INTRO_ON.search(blob) or not _INTRO_OFF.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "GraphQL introspection is not disabled",
                "Disable introspection on public GraphQL endpoints.",
            )
        )
    if not _LIMIT.search(blob):
        status = "fail"
        findings.append(
            finding(
                NAME,
                "medium",
                "GraphQL queries have no depth or cost limit",
                "Limit query depth or cost.",
            )
        )
    if not findings:
        findings.append(
            finding(
                NAME,
                "info",
                "GraphQL introspection is off and queries are limited",
                "Source disables introspection and mentions a depth or cost limit.",
            )
        )
    return {"tool": NAME, "status": status, "findings": findings}
