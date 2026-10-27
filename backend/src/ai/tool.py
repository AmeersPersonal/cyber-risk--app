"""Preloaded checks plus any other inspection method an agent names.

The arsenal is the convenient starting set. A name outside that set still runs:
it reviews the fetched response or uploaded source, and uses the council model
when one is configured. It does not gain a shell or send attack traffic.
"""

import json
import re

from report import finding

from cyber_tools import (
    access_control,
    account_takeover,
    api_mass_assignment,
    broken_authentication,
    business_logic,
    clickjacking,
    cloud_config,
    cors,
    cryptographic_failures,
    csrf,
    ddos,
    denial_of_service,
    file_upload_abuse,
    graphql,
    injection,
    insecure_deserialization,
    jwt,
    load_balancing,
    misconfiguration,
    oauth,
    path_traversal,
    pen_test,
    prototype_pollution,
    rate_limit,
    security_logging,
    sensitive_data,
    session,
    session_fixation,
    ssrf,
    ssti,
    supply_chain,
    tls_posture,
    user_enumeration,
    website_element_manipulation,
    xss,
    xxe,
)

_MODULES = (
    session,
    website_element_manipulation,
    pen_test,
    injection,
    xss,
    csrf,
    broken_authentication,
    access_control,
    ssrf,
    file_upload_abuse,
    clickjacking,
    business_logic,
    api_mass_assignment,
    denial_of_service,
    supply_chain,
    misconfiguration,
    cryptographic_failures,
    account_takeover,
    user_enumeration,
    ddos,
    rate_limit,
    load_balancing,
    cors,
    path_traversal,
    xxe,
    insecure_deserialization,
    ssti,
    oauth,
    jwt,
    prototype_pollution,
    graphql,
    session_fixation,
    security_logging,
    tls_posture,
    sensitive_data,
    cloud_config,
)

ARSENAL = {
    module.NAME: {
        "name": module.NAME,
        "description": module.DESCRIPTION,
        "run": module.run,
    }
    for module in _MODULES
}


def list_tools():
    return [
        {"name": item["name"], "description": item["description"]}
        for item in ARSENAL.values()
    ]


def get_tool(name):
    return ARSENAL.get(name)


_METHOD = re.compile(r"[a-z][a-z0-9_]{1,48}")
_UNSAFE_TEXT = re.compile(
    r"(payload|exploit|proof of concept|\bpoc\b|sqlmap|nmap\b|union\s+select|"
    r"os\.system|subprocess|flood|slowloris)",
    re.I,
)


def normalize_method(name):
    """Return a snake_case method name, or None when the name is not a method id."""
    text = str(name or "").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,48}", text):
        return None
    text = re.sub(r"_+", "_", text.replace("-", "_")).strip("_")
    if _METHOD.fullmatch(text):
        return text
    return None


def is_accepted_method(name):
    return normalize_method(name) is not None


def _excerpt(target, limit=4000):
    if target.get("kind") == "url":
        http = target.get("http") or {}
        headers = http.get("headers") or {}
        header_text = "\n".join(f"{key}: {value}" for key, value in headers.items())
        body = http.get("body") or ""
        text = f"url: {target.get('url', '')}\nstatus: {http.get('status', '')}\n{header_text}\n{body}"
        return text[:limit]
    parts = []
    for path, content in (target.get("files") or {}).items():
        parts.append(f"# {path}\n{content}")
    return "\n".join(parts)[:limit]


def _safe_detail(detail):
    text = " ".join(str(detail or "").split())
    if not text or _UNSAFE_TEXT.search(text):
        return "Reviewed the fetched response or uploaded source for this method."
    return text[:500]


def _model_additional(name, excerpt):
    from ai.model_client import ModelClient

    model = ModelClient()
    if not model.configured():
        return None
    text = model.complete(
        [
            {
                "role": "system",
                "content": (
                    "Review only the excerpt already collected. "
                    "Reply with JSON {\"status\":\"pass|fail|info\","
                    "\"findings\":[{\"severity\":\"info|low|medium|high\","
                    "\"title\":\"\",\"detail\":\"\",\"evidence\":\"\"}]}. "
                    "Do not include exploit steps, payloads, commands, or traffic-generation instructions."
                ),
            },
            {"role": "user", "content": f"Method: {name}\nExcerpt:\n{excerpt}"},
        ]
    )
    if not text:
        return None
    raw = text.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    status = str(data.get("status") or "info").lower()
    if status not in {"pass", "fail", "info"}:
        status = "info"
    findings = []
    for item in data.get("findings") or []:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "info").lower()
        if severity not in {"high", "medium", "low", "info"}:
            severity = "info"
        title = " ".join(str(item.get("title") or "Additional inspection method").split())[:160]
        findings.append(
            finding(name, severity, title, _safe_detail(item.get("detail")), str(item.get("evidence") or "")[:200])
        )
    if not findings:
        return None
    return {"tool": name, "status": status, "findings": findings[:6]}


def run_additional_method(name, target):
    excerpt = _excerpt(target)
    reviewed = _model_additional(name, excerpt)
    if reviewed:
        return reviewed
    tokens = [part for part in name.split("_") if len(part) >= 4]
    evidence = ""
    for line in excerpt.splitlines():
        if tokens and any(token in line.lower() for token in tokens):
            evidence = line.strip()[:200]
            break
    return {
        "tool": name,
        "status": "info",
        "findings": [
            finding(
                name,
                "info",
                "Additional inspection method applied",
                "This method is outside the preloaded starting set. "
                "It reviewed the fetched response or uploaded source.",
                evidence or name,
            )
        ],
    }


def run_tool(name, target):
    method = normalize_method(name)
    if method is None:
        return {
            "tool": str(name),
            "status": "error",
            "findings": [
                finding(
                    str(name),
                    "info",
                    "Unusable method name",
                    "Name an inspection method in snake_case. Commands are not accepted.",
                    str(name)[:200],
                )
            ],
        }
    tool = get_tool(method)
    if target.get("stay_inspect") and tool is None:
        return {
            "tool": method,
            "status": "info",
            "findings": [
                finding(
                    method,
                    "info",
                    "Command overridden by stay-inspect",
                    "Stay-inspect mode kept this scan on the preloaded checks.",
                    method,
                )
            ],
        }
    if tool is not None:
        return tool["run"](target)
    return run_additional_method(method, target)
