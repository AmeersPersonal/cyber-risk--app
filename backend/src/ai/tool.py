"""Preloaded tool arsenal. The AI may only call these tools."""

from cyber_tools import (
    access_control,
    account_takeover,
    api_mass_assignment,
    broken_authentication,
    business_logic,
    click_jacking,
    clickjacking,
    cryptographic_failures,
    csrf,
    denial_of_service,
    file_trasnfer,
    file_upload_abuse,
    injection,
    misconfiguration,
    pen_test,
    session,
    sql_inject,
    ssrf,
    supply_chain,
    website_element_manipulation,
    xss,
)

_MODULES = (
    click_jacking,
    sql_inject,
    session,
    file_trasnfer,
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


def run_tool(name, target):
    tool = get_tool(name)
    if tool is None:
        return {
            "tool": name,
            "status": "error",
            "findings": [
                {
                    "tool": name,
                    "severity": "info",
                    "title": "Unknown tool",
                    "detail": "The AI can only use the preloaded arsenal.",
                    "evidence": name,
                }
            ],
        }
    return tool["run"](target)
