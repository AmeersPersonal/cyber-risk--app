"""Meterless Scout–style intent router for the next council action."""

from ai.tool import ARSENAL

# Intent registry: maps analysis intents to arsenal capabilities.
INTENT_REGISTRY = {
    "threat.recon": {
        "tools": ["pen_test", "misconfiguration", "supply_chain", "clickjacking"],
        "risk": "low",
    },
    "threat.inject": {
        "tools": ["injection", "xss", "ssrf"],
        "risk": "medium",
    },
    "threat.auth": {
        "tools": [
            "broken_authentication",
            "session",
            "csrf",
            "account_takeover",
            "access_control",
        ],
        "risk": "medium",
    },
    "threat.upload": {
        "tools": ["file_upload_abuse", "website_element_manipulation"],
        "risk": "low",
    },
    "threat.crypto_api": {
        "tools": ["cryptographic_failures", "api_mass_assignment", "business_logic", "denial_of_service"],
        "risk": "medium",
    },
    "threat.done": {
        "tools": [],
        "risk": "low",
    },
}


def _score_intent(prompt, intent_name, used_tools):
    prompt_l = (prompt or "").lower()
    entry = INTENT_REGISTRY[intent_name]
    available = [name for name in entry["tools"] if name in ARSENAL and name not in used_tools]
    score = 0.05 * len(available)
    keywords = {
        "threat.recon": ("recon", "header", "https", "misconfig", "surface", "url"),
        "threat.inject": ("inject", "xss", "sql", "ssrf", "source", "sink"),
        "threat.auth": ("auth", "session", "csrf", "login", "token", "access"),
        "threat.upload": ("upload", "file", "form", "csp"),
        "threat.crypto_api": ("crypto", "secret", "api", "price", "rate", "dos"),
        "threat.done": ("done", "complete", "enough", "stop"),
    }
    for word in keywords.get(intent_name, ()):
        if word in prompt_l:
            score += 0.2
    if intent_name != "threat.done" and not available:
        score = 0.0
    if intent_name == "threat.done" and len(used_tools) >= 6:
        score += 0.4
    return score, available


class Scout:
    """Conforming Scout surface: decide() -> intent, risk, toolPlan, executionContract."""

    def decide(self, prompt, user=None, surface="council", used_tools=None, max_tools=4):
        used_tools = set(used_tools or [])
        candidates = []
        plans = {}
        for intent_name in INTENT_REGISTRY:
            score, tools = _score_intent(prompt, intent_name, used_tools)
            candidates.append({"intent": intent_name, "score": round(score, 3)})
            plans[intent_name] = tools
        candidates.sort(key=lambda item: item["score"], reverse=True)
        primary = candidates[0]["intent"] if candidates else "threat.done"
        tool_plan = [
            {"tool": name, "input": {"surface": surface}}
            for name in plans.get(primary, [])[:max_tools]
        ]
        risk_level = INTENT_REGISTRY.get(primary, {}).get("risk", "low")
        contract = {
            "schema": "meterless.scout.execution_contract.v1",
            "intent": {"primary": primary, "confidence": candidates[0]["score"] if candidates else 0},
            "risk": {"level": risk_level, "flags": []},
            "toolPlan": tool_plan,
            "user": user or {"id": "council", "role": "analyst"},
            "surface": surface,
            "policy": "defensive_arsenal_only",
        }
        return {
            "intent": contract["intent"],
            "risk": contract["risk"],
            "toolPlan": tool_plan,
            "executionContract": contract,
            "candidates": candidates,
            "engine": "meterless-scout-local",
        }
