"""Parallel AI threat council: agents debate, then run starting checks or other methods."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from ai.cve_knowledge import agent_context, initialize_cve_knowledge
from ai.debate_manger import DebateManager
from ai.meterless_memory import MemoryRetrieval, MemoryStore, format_reinjection
from ai.meterless_scout import Scout
from ai.model_client import ModelClient, parse_model_decision
from ai.tool import ARSENAL, normalize_method, run_tool
from ai.zetaris_client import ZetarisClient


def _env_int(name, default):
    try:
        return int(os.getenv(name) or default)
    except ValueError:
        return default


_MODEL_SYSTEM = (
    "You are one analyst in a defensive security council. "
    "The preloaded arsenal is the convenient starting set. "
    "You may also name other inspection methods that are not implemented in this repo, "
    "as short snake_case names. "
    "Review a fetched response or uploaded source. "
    "Do not request exploit payloads, flood traffic, or unauthorized access steps. "
    "Reply with JSON only: {\"argument\": \"...because...\", \"votes\": [\"tool_name\"]}. "
    "The argument must say why, using because, since, or therefore."
)


class CouncilAgent:
    def __init__(self, name, role, preferred_tools, model=None):
        self.name = name
        self.role = role
        self.preferred_tools = [tool for tool in preferred_tools if tool in ARSENAL]
        self.model = model

    def _template(self, target, memory_text, available, intel, cve_brief, guidelines):
        kind = target.get("kind")
        argument = (
            f"{self.name} ({self.role}): for a {kind} target, next we should run "
            f"{', '.join(available[:3]) or 'nothing further'} because those checks "
            f"match this role's attack surface."
        )
        if intel.get("source") == "zetaris" and self.name == "intel":
            argument += " Zetaris returned live company threat rows; prioritize stack and CVE-aligned checks."
        if cve_brief and self.name in {"intel", "attacker_mindset", "defender"}:
            argument += f" Local CVE context: {cve_brief[:220]}"
        if "high" in memory_text and self.name == "attacker_mindset":
            argument += " Prior findings are high severity; deepen injection and access paths."
        if "high" in memory_text and self.name == "defender":
            argument += " Prior findings are high severity; harden session, CSRF, and crypto next."
        if guidelines:
            argument += " Following debate guidelines: no bare agree/disagree; justify every vote."
        return {
            "agent": self.name,
            "role": self.role,
            "argument": argument,
            "votes": available[:3],
            "source": "template",
        }

    def _ask_model(self, target, memory_text, available, intel, cve_brief, guidelines):
        if self.model is None or not self.model.configured():
            return None
        allowed = [name for name in ARSENAL if name not in (target.get("_used") or [])]
        # Starting set for convenience. The model may also name other methods.
        catalog = list(dict.fromkeys(available + allowed))
        stay_inspect = bool(target.get("stay_inspect"))
        if stay_inspect:
            catalog = [name for name in catalog if name in ARSENAL]
        extra = "" if stay_inspect else " Other snake_case inspection methods are also allowed."
        messages = [
            {"role": "system", "content": _MODEL_SYSTEM},
            {
                "role": "user",
                "content": (
                    f"Agent: {self.name} ({self.role}).\n"
                    f"Target kind: {target.get('kind')}.\n"
                    f"Convenient starting tools: {', '.join(catalog) or 'none'}.{extra}\n"
                    f"Prior findings: {memory_text[:800] or 'none yet'}.\n"
                    f"Intel source: {intel.get('source')}.\n"
                    f"Defense notes: {cve_brief[:400] or 'none'}.\n"
                    f"Guidelines: {guidelines[:400]}"
                ),
            },
        ]
        parsed = parse_model_decision(
            self.model.complete(messages), catalog, stay_inspect=stay_inspect
        )
        if not parsed:
            return None
        return {
            "agent": self.name,
            "role": self.role,
            "argument": f"{self.name}: {parsed['argument']}",
            "votes": parsed["votes"],
            "source": "model",
        }

    def propose(self, target, memory_text, used_tools, intel, cve_brief="", guidelines=""):
        available = [name for name in self.preferred_tools if name not in used_tools]
        asked = self._ask_model(
            {**target, "_used": used_tools},
            memory_text,
            available,
            intel,
            cve_brief,
            guidelines,
        )
        if asked and asked.get("votes"):
            return asked
        return self._template(target, memory_text, available, intel, cve_brief, guidelines)


def default_agents(model=None):
    return [
        CouncilAgent(
            "recon",
            "surface mapper",
            ["pen_test", "misconfiguration", "supply_chain", "clickjacking", "cors", "tls_posture", "graphql"],
            model=model,
        ),
        CouncilAgent(
            "attacker_mindset",
            "offensive analyst (defensive checks only)",
            [
                "injection",
                "xss",
                "ssrf",
                "access_control",
                "business_logic",
                "path_traversal",
                "xxe",
                "ssti",
                "insecure_deserialization",
                "prototype_pollution",
            ],
            model=model,
        ),
        CouncilAgent(
            "defender",
            "defensive hardening analyst",
            [
                "session",
                "csrf",
                "broken_authentication",
                "cryptographic_failures",
                "account_takeover",
                "user_enumeration",
                "website_element_manipulation",
                "oauth",
                "jwt",
                "session_fixation",
                "security_logging",
            ],
            model=model,
        ),
        CouncilAgent(
            "intel",
            "threat-intel / Zetaris analyst",
            [
                "pen_test",
                "supply_chain",
                "misconfiguration",
                "denial_of_service",
                "ddos",
                "rate_limit",
                "load_balancing",
                "api_mass_assignment",
                "sensitive_data",
                "cloud_config",
            ],
            model=model,
        ),
        CouncilAgent(
            "upload_forms",
            "content and transfer analyst",
            ["file_upload_abuse", "website_element_manipulation", "csrf"],
            model=model,
        ),
    ]


def _tally_votes(proposals, used_tools):
    scores = {}
    for proposal in proposals:
        for index, tool in enumerate(proposal.get("votes") or []):
            method = normalize_method(tool)
            if not method or method in used_tools:
                continue
            scores[method] = scores.get(method, 0) + (3 - index)
    return sorted(scores.items(), key=lambda item: item[1], reverse=True)


def _run_tools_parallel(tool_names, target, max_workers=6):
    results = []
    if not tool_names:
        return results
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(run_tool, name, target): name for name in tool_names}
        for future in as_completed(futures):
            results.append(future.result())
    return results


def _summarize_findings(tool_results):
    parts = []
    for result in tool_results:
        for item in result.get("findings") or []:
            parts.append(
                f"{item.get('severity', 'info')} {result.get('tool')}: {item.get('title', '')}"
            )
    return "; ".join(parts[:12])


class ThreatCouncil:
    """Council of agents that argue in parallel, then Scout routes the next tools."""

    def __init__(
        self,
        agents=None,
        scout=None,
        memory=None,
        zetaris=None,
        debate_manager=None,
        model=None,
        max_rounds=None,
        tools_per_round=None,
    ):
        self.model = model if model is not None else ModelClient()
        self.agents = agents or default_agents(self.model)
        for agent in self.agents:
            if getattr(agent, "model", None) is None:
                agent.model = self.model
        self.scout = scout or Scout()
        self.memory = memory or MemoryStore()
        self.retrieval = MemoryRetrieval(self.memory)
        self.zetaris = zetaris or ZetarisClient()
        self.debate_manager = debate_manager or DebateManager()
        self.max_rounds = max_rounds if max_rounds is not None else _env_int(
            "METERLESS_COUNCIL_ROUNDS", 3
        )
        self.tools_per_round = tools_per_round if tools_per_round is not None else _env_int(
            "METERLESS_TOOLS_PER_ROUND", 4
        )
        initialize_cve_knowledge()
        self.cve_context = agent_context()

    def _gather_proposals(self, target, used_tools, intel):
        memory_hit = self.retrieval.query(
            text="threat findings next action company CVE",
            top_n=5,
            threshold=0.0,
            strategy="comprehensive",
        )
        memory_text = format_reinjection(memory_hit["memories"])
        cve_brief = (self.cve_context or {}).get("text", "")
        guidelines = self.debate_manager.guidelines_prompt()
        proposals = []

        def work(agent):
            return agent.propose(
                target,
                memory_text,
                used_tools,
                intel,
                cve_brief=cve_brief,
                guidelines=guidelines,
            )

        with ThreadPoolExecutor(max_workers=len(self.agents)) as pool:
            futures = [pool.submit(work, agent) for agent in self.agents]
            for future in futures:
                proposals.append(future.result())
        return proposals, memory_hit["trace"]

    def analyze(self, target, company_hint="", fingerprints=None):
        used_tools = set()
        tool_results = []
        debate_log = []
        fingerprints = fingerprints or []

        intel = self.zetaris.company_threat_context(
            company_hint=company_hint or target.get("url") or "uploaded-source",
            fingerprints=fingerprints,
        )
        self.memory.add(
            "intel",
            f"Threat intel from {intel.get('source')} for {intel.get('company')}",
            meta={"rows": len(intel.get("rows") or []), "fingerprints": fingerprints[:8]},
        )
        self.memory.add(
            "cve_knowledge",
            f"Local common CVE briefs: {', '.join((self.cve_context or {}).get('common_cves') or [])}",
            meta={"briefs": (self.cve_context or {}).get("briefs") or []},
        )

        for round_index in range(1, self.max_rounds + 1):
            proposals, memory_trace = self._gather_proposals(target, used_tools, intel)
            vote_ranking = _tally_votes(proposals, used_tools)
            prompt = (
                f"Round {round_index}. Analyze company threat. "
                f"Prior tools: {sorted(used_tools) or ['none']}. "
                f"Top votes: {[name for name, _ in vote_ranking[:5]]}. "
                f"Intel source: {intel.get('source')}."
            )
            decision = self.scout.decide(
                prompt=prompt,
                user={"id": "threat-council", "role": "arbiter"},
                surface="council",
                used_tools=used_tools,
                max_tools=self.tools_per_round,
            )

            moderated = self.debate_manager.moderate_round(
                round_index,
                proposals,
                used_tools=used_tools,
                max_tools=self.tools_per_round,
            )
            # Debate manager resolves collisions first; Scout fills remaining slots.
            chosen = list(moderated.get("chosen_tools") or [])
            for name, _ in vote_ranking:
                method = normalize_method(name)
                if method and method not in chosen and method not in used_tools:
                    chosen.append(method)
                if len(chosen) >= self.tools_per_round:
                    break
            for step in decision.get("toolPlan") or []:
                method = normalize_method(step.get("tool"))
                if method and method not in chosen and method not in used_tools:
                    chosen.append(method)
                if len(chosen) >= self.tools_per_round:
                    break

            if target.get("stay_inspect"):
                chosen = [name for name in chosen if name in ARSENAL]

            round_entry = {
                "round": round_index,
                "proposals": proposals,
                "votes": vote_ranking,
                "scout": {
                    "intent": decision.get("intent"),
                    "risk": decision.get("risk"),
                    "candidates": decision.get("candidates"),
                    "executionContract": decision.get("executionContract"),
                    "engine": decision.get("engine"),
                },
                "debate_manager": {
                    "session_id": moderated.get("session_id"),
                    "collisions": moderated.get("collisions"),
                    "resolution": moderated.get("resolution"),
                },
                "memory_trace": memory_trace,
                "chosen_tools": chosen,
                "stay_inspect": bool(target.get("stay_inspect")),
            }
            debate_log.append(round_entry)

            if not chosen or decision.get("intent", {}).get("primary") == "threat.done":
                self.memory.add("debate", f"Council stopped after round {round_index}", round_entry)
                break

            round_results = _run_tools_parallel(chosen, target)
            tool_results.extend(round_results)
            used_tools.update(chosen)
            summary = _summarize_findings(round_results)
            self.memory.add(
                "findings",
                f"Round {round_index} ran {chosen}: {summary or 'no findings'}",
                meta={"tools": chosen},
            )
            for proposal in proposals:
                self.memory.add("argument", proposal["argument"], meta={"agent": proposal["agent"]})

        return {
            "tool_results": tool_results,
            "debate": debate_log,
            "memory": self.memory.all(),
            "intel": intel,
            "engines": {
                "zetaris": intel.get("source"),
                "meterless_scout": "meterless-scout-local",
                "meterless_hmem": "meterless-hmem-local",
                "council": "parallel-threat-council",
                "debate_manager": "debate-manager-local",
                "meterless_model": "meterless-chat" if self.model.configured() else "template",
            },
        }
