"""Parallel AI threat council: agents debate and pick the next arsenal tools."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from ai.meterless_memory import MemoryRetrieval, MemoryStore, format_reinjection
from ai.meterless_scout import Scout
from ai.tool import ARSENAL, run_tool
from ai.zetaris_client import ZetarisClient


def _env_int(name, default):
    try:
        return int(os.getenv(name) or default)
    except ValueError:
        return default


class CouncilAgent:
    def __init__(self, name, role, preferred_tools):
        self.name = name
        self.role = role
        self.preferred_tools = [tool for tool in preferred_tools if tool in ARSENAL]

    def propose(self, target, memory_text, used_tools, intel):
        available = [name for name in self.preferred_tools if name not in used_tools]
        kind = target.get("kind")
        argument = (
            f"{self.name} ({self.role}): for a {kind} target, next we should run "
            f"{', '.join(available[:3]) or 'nothing further'}."
        )
        if intel.get("source") == "zetaris" and self.name == "intel":
            argument += " Zetaris returned live company threat rows; prioritize stack and CVE-aligned checks."
        if "high" in memory_text and self.name == "attacker_mindset":
            argument += " Prior findings are high severity; deepen injection and access paths."
        if "high" in memory_text and self.name == "defender":
            argument += " Prior findings are high severity; harden session, CSRF, and crypto next."
        votes = available[:3]
        return {
            "agent": self.name,
            "role": self.role,
            "argument": argument,
            "votes": votes,
        }


def default_agents():
    return [
        CouncilAgent(
            "recon",
            "surface mapper",
            ["pen_test", "misconfiguration", "supply_chain", "clickjacking", "click_jacking"],
        ),
        CouncilAgent(
            "attacker_mindset",
            "offensive analyst (defensive checks only)",
            ["injection", "sql_inject", "xss", "ssrf", "access_control", "business_logic"],
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
                "website_element_manipulation",
            ],
        ),
        CouncilAgent(
            "intel",
            "threat-intel / Zetaris analyst",
            ["pen_test", "supply_chain", "misconfiguration", "denial_of_service", "api_mass_assignment"],
        ),
        CouncilAgent(
            "upload_forms",
            "content and transfer analyst",
            ["file_upload_abuse", "file_trasnfer", "website_element_manipulation", "csrf"],
        ),
    ]


def _tally_votes(proposals, used_tools):
    scores = {}
    for proposal in proposals:
        for index, tool in enumerate(proposal.get("votes") or []):
            if tool in used_tools or tool not in ARSENAL:
                continue
            scores[tool] = scores.get(tool, 0) + (3 - index)
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
        max_rounds=None,
        tools_per_round=None,
    ):
        self.agents = agents or default_agents()
        self.scout = scout or Scout()
        self.memory = memory or MemoryStore()
        self.retrieval = MemoryRetrieval(self.memory)
        self.zetaris = zetaris or ZetarisClient()
        self.max_rounds = max_rounds if max_rounds is not None else _env_int(
            "METERLESS_COUNCIL_ROUNDS", 3
        )
        self.tools_per_round = tools_per_round if tools_per_round is not None else _env_int(
            "METERLESS_TOOLS_PER_ROUND", 4
        )

    def _gather_proposals(self, target, used_tools, intel):
        memory_hit = self.retrieval.query(
            text="threat findings next action company",
            top_n=5,
            threshold=0.0,
            strategy="comprehensive",
        )
        memory_text = format_reinjection(memory_hit["memories"])
        proposals = []

        def work(agent):
            return agent.propose(target, memory_text, used_tools, intel)

        with ThreadPoolExecutor(max_workers=len(self.agents)) as pool:
            futures = [pool.submit(work, agent) for agent in self.agents]
            for future in as_completed(futures):
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

            # Blend Scout plan with council votes: votes first, then Scout fill.
            chosen = []
            for name, _ in vote_ranking:
                if name not in chosen:
                    chosen.append(name)
                if len(chosen) >= self.tools_per_round:
                    break
            for step in decision.get("toolPlan") or []:
                name = step.get("tool")
                if name and name not in chosen and name not in used_tools and name in ARSENAL:
                    chosen.append(name)
                if len(chosen) >= self.tools_per_round:
                    break

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
                "memory_trace": memory_trace,
                "chosen_tools": chosen,
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
            },
        }
