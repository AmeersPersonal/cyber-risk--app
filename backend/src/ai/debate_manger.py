"""Debate manager: guidelines, reasoned arguments, and parallel collision control."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import re
import threading
from pathlib import Path
from uuid import uuid4

from ai.tool import ARSENAL, normalize_method

AI_DIR = Path(__file__).resolve().parent
GUIDLINES_DIR = AI_DIR / "guidlines"
SAMPLE_DIR = AI_DIR / "sample_conservations"
STORAGE_DIR = AI_DIR / "local_debate_storage"

_BARE_STANCE = re.compile(
    r"^\s*(i\s+)?(agree|disagree|same|ok|\+1|looks\s+good|yes|no|correct|wrong)"
    r"[\s.!]*$",
    re.IGNORECASE,
)
_REASON_MARKERS = re.compile(
    r"\b(because|since|due\s+to|therefore|so\s+that|evidence|finding|cve|"
    r"target|tool|should|prioritize|risk|justify|reason)\b",
    re.IGNORECASE,
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_id(value):
    text = re.sub(r"[^a-zA-Z0-9_\-]+", "_", (value or "").strip())
    return text or "unknown"


class DebateManager:
    """Keeps parallel agents reasoned and resolves colliding tool proposals.

    Guidelines live in ``guidlines/``. Per-agent context is persisted under
    ``local_debate_storage/``. Sample moderated rounds live in
    ``sample_conservations/``.
    """

    OVERLOOKED_PRIORITY = (
        "ssrf",
        "file_upload_abuse",
        "csrf",
        "misconfiguration",
        "injection",
        "xss",
        "access_control",
        "broken_authentication",
        "cryptographic_failures",
        "supply_chain",
        "user_enumeration",
        "ddos",
        "rate_limit",
        "load_balancing",
        "cors",
        "path_traversal",
        "xxe",
        "insecure_deserialization",
        "ssti",
        "oauth",
        "jwt",
        "prototype_pollution",
        "graphql",
        "session_fixation",
        "security_logging",
        "tls_posture",
        "sensitive_data",
        "cloud_config",
    )

    def __init__(
        self,
        guidelines_dir=None,
        storage_dir=None,
        sample_dir=None,
        session_id=None,
    ):
        self.guidelines_dir = Path(guidelines_dir) if guidelines_dir else GUIDLINES_DIR
        self.storage_dir = Path(storage_dir) if storage_dir else STORAGE_DIR
        self.sample_dir = Path(sample_dir) if sample_dir else SAMPLE_DIR
        self.session_id = session_id or f"debate-{uuid4().hex[:12]}"
        self._lock = threading.Lock()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._guidelines = None

    def load_guidelines(self, force=False):
        """Load markdown guidelines as ordered sections for model prompts."""
        if self._guidelines is not None and not force:
            return self._guidelines

        sections = []
        if self.guidelines_dir.exists():
            for path in sorted(self.guidelines_dir.glob("*.md")):
                sections.append(
                    {
                        "id": path.stem,
                        "title": path.stem.replace("_", " "),
                        "path": str(path),
                        "text": path.read_text(encoding="utf-8").strip(),
                    }
                )
        self._guidelines = sections
        return sections

    def guidelines_prompt(self):
        """Compact system text to inject into agent / model instructions."""
        sections = self.load_guidelines()
        if not sections:
            return (
                "Debate rules: never agree or disagree without reasoning; "
                "justify every tool vote; resolve duplicate votes toward overlooked attacks."
            )
        blocks = ["Debate manager guidelines (must follow):"]
        for section in sections:
            blocks.append(f"## {section['title']}\n{section['text']}")
        return "\n\n".join(blocks)

    def validate_argument(self, argument):
        """Return whether an agent argument satisfies reasoning guidelines."""
        text = (argument or "").strip()
        violations = []
        if not text:
            violations.append("empty_argument")
        elif _BARE_STANCE.match(text):
            violations.append("bare_agree_disagree")
        elif len(text.split()) < 8:
            violations.append("too_short")
        elif not _REASON_MARKERS.search(text):
            # Allow longer role statements that already name tools/targets.
            if "should" not in text.lower() and "run" not in text.lower():
                violations.append("missing_reasoning_marker")
        return {
            "ok": not violations,
            "violations": violations,
            "argument": text,
        }

    def detect_collisions(self, proposals):
        """Find duplicate tool votes and invalid unreasoned stances."""
        tool_owners = {}
        collisions = []
        for proposal in proposals or []:
            agent = proposal.get("agent") or "unknown"
            check = self.validate_argument(proposal.get("argument"))
            if not check["ok"]:
                collisions.append(
                    {
                        "type": "unreasoned_stance",
                        "agent": agent,
                        "violations": check["violations"],
                        "argument": check["argument"],
                    }
                )
            for tool in proposal.get("votes") or []:
                tool_owners.setdefault(tool, []).append(agent)

        for tool, agents in sorted(tool_owners.items()):
            if len(agents) > 1:
                collisions.append(
                    {
                        "type": "duplicate_tool",
                        "tool": tool,
                        "agents": agents,
                    }
                )
        return collisions

    def overlooked_tools(self, proposals, used_tools):
        """Arsenal tools nobody voted for, ordered by coverage priority."""
        used = set(used_tools or [])
        voted = set()
        for proposal in proposals or []:
            for tool in proposal.get("votes") or []:
                if tool in ARSENAL:
                    voted.add(tool)
        overlooked = []
        for tool in self.OVERLOOKED_PRIORITY:
            if tool in ARSENAL and tool not in used and tool not in voted:
                overlooked.append(tool)
        for tool in ARSENAL:
            if tool not in used and tool not in voted and tool not in overlooked:
                overlooked.append(tool)
        return overlooked

    def resolve_collisions(self, proposals, used_tools=None, max_tools=4):
        """Pick tools after filtering unreasoned votes and filling overlooked gaps."""
        used_tools = set(used_tools or [])
        collisions = self.detect_collisions(proposals)
        invalid_agents = {
            item["agent"]
            for item in collisions
            if item.get("type") == "unreasoned_stance"
        }

        scores = {}
        reasons = {}
        for proposal in proposals or []:
            agent = proposal.get("agent")
            if agent in invalid_agents:
                continue
            check = self.validate_argument(proposal.get("argument"))
            weight = 2 if check["ok"] else 0
            for index, tool in enumerate(proposal.get("votes") or []):
                method = normalize_method(tool)
                if not method or method in used_tools:
                    continue
                rank = max(3 - index, 1)
                scores[method] = scores.get(method, 0) + weight * rank
                reasons.setdefault(method, []).append(
                    {
                        "agent": agent,
                        "argument": proposal.get("argument"),
                        "rank": index + 1,
                    }
                )

        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        chosen = []
        for tool, _score in ranked:
            if tool not in chosen:
                chosen.append(tool)
            if len(chosen) >= max_tools:
                break

        # Collision free-up: if duplicates dominated, ensure overlooked coverage.
        duplicates = [
            item["tool"]
            for item in collisions
            if item.get("type") == "duplicate_tool" and item.get("tool") in chosen
        ]
        overlooked = self.overlooked_tools(proposals, used_tools)
        if duplicates and overlooked and len(chosen) >= max_tools:
            # Replace the weakest duplicate slot with an overlooked tool.
            for tool in list(reversed(chosen)):
                # A method outside the starting set stays when agents voted for it.
                if tool in duplicates and tool in ARSENAL and overlooked:
                    chosen.remove(tool)
                    fill = overlooked.pop(0)
                    if fill not in chosen:
                        chosen.append(fill)
                        reasons.setdefault(fill, []).append(
                            {
                                "agent": "debate_manager",
                                "argument": (
                                    "Inserted overlooked attack surface after "
                                    f"duplicate collision on {tool}."
                                ),
                                "rank": 0,
                            }
                        )
                    break

        while len(chosen) < max_tools and overlooked:
            fill = overlooked.pop(0)
            if fill not in chosen and fill not in used_tools:
                chosen.append(fill)
                reasons.setdefault(fill, []).append(
                    {
                        "agent": "debate_manager",
                        "argument": "Filled open slot with overlooked arsenal check.",
                        "rank": 0,
                    }
                )

        resolution = {
            "chosen_tools": chosen,
            "collisions": collisions,
            "invalid_agents": sorted(invalid_agents),
            "vote_scores": ranked,
            "reasons": reasons,
            "guidelines_applied": [section["id"] for section in self.load_guidelines()],
        }
        return resolution

    def agent_storage_path(self, agent_name):
        session_dir = self.storage_dir / _safe_id(self.session_id)
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir / f"{_safe_id(agent_name)}.json"

    def store_agent_context(self, agent_name, entry):
        """Append a context entry for one agent in this debate session."""
        path = self.agent_storage_path(agent_name)
        with self._lock:
            existing = []
            if path.exists():
                try:
                    existing = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    existing = []
                if not isinstance(existing, list):
                    existing = [existing]
            record = {
                "stored_at": _now(),
                "session_id": self.session_id,
                "agent": agent_name,
                **(entry or {}),
            }
            existing.append(record)
            path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        return path

    def load_agent_context(self, agent_name):
        path = self.agent_storage_path(agent_name)
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        return data if isinstance(data, list) else [data]

    def store_round(self, round_index, proposals, resolution):
        """Persist each agent's proposal and the manager resolution for a round."""
        paths = []
        for proposal in proposals or []:
            agent = proposal.get("agent") or "unknown"
            paths.append(
                self.store_agent_context(
                    agent,
                    {
                        "round": round_index,
                        "proposal": proposal,
                        "validation": self.validate_argument(proposal.get("argument")),
                    },
                )
            )
        paths.append(
            self.store_agent_context(
                "debate_manager",
                {
                    "round": round_index,
                    "resolution": resolution,
                },
            )
        )
        return paths

    def moderate_round(self, round_index, proposals, used_tools=None, max_tools=4):
        """Validate, resolve collisions, store context, return moderated result."""
        resolution = self.resolve_collisions(
            proposals,
            used_tools=used_tools,
            max_tools=max_tools,
        )
        self.store_round(round_index, proposals, resolution)
        return {
            "round": round_index,
            "session_id": self.session_id,
            "guidelines_prompt": self.guidelines_prompt(),
            "proposals": proposals,
            "resolution": resolution,
            "chosen_tools": resolution["chosen_tools"],
            "collisions": resolution["collisions"],
        }

    def load_sample_conversation(self, name="sample_round.json"):
        path = self.sample_dir / name
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def run_proposals_parallel(self, workers, max_workers=None):
        """Run callables in parallel (agent proposal workers) and collect results."""
        results = []
        if not workers:
            return results
        workers = list(workers)
        limit = max_workers or max(len(workers), 1)
        with ThreadPoolExecutor(max_workers=limit) as pool:
            futures = [pool.submit(fn) for fn in workers]
            for future in as_completed(futures):
                results.append(future.result())
        return results
