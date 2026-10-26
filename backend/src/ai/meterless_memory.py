"""Meterless H-MEM–style local memory for the threat council."""

from datetime import datetime, timezone
import re


def _now():
    return datetime.now(timezone.utc).isoformat()


def _tokens(text):
    return set(re.findall(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}", (text or "").lower()))


class MemoryStore:
    """In-process memory store matching the H-MEM service boundary."""

    def __init__(self):
        self._items = []

    def hydrate(self):
        return len(self._items)

    def add(self, kind, text, meta=None):
        item = {
            "id": f"m-{len(self._items) + 1}",
            "kind": kind,
            "text": text,
            "meta": meta or {},
            "created_at": _now(),
        }
        self._items.append(item)
        return item

    def all(self):
        return list(self._items)


class MemoryRetrieval:
    def __init__(self, store):
        self.store = store

    def query(self, text, top_n=5, threshold=0.0, strategy="comprehensive"):
        query_tokens = _tokens(text)
        scored = []
        for item in self.store.all():
            item_tokens = _tokens(item["text"]) | _tokens(json_dumps(item.get("meta")))
            if not query_tokens or not item_tokens:
                score = 0.1 if strategy == "comprehensive" else 0.0
            else:
                score = len(query_tokens & item_tokens) / max(len(query_tokens), 1)
            if score >= threshold:
                scored.append((score, item))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        memories = [item for _, item in scored[:top_n]]
        return {
            "memories": memories,
            "trace": {
                "strategy": strategy,
                "query": text,
                "hits": len(memories),
                "engine": "meterless-hmem-local",
            },
        }


def json_dumps(value):
    if isinstance(value, dict):
        return " ".join(f"{key} {json_dumps(val)}" for key, val in value.items())
    if isinstance(value, list):
        return " ".join(json_dumps(item) for item in value)
    return str(value or "")


def format_reinjection(memories):
    if not memories:
        return "No prior council memory."
    lines = ["Council memory:"]
    for item in memories:
        lines.append(f"- [{item.get('kind')}] {item.get('text')}")
    return "\n".join(lines)
