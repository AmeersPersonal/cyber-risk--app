"""OpenAI-compatible chat client for the threat council.

Uses METERLESS_BASE_URL, METERLESS_API_KEY, and METERLESS_MODEL.
When the key is unset, configured() is false and agents keep the local template.
"""

import json
import os
import re
import urllib.error
import urllib.request


def _load_dotenv_local():
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    for name in (".env.local", ".env"):
        path = root / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv_local()

_REASON = re.compile(r"\b(because|since|due\s+to|therefore)\b", re.IGNORECASE)


class ModelClient:
    def __init__(self, base_url=None, api_key=None, model=None, opener=None):
        self.base_url = (
            base_url if base_url is not None else os.getenv("METERLESS_BASE_URL") or ""
        ).rstrip("/")
        self.api_key = api_key if api_key is not None else (os.getenv("METERLESS_API_KEY") or "")
        self.model = model or os.getenv("METERLESS_MODEL") or "meterless/local"
        self.opener = opener or urllib.request.urlopen

    def configured(self):
        return bool(self.api_key and self.base_url)

    def complete(self, messages, timeout=25):
        """Return assistant text, or None when the model is unset or the call fails."""
        if not self.configured():
            return None
        body = json.dumps(
            {
                "model": self.model,
                "temperature": 0.2,
                "messages": messages,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self.opener(request, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError, KeyError, TypeError):
            return None
        try:
            return payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return None


def parse_model_decision(text, allowed_tools):
    """Read a JSON vote. Unknown tool names are dropped."""
    if not text:
        return None
    raw = text.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    argument = " ".join(str(data.get("argument") or "").split())
    allowed = set(allowed_tools or [])
    votes = []
    for name in data.get("votes") or []:
        if name in allowed and name not in votes:
            votes.append(name)
    if not argument or not votes:
        return None
    if not _REASON.search(argument):
        argument += " This is the next check because those tools match the evidence so far."
    return {"argument": argument[:1200], "votes": votes[:3]}
