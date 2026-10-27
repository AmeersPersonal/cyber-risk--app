"""Zetaris REST client for governed threat-intel queries (read-only SQL)."""

import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def _load_dotenv_local():
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

READ_PREFIXES = ("select", "show", "describe", "desc", "explain")


def config_from_env():
    base = (os.getenv("ZETARIS_BASE_URL") or "http://localhost:3000").rstrip("/")
    return {
        "base_url": base,
        "query_path": "/api/proxy/sql-editor/sqls/run-query",
        "org_id": os.getenv("ZETARIS_ORG_ID") or "",
        "api_key": os.getenv("ZETARIS_API_KEY") or "",
        "query_limit": int(os.getenv("ZETARIS_QUERY_LIMIT") or "1000"),
        "threat_sql": (os.getenv("ZETARIS_THREAT_SQL") or "").strip(),
    }


def is_configured(cfg=None):
    cfg = cfg or config_from_env()
    return bool(cfg.get("api_key") and cfg.get("org_id"))


def assert_readonly_sql(sql):
    text = " ".join((sql or "").strip().split())
    if not text:
        raise ValueError("empty SQL")
    lowered = text.lower()
    if ";" in text.rstrip(";"):
        raise ValueError("only one Lightning SQL statement is allowed")
    if not any(lowered.startswith(prefix) for prefix in READ_PREFIXES):
        raise ValueError("only read-only SQL is allowed")
    return text


class ZetarisClient:
    """REST adapter via the Zetaris UI proxy: POST /api/proxy/sql-editor/sqls/run-query."""

    def __init__(self, cfg=None, opener=None):
        self.cfg = cfg or config_from_env()
        self.opener = opener or urllib.request.urlopen

    def configured(self):
        return is_configured(self.cfg)

    def _request(self, sql, limit=None):
        url = f"{self.cfg['base_url']}{self.cfg['query_path']}"
        body = {"sql": sql, "limit": limit or self.cfg["query_limit"]}
        payload = json.dumps(body).encode("utf-8")
        return urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.cfg['api_key']}",
                "X-Org-ID": str(self.cfg["org_id"]),
                "X-Request-ID": str(uuid.uuid4()),
                "Content-Type": "application/json",
                "User-Agent": "CyberRiskCouncil/1.0",
            },
        )

    def run_sql(self, sql):
        sql = assert_readonly_sql(sql)
        if not self.configured():
            return {
                "ok": False,
                "mode": "offline",
                "headers": [],
                "data": [],
                "error": "Zetaris is not configured; set ZETARIS_API_KEY and ZETARIS_ORG_ID",
            }

        try:
            with self.opener(self._request(sql), timeout=20) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
            return {
                "ok": False,
                "mode": "error",
                "headers": [],
                "data": [],
                "error": str(exc),
            }

        return {
            "ok": True,
            "mode": "zetaris",
            "headers": body.get("headers") or [],
            "data": body.get("data") or [],
            "raw": body,
        }

    def write_sql(self, sql):
        """Execute a write statement (CREATE, INSERT, DROP) for admin/setup use."""
        sql = " ".join((sql or "").strip().split())
        if not sql:
            raise ValueError("empty SQL")
        if not self.configured():
            return {
                "ok": False,
                "mode": "offline",
                "error": "Zetaris is not configured; set ZETARIS_API_KEY and ZETARIS_ORG_ID",
            }

        try:
            with self.opener(self._request(sql), timeout=20) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
            return {"ok": False, "mode": "error", "error": str(exc)}

        return {"ok": True, "mode": "zetaris", "raw": body}

    def company_threat_context(self, company_hint="", fingerprints=None):
        """Query Zetaris for company threat context, or return a local fallback."""
        fingerprints = fingerprints or []
        sql = self.cfg.get("threat_sql") or ""
        if sql and self.configured():
            result = self.run_sql(sql)
            if result.get("ok"):
                rows = []
                headers = result.get("headers") or []
                for row in result.get("data") or []:
                    if isinstance(row, dict):
                        rows.append(row)
                    elif isinstance(row, list) and headers:
                        rows.append(dict(zip(headers, row)))
                    else:
                        rows.append({"value": row})
                return {
                    "source": "zetaris",
                    "company": company_hint,
                    "rows": rows[:50],
                    "fingerprints": fingerprints,
                }

        return {
            "source": "local_fallback",
            "company": company_hint,
            "rows": [
                {
                    "note": "Configure ZETARIS_* and optional ZETARIS_THREAT_SQL for live intel",
                    "fingerprints": fingerprints[:8],
                }
            ],
            "fingerprints": fingerprints,
        }
