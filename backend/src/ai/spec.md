# Spec

Revamped the AI layer into a Meterless-style threat council with Zetaris intel.

- `zetaris_client.py` — Zetaris REST adapter (`POST /sql-editor/sqls/run-query`) for read-only Lightning SQL. Uses `ZETARIS_*` env vars. Falls back locally when unset.
- `meterless_memory.py` — H-MEM–style `MemoryStore` / `MemoryRetrieval` for council arguments and findings.
- `meterless_scout.py` — Scout–style intent router that emits an execution contract and tool plan from the defensive arsenal only.
- `council.py` — Parallel agent council (recon, attacker_mindset, defender, intel, upload_forms). Agents propose and argue; Scout arbitrates; chosen arsenal tools run in parallel each round.
- `tool.py` — Preloaded cyber-tool arsenal (AI may only call these).
- `cve_manger.py` — CISA KEV metadata matching (no exploit download).
- `main.py` — Prepares URL/source targets, runs the council, matches CVEs, returns a report with debate + memory + intel.
- `summary.json` — CVE summary cache.
