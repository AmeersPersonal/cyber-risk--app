# Spec

Revamped the AI layer into a Meterless-style threat council with Zetaris intel.

- `zetaris_client.py` — Zetaris REST adapter (`POST /sql-editor/sqls/run-query`) for read-only Lightning SQL. Uses `ZETARIS_*` env vars. Falls back locally when unset.
- `meterless_memory.py` — H-MEM–style `MemoryStore` / `MemoryRetrieval` for council arguments and findings.
- `meterless_scout.py` — Scout–style intent router that emits an execution contract and tool plan from the defensive arsenal only.
- `council.py` — Parallel agent council (recon, attacker_mindset, defender, intel, upload_forms). Agents propose and argue; Scout arbitrates; chosen arsenal tools run in parallel each round. Wired to `DebateManager` for guideline prompts, collision resolution, and per-agent storage.
- `debate_manger.py` — Debate manager: loads `guidlines/`, rejects bare agree/disagree, resolves duplicate parallel tool votes, fills overlooked arsenal checks, stores context in `local_debate_storage/`, and ships a sample round under `sample_conservations/`.
- `tool.py` — Preloaded cyber-tool arsenal (AI may only call these).
- `cve_manger.py` — Fetches CVE metadata from CISA KEV, NIST NVD, and OSV; merges by CVE id for cross-checking; matches stack fingerprints. Does not download or run exploits.
- `cve_knowledge.py` — On initialization, seeds `cve_knowledge/common_cves.json` and `cve_knowledge/zero_days/<cve_name>.json` with name, how it works, and defend_against. Used as agent context and after-action defenses.
- `main.py` — Prepares URL/source targets, runs the council, matches CVEs, returns a NIST-scored report with narrative and after-action steps.
- `summary.json` — Multi-source CVE summary cache.
