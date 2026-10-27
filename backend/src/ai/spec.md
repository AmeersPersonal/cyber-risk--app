# Spec

Revamped the AI layer into a Meterless-style threat council with Zetaris intel.

- `zetaris_client.py` — Zetaris REST adapter via the UI proxy (`POST /api/proxy/sql-editor/sqls/run-query`). `run_sql` for read-only queries, `write_sql` for admin/setup DDL. Config: `ZETARIS_BASE_URL` (default `http://localhost:3000`), `ZETARIS_ORG_ID`, `ZETARIS_API_KEY`. Falls back locally when unset.
- `meterless_memory.py` — H-MEM–style `MemoryStore` / `MemoryRetrieval` for council arguments and findings.
- `meterless_scout.py` — Scout–style intent router that emits an execution contract and tool plan from the defensive arsenal only.
- `council.py` — Parallel agent council (recon, attacker_mindset, defender, intel, upload_forms). When a model key is set, each agent writes its argument and tool votes through `model_client`; otherwise it uses the local template. Scout still limits execution to the arsenal. Wired to `DebateManager` for guideline prompts, collision resolution, and per-agent storage.
- `debate_manger.py` — Debate manager: loads `guidlines/`, rejects bare agree/disagree, resolves duplicate parallel tool votes, fills overlooked arsenal checks, stores context in `local_debate_storage/`, and ships a sample round under `sample_conservations/`.
- `tool.py` — Preloaded cyber-tool arsenal (AI may only call these).
- `cve_manger.py` — CVE data layer. Queries Zetaris first via `CVE_PG.cve_items` (`fetch_cves_from_zetaris`); enriches with OSV affected ranges and KEV badges; falls back to direct API calls when Zetaris is unavailable. Matches CVEs only when an exact package version falls in the affected range. Does not download or run exploits.
- `manifests.py` — Reads exact versions from `requirements.txt`, `package.json`, `package-lock.json`, and `go.mod`.
- `model_client.py` — OpenAI-compatible council client. Calls the model only when `METERLESS_API_KEY` is set, and drops any tool vote outside the arsenal.
- `cve_knowledge.py` — On initialization, seeds `cve_knowledge/common_cves.json` and `cve_knowledge/zero_days/<cve_name>.json` with name, how it works, and defend_against. Used as agent context and after-action defenses.
- `setup_zetaris.py` — CLI script to populate Zetaris with CVE data. Creates the `cve_data` PostgreSQL database (in the Zetaris Docker stack), registers it as the `CVE_PG` datasource in Zetaris Lightning, fetches CVEs from NIST NVD / CISA KEV / OSV, and bulk-inserts into PostgreSQL. Queries go through `CVE_PG.cve_items`. Run with `python -m ai.setup_zetaris [--reset] [--limit N]`.
- `main.py` — Prepares URL/source targets, reads exact package versions, creates a shared `ZetarisClient` for both CVE queries and council intel, runs the council, matches CVEs by affected version, and returns a scored report with narrative and after-action steps.
