# Spec

Backend for the GenWorks Open Agent Hackathon cyber risk app.

- Integrates **Zetaris** (data layer) via REST SQL for company threat context.
- Integrates **Meterless** patterns: Scout intent routing, H-MEM memory, and a parallel agent council (swarm-style debate).
- `DebateManager` enforces reasoning guidelines, resolves parallel tool collisions, and stores per-agent debate context.
- CVE intel is fetched from **CISA KEV**, **NIST NVD**, and **OSV**, then cross-checked by CVE id.
- Reports use a **1-10** risk score. It is marked confirmed CVSS only when a version-matched CVE includes a numeric CVSS value; otherwise the label is heuristic. Reports include narrative, pass/fail tool outcomes, CVEs tried/matched, and an after-action remediation plan. The same report can be downloaded as a PDF from `POST /report/pdf`, or from `/scan/url` and `/scan/source` with `format=pdf`.
- CVE matches require an exact manifest version inside the affected range (OSV query plus CISA KEV badge). Duplicate arsenal checks were removed.
- Council agents call an OpenAI-compatible model when `METERLESS_API_KEY` is set. The preloaded arsenal is their starting set. They may also name other inspection methods.
- The temporary scan page was removed. The API stays JSON and PDF so a separate frontend can be added later.
- Scans require ownership proof from `safety.py` before the agents run. A site must serve the well-known token. Uploaded source is refused when a labeled owner does not match the caller. Source with no owner label is assumed to be theirs. Private and local hosts are refused. Stay-inspect mode is off by default. The caller turns it on with `stay_inspect` plus `override_command`.
- The preloaded tools in `src/ai/tool.py` are the convenient starting set. That set includes the earlier web checks plus CORS, path traversal, XXE, insecure deserialization, SSTI, OAuth, JWT, prototype pollution, GraphQL, session fixation, security logging, TLS posture, sensitive data, and cloud config. Agents may also run other snake_case inspection methods against the fetched response or uploaded source.
- Tools inspect a URL GET or uploaded source. They do not execute uploaded code or run exploits.
- `requirements.txt` lists FastAPI, Uvicorn, multipart, and Pydantic.
- Root `.env.example` documents `ZETARIS_*` and `METERLESS_*` settings.
- `test_backend.py` checks the arsenal, the user-enumeration, DDoS, rate-limit, and load-balancing checks, council debate flow, debate manager guidelines/collisions, multi-source CVE merge, NIST score/AAR, PDF download, and `/health`.
