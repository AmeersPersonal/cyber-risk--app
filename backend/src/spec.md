# Spec

Implemented the backend scan API and report builder around the threat council.

- `report.py` builds a scan report from tool findings, matched CVEs, and council debate/memory/intel.
- `fastapi.py` exposes `/health` (includes Zetaris/Meterless engine status), `/tools`, `/cves`, `/scan/url`, and `/scan/source`.
- `main.py` starts the API on 127.0.0.1:8000 without shadowing the FastAPI package.
- URL scans perform a single GET and inspect the response. Uploaded source is read, not executed.
- Scans are driven by the parallel Meterless council, not a blind run of every tool.

`backend/test_backend.py` covers the report, arsenal, council, Zetaris read-only guard, Scout routing, CVE matching, and API health route.
