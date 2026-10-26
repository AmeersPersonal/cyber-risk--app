# Spec

Implemented the backend scan API and NIST-aligned report builder around the threat council.

- `report.py` builds a NIST/CVSS-aligned 1-10 risk score, coherent score explanation, passed/failed tools, CVEs tried and matched, and an after-action remediation plan that prefers local `defend_against` text from CVE knowledge files.
- `fastapi.py` exposes `/health` (includes Zetaris/Meterless engine status), `/tools`, `/cves`, `/scan/url`, and `/scan/source`.
- `main.py` starts the API on 127.0.0.1:8000 without shadowing the FastAPI package.
- URL scans perform a single GET and inspect the response. Uploaded source is read, not executed.
- Scans are driven by the parallel Meterless council with debate-manager collision control. CVE intel is cross-checked across CISA KEV, NIST NVD, and OSV.

`backend/test_backend.py` covers the report score/narrative/AAR, arsenal, council, debate manager, Zetaris read-only guard, Scout routing, multi-source CVE merge, and API health route.
