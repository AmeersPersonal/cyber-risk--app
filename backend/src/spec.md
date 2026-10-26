# Spec

Implemented the backend scan API and NIST-aligned report builder around the threat council.

- `report.py` builds a 1-10 risk score. The score is labeled `confirmed_cvss` when a version-matched CVE has a numeric CVSS value; otherwise it is labeled `heuristic`. Identical findings are counted once. The report still lists passed/failed tools, CVEs tried and matched, and an after-action plan. `render_pdf` turns that report into a PDF file.
- `fastapi.py` exposes `/health` (includes Zetaris/Meterless engine status and whether the council model key is set), `/tools`, `/cves`, `/scan/url`, `/scan/source`, and `/report/pdf`. Scan routes accept `format=json` (default) or `format=pdf`. `POST /report/pdf` accepts an existing report and returns `cyber-risk-report.pdf` as an attachment. The temporary scan page and `/static` routes were removed.
- `main.py` starts the API on 127.0.0.1:8000 without shadowing the FastAPI package.
- URL scans perform a single GET and inspect the response. Uploaded source is read, not executed.
- Scans are driven by the parallel Meterless council with debate-manager collision control. CVE intel is cross-checked across CISA KEV, NIST NVD, and OSV.

`backend/test_backend.py` covers the report score/narrative/AAR, PDF rendering, arsenal, council, debate manager, Zetaris read-only guard, Scout routing, multi-source CVE merge, API health, and the PDF download routes.
