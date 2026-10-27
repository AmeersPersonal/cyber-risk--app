# Spec

Local CVE knowledge store seeded on AI initialization.

- `common_cves.json` — JSON list of commonly exploited CVE names from the public CISA Known Exploited Vulnerabilities catalog, used for fast agent context. The original seeded names stay first.
- `zero_days/<cve_name>.json` — detailed files for the seeded CVEs, with `cve_name`, `how_it_works`, and `defend_against`. Catalog IDs do not each get a file.
- `defend_against` is preferred text for after-action remediation steps.
- Managed by `../cve_knowledge.py` (`initialize_cve_knowledge` on startup).
