# Spec

Local CVE knowledge store seeded on AI initialization.

- `common_cves.json` — JSON list of common CVE names used for fast agent context.
- `zero_days/<cve_name>.json` — one file per CVE with `cve_name`, `how_it_works`, and `defend_against`.
- `defend_against` is preferred text for after-action remediation steps.
- Managed by `../cve_knowledge.py` (`initialize_cve_knowledge` on startup).
