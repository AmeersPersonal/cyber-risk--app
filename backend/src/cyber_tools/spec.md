# Spec

Implemented the preloaded cyber-tool arsenal the AI must use instead of writing its own scripts.

Each tool inspects a URL response or uploaded source and returns findings. None of the tools send attack payloads, build exploit pages, steal sessions, or transfer files.

Original tools:

- `session.py` checks Secure, HttpOnly, and SameSite cookie flags.
- `website_element_manipulation.py` checks CSP, script integrity, and CSRF tokens on POST forms.
- `pen_test.py` checks HTTPS, common security headers, and stack disclosure for CVE matching.

Duplicate checks were removed so the same issue is not scored twice: `click_jacking.py` (covered by `clickjacking.py`), `sql_inject.py` (covered by `injection.py`), and `file_trasnfer.py` (covered by `file_upload_abuse.py`).

Attack-type tools (one file per common web attack category; defensive checks only):

- `injection.py` — SQL, command, NoSQL, LDAP string-built sinks in source
- `xss.py` — CSP script policy and unsafe HTML rendering sinks
- `csrf.py` — POST form tokens and CSRF middleware / exemptions
- `broken_authentication.py` — weak password handling and Basic auth signals
- `access_control.py` — routes without auth and direct object references
- `ssrf.py` — user-controlled server-side fetches without allowlists
- `file_upload_abuse.py` — upload inputs and handlers missing type or size checks
- `clickjacking.py` — frame-control headers and CSP frame-ancestors
- `business_logic.py` — client-trusted price, quantity, coupon, or balance fields
- `api_mass_assignment.py` — wholesale request-to-model binding
- `denial_of_service.py` — missing rate limits and expensive unbounded work
- `supply_chain.py` — unlocked manifests and third-party scripts without integrity
- `misconfiguration.py` — HTTPS, security headers, and debug mode
- `cryptographic_failures.py` — hard-coded secrets and weak crypto
- `account_takeover.py` — weak password-reset and open-redirect patterns
