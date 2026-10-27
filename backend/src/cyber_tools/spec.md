# Spec

Implemented the preloaded cyber-tool arsenal. Agents use it as the convenient starting set and may also name other inspection methods.

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
- `user_enumeration.py` — login, signup, and reset messages that reveal whether an account exists
- `ddos.py` — edge-protection headers and request size or connection caps
- `rate_limit.py` — limiter coverage on auth and API routes, and rate-limit response headers
- `load_balancing.py` — trusted-proxy handling and shared sessions when a balancer is configured
- `cors.py` — wildcard or reflected CORS origins, including credentialed responses
- `path_traversal.py` — request data joined into a filesystem path
- `xxe.py` — XML parsers without external-entity protection
- `insecure_deserialization.py` — pickle, unsafe YAML, PHP unserialize, and Java object streams
- `ssti.py` — template engines rendering request data
- `oauth.py` — missing OAuth state, open redirect URIs, and tokens in the query string
- `jwt.py` — localStorage token storage, missing expiry, and hardcoded HMAC secrets
- `prototype_pollution.py` — request objects merged into application objects
- `graphql.py` — introspection left on and queries without a depth or cost limit
- `session_fixation.py` — login that keeps the pre-authentication session id
- `security_logging.py` — login, reset, and access-denied paths without an audit log
- `tls_posture.py` — HSTS max-age, certificate expiry on the fetched connection, and disabled TLS verification
- `sensitive_data.py` — responses that return password hashes, card numbers, or government identifiers
- `cloud_config.py` — root containers, image ENV secrets, privileged mode, and public storage ACLs

These checks only read the fetched response or uploaded source. They do not guess usernames, send repeated requests, submit crafted documents, start authorization flows, or change cloud resources.
