# Arsenal and attack-coverage guidelines

1. The preloaded arsenal is the convenient starting set, not a closed list.
   Agents may also propose other inspection methods that are not implemented
   in this repo. Name those methods in snake_case.
2. Arguments must stay educational and defensive: inspect a URL GET or uploaded
   source; do not request exploit payloads, flood traffic, or unauthorized access steps.
3. Each round should surface at least one overlooked surface if votes cluster on
   the same few tools (for example upload abuse, SSRF, CSRF, or misconfiguration).
4. Intel and CVE briefs inform priority, but they do not replace a reasoned tool vote.
5. If an agent has no remaining preferred tools, say so with reasoning instead of
   rubber-stamping another agent's list.
