# Spec

## AGENTS.md

Added a Project section stating this repository is for the GenWorks Open Agent Hackathon. The application tests websites and applications from a URL or uploaded source code inside a safe environment, and uses libraries to track the latest zero-day CVEs and test the user's application against them.

`test_agents_md.py` checks that this section is present.

## .gitignore

Added a root `.gitignore` for a Python AI cyber threat analysis agent.

Ignored paths:

- Python bytecode, build output, virtual environments, and tool caches
- Secrets (`.env`, keys, and credential files), while keeping `.env.example`
- Local model weights and AI caches
- Local threat-analysis artifacts: logs, intel cache, vector stores, packet captures, and raw data

`test_gitignore.py` checks that those paths are ignored and that source files stay trackable.

## safety.py

Added scan-scope checks, ownership proof, and optional stay-inspect mode. Stay-inspect is off unless the request sets `stay_inspect` and `override_command`. A URL scan requires the site to serve an issued token at `/.well-known/cyber-risk-verify.txt`, and that proof must pass before the agents run. A source scan reads owner labels (`cyber-risk-owner.txt`, copyright lines, and author fields). A label that does not match the caller refuses the scan. Source with no owner label continues and is assumed to be theirs. Private, loopback, and link-local hosts are refused.

`test_safety.py` checks those refusals.

## future-implementations.md

Records the ownership and stay-inspect work. A labeled source owner that does not match is refused. Source with no owner label is assumed to be the caller's. Stay-inspect stays off unless override is pressed.

## README.md

Added a root README for the GenWorks Open Agent Hackathon. It describes the inspect-only scan API and states that the project is for education. The disclaimer provides the software "AS IS" and disclaims liability to the maximum extent permitted by law. Use is limited to systems the caller owns or has explicit permission to test.

`test_readme.py` checks that the hackathon, education, and liability language is present.

## frontend

Removed the temporary scan page (`frontend/`) and the backend routes that served it. A separate frontend will be added later. The scan API remains.
