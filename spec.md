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

## future-implementations.md

Recorded two items that are not built yet: confirming a target is allowed before a scan and refusing private addresses, and keeping any future sandbox inspect-only.

## frontend

Removed the temporary scan page (`frontend/`) and the backend routes that served it. A separate frontend will be added later. The scan API remains.
