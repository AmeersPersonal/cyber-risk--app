# Spec

## .gitignore

Added a root `.gitignore` for a Python AI cyber threat analysis agent.

Ignored paths:

- Python bytecode, build output, virtual environments, and tool caches
- Secrets (`.env`, keys, and credential files), while keeping `.env.example`
- Local model weights and AI caches
- Local threat-analysis artifacts: logs, intel cache, vector stores, packet captures, and raw data

`test_gitignore.py` checks that those paths are ignored and that source files stay trackable.
