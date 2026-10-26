# Spec

Backend for the GenWorks Open Agent Hackathon cyber risk app.

- Integrates **Zetaris** (data layer) via REST SQL for company threat context.
- Integrates **Meterless** patterns: Scout intent routing, H-MEM memory, and a parallel agent council (swarm-style debate).
- The AI only runs tools registered in `src/ai/tool.py` (defensive arsenal).
- Tools inspect a URL GET or uploaded source. They do not execute uploaded code or run exploits.
- `requirements.txt` lists FastAPI, Uvicorn, multipart, and Pydantic.
- Root `.env.example` documents `ZETARIS_*` and `METERLESS_*` settings.
- `test_backend.py` checks the arsenal, council debate flow, Zetaris SQL guard, Scout contracts, and `/health`.
