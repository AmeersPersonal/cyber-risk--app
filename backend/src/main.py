"""Start the scan API."""

import importlib.util
import sys
from pathlib import Path

import uvicorn

SRC = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def load_app():
    spec = importlib.util.spec_from_file_location("cyber_risk_api", SRC / "fastapi.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_app()


def main():
    uvicorn.run(load_app(), host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
