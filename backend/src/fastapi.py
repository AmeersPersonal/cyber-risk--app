"""HTTP API for URL and source scans."""

import importlib
import sys
from pathlib import Path


def _fastapi_package():
    here = str(Path(__file__).resolve().parent)
    removed = []
    while here in sys.path:
        sys.path.remove(here)
        removed.append(here)
    held = sys.modules.pop("fastapi", None)
    try:
        return importlib.import_module("fastapi")
    finally:
        for path in reversed(removed):
            sys.path.insert(0, path)
        if held is not None and held is not sys.modules.get("fastapi"):
            sys.modules["cyber_risk_fastapi_local"] = held


def create_app():
    fastapi = _fastapi_package()
    FastAPI = fastapi.FastAPI
    File = fastapi.File
    UploadFile = fastapi.UploadFile
    from pydantic import BaseModel, HttpUrl

    from ai.main import files_from_zip, run_scan
    from ai.tool import list_tools
    from ai.cve_manger import load_summary

    app = FastAPI(title="Cyber Risk Scan API")

    class UrlScan(BaseModel):
        url: HttpUrl
        company: str | None = None

    @app.get("/health")
    def health():
        from ai.zetaris_client import is_configured

        return {
            "status": "ok",
            "engines": {
                "zetaris_configured": is_configured(),
                "meterless": ["scout-local", "hmem-local", "threat-council"],
            },
        }

    @app.get("/tools")
    def tools():
        return {"tools": list_tools()}

    @app.get("/cves")
    def cves():
        return load_summary()

    @app.post("/scan/url")
    def scan_url(body: UrlScan):
        return run_scan(
            {"kind": "url", "url": str(body.url)},
            company_hint=body.company or str(body.url),
        )

    @app.post("/scan/source")
    async def scan_source(archive: UploadFile = File(...), company: str | None = None):
        data = await archive.read()
        files = files_from_zip(data)
        return run_scan(
            {"kind": "source", "files": files},
            company_hint=company or archive.filename or "uploaded-source",
        )

    return app
