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
    HTTPException = fastapi.HTTPException
    UploadFile = fastapi.UploadFile
    Response = fastapi.Response
    from pydantic import BaseModel, HttpUrl

    from ai.main import files_from_zip, run_scan
    from ai.model_client import ModelClient
    from ai.tool import list_tools
    from report import render_pdf

    app = FastAPI(title="Cyber Risk Scan API")

    def _report_format(fmt):
        value = (fmt or "json").strip().lower()
        if value not in {"json", "pdf"}:
            raise HTTPException(status_code=400, detail="format must be json or pdf")
        return value

    def _pdf_download(report):
        data = render_pdf(report)
        return Response(
            content=data,
            media_type="application/pdf",
            headers={
                "Content-Disposition": 'attachment; filename="cyber-risk-report.pdf"'
            },
        )

    def _respond(report, fmt):
        if _report_format(fmt) == "pdf":
            return _pdf_download(report)
        return report

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
                "model_configured": ModelClient().configured(),
            },
        }

    @app.get("/tools")
    def tools():
        return {"tools": list_tools()}

    @app.get("/cves")
    def cves():
        from ai.cve_manger import fetch_cves_from_zetaris, cross_check_summary
        from ai.zetaris_client import ZetarisClient

        client = ZetarisClient()
        items, ok = fetch_cves_from_zetaris(client, limit=100)
        if not ok:
            raise HTTPException(status_code=503, detail="Zetaris is not configured or unreachable")
        return {
            "source": "zetaris",
            "count": len(items),
            "items": items,
            "cross_check": cross_check_summary(items),
        }

    @app.post("/scan/url")
    def scan_url(body: UrlScan, format: str = "json"):
        chosen = _report_format(format)
        report = run_scan(
            {"kind": "url", "url": str(body.url)},
            company_hint=body.company or str(body.url),
        )
        return _respond(report, chosen)

    @app.post("/scan/source")
    async def scan_source(
        archive: UploadFile = File(...),
        company: str | None = None,
        format: str = "json",
    ):
        chosen = _report_format(format)
        data = await archive.read()
        files = files_from_zip(data)
        report = run_scan(
            {"kind": "source", "files": files},
            company_hint=company or archive.filename or "uploaded-source",
        )
        return _respond(report, chosen)

    @app.post("/report/pdf")
    def download_report(report: dict):
        return _pdf_download(report)

    return app
