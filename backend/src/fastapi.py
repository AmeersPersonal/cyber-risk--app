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

    src = Path(__file__).resolve().parent
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    import safety

    from ai.main import files_from_zip, run_scan
    from ai.model_client import ModelClient
    from ai.tool import list_tools
    from ai.cve_manger import load_summary
    from report import render_pdf

    app = FastAPI(title="Cyber Risk Scan API")
    app.state.ownership = safety.OwnershipStore()
    app.state.resolve = None
    app.state.proof_reader = safety.read_proof_body

    def _refuse(exc):
        raise HTTPException(status_code=403, detail=str(exc)) from exc

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

    class UrlProof(BaseModel):
        url: HttpUrl

    class UrlScan(BaseModel):
        url: HttpUrl
        company: str | None = None
        ownership_token: str
        stay_inspect: bool = False
        override_command: bool = False

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
        return load_summary()

    @app.post("/verify/url")
    def verify_url(body: UrlProof):
        try:
            issued = app.state.ownership.issue_url(str(body.url), resolve=app.state.resolve)
        except safety.UnsafeTarget as exc:
            _refuse(exc)
        return {
            "token": issued["token"],
            "place_at": issued["place_at"],
            "instructions": (
                "Save the token as the entire contents of that URL, then scan with ownership_token."
            ),
        }

    @app.post("/verify/source")
    def verify_source():
        issued = app.state.ownership.issue_source()
        return {
            "token": issued["token"],
            "file": issued["file"],
            "instructions": (
                "Save the token as the entire contents of cyber-risk-owner.txt at the archive root."
            ),
        }

    @app.post("/scan/url")
    def scan_url(body: UrlScan, format: str = "json"):
        chosen = _report_format(format)
        try:
            stay_inspect = safety.stay_inspect_enabled(body.stay_inspect, body.override_command)
            safety.verify_url_ownership(
                str(body.url),
                body.ownership_token,
                app.state.ownership,
                lambda location: app.state.proof_reader(location, resolve=app.state.resolve),
                resolve=app.state.resolve,
            )
        except safety.UnsafeTarget as exc:
            _refuse(exc)
        try:
            report = run_scan(
                {
                    "kind": "url",
                    "url": str(body.url),
                    "ownership_verified": True,
                    "ownership_checked": True,
                },
                company_hint=body.company or str(body.url),
                stay_inspect=stay_inspect,
            )
        except safety.UnsafeTarget as exc:
            _refuse(exc)
        return _respond(report, chosen)

    @app.post("/scan/source")
    async def scan_source(
        archive: UploadFile = File(...),
        ownership_token: str = "",
        company: str | None = None,
        format: str = "json",
        stay_inspect: bool = False,
        override_command: bool = False,
    ):
        chosen = _report_format(format)
        data = await archive.read()
        try:
            inspect_mode = safety.stay_inspect_enabled(stay_inspect, override_command)
            safety.check_archive(data)
            files = files_from_zip(data)
            ownership = safety.verify_source_ownership(
                files,
                ownership_token,
                app.state.ownership,
                claimed_owner=company or "",
            )
        except safety.UnsafeTarget as exc:
            _refuse(exc)
        files.pop(safety.OWNER_FILE, None)
        try:
            report = run_scan(
                {
                    "kind": "source",
                    "files": files,
                    "ownership_checked": True,
                    "ownership_assumed": ownership["assumed"],
                },
                company_hint=company or archive.filename or "uploaded-source",
                stay_inspect=inspect_mode,
            )
        except safety.UnsafeTarget as exc:
            _refuse(exc)
        return _respond(report, chosen)

    @app.post("/report/pdf")
    def download_report(report: dict):
        return _pdf_download(report)

    return app
