"""HTTP API for URL and source scans."""

import importlib
import io
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


def _parse_github_repository(value):
    raw = value.strip()
    if "://" not in raw:
        raw = f"https://github.com/{raw}"
    parsed = urllib.parse.urlparse(raw)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Enter a GitHub repository URL or owner/repository.")

    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise ValueError("Enter a GitHub repository URL or owner/repository.")
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    if (
        not owner
        or not repository
        or owner in {".", ".."}
        or repository in {".", ".."}
        or not all(char.isalnum() or char == "-" for char in owner)
        or not all(char.isalnum() or char in "._-" for char in repository)
    ):
        raise ValueError("Enter a valid GitHub repository URL or owner/repository.")
    return owner, repository


def _github_api_json(path, token):
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "AegisSecurityScanner/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        data = response.read(1_000_001)
    if len(data) > 1_000_000:
        raise ValueError("GitHub returned an unexpectedly large response.")
    return json.loads(data)


def _download_github_archive(path, token):
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "AegisSecurityScanner/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    class ArchiveRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, file_pointer, code, message, headers, new_url):
            destination = urllib.parse.urlparse(new_url)
            if destination.scheme != "https" or destination.hostname not in {
                "api.github.com",
                "codeload.github.com",
            }:
                return None
            redirected = super().redirect_request(
                request, file_pointer, code, message, headers, new_url
            )
            if redirected and destination.hostname != urllib.parse.urlparse(
                request.full_url
            ).hostname:
                redirected.remove_header("Authorization")
            return redirected

    opener = urllib.request.build_opener(ArchiveRedirectHandler())
    with opener.open(req, timeout=30) as response:
        data = response.read(25_000_001)
    if len(data) > 25_000_000:
        raise ValueError("Repository archive exceeds the 25 MB scan limit.")
    return data


def _source_files_from_archive(data):
    source_suffixes = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb",
        ".php", ".cs", ".html", ".htm", ".json", ".txt", ".mod",
    }
    files = {}
    total_size = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > 10_000:
            raise ValueError("Repository archive contains too many entries.")
        for info in entries:
            suffix = Path(info.filename).suffix.lower()
            if info.is_dir() or suffix not in source_suffixes or info.file_size > 1_000_000:
                continue
            if len(files) >= 2_000 or total_size >= 20_000_000:
                break
            with archive.open(info) as source:
                content = source.read(1_000_001)
            if len(content) > 1_000_000 or total_size + len(content) > 20_000_000:
                continue
            total_size += len(content)
            files[info.filename] = content.decode("utf-8", errors="replace")
    return files


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
    Header = fastapi.Header
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

    class GithubScan(BaseModel):
        repository: str

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

    @app.post("/scan/github")
    def scan_github(
        body: GithubScan,
        authorization: str | None = Header(default=None),
        format: str = "json",
    ):
        chosen = _report_format(format)
        if not authorization:
            raise HTTPException(status_code=401, detail="A GitHub access token is required.")
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token.strip():
            raise HTTPException(status_code=401, detail="Use a GitHub bearer token.")

        try:
            owner, repository = _parse_github_repository(body.repository)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        owner_path = urllib.parse.quote(owner, safe="")
        repository_path = urllib.parse.quote(repository, safe="")
        try:
            identity = _github_api_json("/user", token.strip())
            repo = _github_api_json(
                f"/repos/{owner_path}/{repository_path}", token.strip()
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise HTTPException(status_code=401, detail="GitHub rejected the access token.") from exc
            if exc.code == 404:
                raise HTTPException(status_code=404, detail="Repository not found or not accessible.") from exc
            raise HTTPException(status_code=502, detail="GitHub could not verify the repository.") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail="GitHub verification failed.") from exc

        authenticated_login = str(identity.get("login") or "").casefold()
        repository_owner = str(repo.get("owner", {}).get("login") or "").casefold()
        if not authenticated_login or not repository_owner or repository_owner != authenticated_login:
            raise HTTPException(
                status_code=403,
                detail="Only repositories owned by the authenticated GitHub account can be scanned.",
            )

        try:
            archive = _download_github_archive(
                f"/repos/{owner_path}/{repository_path}/zipball", token.strip()
            )
            files = _source_files_from_archive(archive)
        except urllib.error.HTTPError as exc:
            raise HTTPException(status_code=502, detail="GitHub could not provide the repository archive.") from exc
        except (urllib.error.URLError, TimeoutError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=502, detail="Repository archive could not be processed.") from exc
        if not files:
            raise HTTPException(status_code=422, detail="No supported source files were found in the repository.")

        report = run_scan(
            {"kind": "source", "files": files},
            company_hint=f"{owner}/{repository}",
        )
        report["target"]["url"] = f"https://github.com/{owner}/{repository}"
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
