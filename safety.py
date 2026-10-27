"""Decide whether a scan target is allowed.

A website scan is allowed only after the site serves an issued token at
`/.well-known/cyber-risk-verify.txt`. That proof must pass before the agents run.
A source scan reads owner labels in the upload. A root `cyber-risk-owner.txt`
or a named owner in the source must match the caller. When the source has no
owner label, the scan continues and the code is assumed to be theirs.

This module does not send exploit traffic and does not run exploit code.
"""

import io
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
import urllib.request
import zipfile
from pathlib import PurePosixPath
from urllib.parse import urlparse


class UnsafeTarget(ValueError):
    """The target is outside the allowed scan scope."""


INSPECT_ONLY = False
STAY_INSPECT_DEFAULT = False
ALLOWED_ACTIONS = frozenset({"inspect", "match_cve", "report"})

BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "metadata.google.internal",
    }
)

MAX_ARCHIVE_BYTES = 8_000_000
MAX_FILES = 200
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_UNCOMPRESSED = 8_000_000

OWNER_FILE = "cyber-risk-owner.txt"
WELL_KNOWN_PATH = "/.well-known/cyber-risk-verify.txt"
TOKEN_TTL_SECONDS = 3600


def require_authorization(confirmed):
    """The caller must explicitly say they are allowed to scan this target."""
    if confirmed is not True:
        raise UnsafeTarget("Confirm that you are allowed to scan this target.")


def assert_action_allowed(action):
    """Reject anything other than inspection, version matching, or a report."""
    if action not in ALLOWED_ACTIONS:
        raise UnsafeTarget(
            "This product only inspects a target, matches known vulnerabilities, and writes a report."
        )


def stay_inspect_enabled(stay_inspect=False, override_command=False):
    """Stay-inspect is off unless the user turns it on and presses override.

    The override is the button. Without it, a request to stay in inspect mode
    is refused and the council command is left unchanged.
    """
    if stay_inspect is not True:
        return False
    if override_command is not True:
        raise UnsafeTarget(
            "Stay-inspect mode is off. Press override before it can replace the council command."
        )
    assert_action_allowed("inspect")
    return True


def _literal_ip(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if host.isdigit():
        number = int(host)
        if 0 <= number <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(number)
    return None


def _forbidden(ip):
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _addresses_for(host, resolve):
    literal = _literal_ip(host)
    if literal is not None:
        return [literal]
    resolver = resolve or socket.getaddrinfo
    try:
        records = resolver(host, None)
    except socket.gaierror as exc:
        raise UnsafeTarget("The host could not be resolved.") from exc
    addresses = []
    for record in records or []:
        addresses.append(ipaddress.ip_address(record[4][0]))
    if not addresses:
        raise UnsafeTarget("The host could not be resolved.")
    return addresses


def check_url(url, resolve=None):
    """Allow a public http(s) URL. Refuse local, private, and link-local targets."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTarget("Only http and https URLs are allowed.")
    host = parsed.hostname
    if not host:
        raise UnsafeTarget("The URL needs a host.")
    normalized = host.lower().rstrip(".")
    if normalized in BLOCKED_HOSTS or normalized.endswith(".localhost"):
        raise UnsafeTarget("That host is not allowed.")
    for address in _addresses_for(host, resolve):
        if _forbidden(address):
            raise UnsafeTarget("That host resolves to an address that is not allowed.")
    return url


def check_redirect(url, resolve=None):
    """Apply the same host rules to a redirect destination."""
    return check_url(url, resolve=resolve)


def check_archive(data):
    """Refuse oversized archives and paths that leave the archive root."""
    if not isinstance(data, (bytes, bytearray)):
        raise UnsafeTarget("The upload must be a zip archive.")
    if len(data) > MAX_ARCHIVE_BYTES:
        raise UnsafeTarget("The archive is too large.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsafeTarget("The upload is not a zip archive.") from exc

    count = 0
    total = 0
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if (
                not name
                or name.startswith("/")
                or ".." in parts
                or (parts and ":" in parts[0])
            ):
                raise UnsafeTarget("The archive contains an unsafe path.")
            count += 1
            if count > MAX_FILES:
                raise UnsafeTarget("The archive has too many files.")
            if info.file_size > MAX_FILE_BYTES:
                raise UnsafeTarget("A file in the archive is too large.")
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise UnsafeTarget("The archive expands too far.")
    return data


def proof_url(site_url):
    """Exact URL where the site must publish its ownership token."""
    parsed = urlparse(site_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise UnsafeTarget("The URL needs a public http or https host.")
    return f"{parsed.scheme}://{parsed.netloc}{WELL_KNOWN_PATH}"


def body_matches_token(body, token):
    left = str(body or "").lstrip("\ufeff").strip()
    right = str(token or "").strip()
    if not left or not right or len(left) != len(right):
        return False
    return secrets.compare_digest(left, right)


def owner_file_text(files):
    """Return the archive-root ownership file, or None when it is absent.

    Nested copies do not count. A missing file is not a refusal.
    """
    for path, text in (files or {}).items():
        name = str(path).replace("\\", "/").lstrip("./")
        if name == OWNER_FILE:
            return text
    return None


_AUTHOR_ASSIGN = re.compile(
    r"""(?:__author__|author)\s*=\s*['\"]([^'\"]{2,80})['\"]""",
    re.IGNORECASE,
)
_COPYRIGHT = re.compile(
    r"copyright\s*(?:\(c\))?\s*(?:\d{4}(?:\s*[-,]\s*\d{4})?)?\s*([A-Za-z][^.\n]{1,80})",
    re.IGNORECASE,
)


def _clean_label(value):
    text = " ".join(str(value or "").replace("<", " ").split())
    text = text.split("@")[0].strip(" ,;\"'")
    return text[:80]


def _add_label(found, value):
    cleaned = _clean_label(value)
    if cleaned and cleaned not in found:
        found.append(cleaned)


def named_owner_labels(files):
    """Owner names written in the source. An absent label means nothing was claimed."""
    found = []
    for path, text in (files or {}).items():
        name = str(path).replace("\\", "/").lstrip("./")
        if name == OWNER_FILE:
            continue
        sample = str(text or "")[:8000]
        base = name.rsplit("/", 1)[-1]
        if base == "pyproject.toml":
            block = re.search(r"(?is)authors\s*=\s*\[(.*?)\]", sample)
            if block:
                for match in re.finditer(r"""['\"]([^'\"]{2,80})['\"]""", block.group(1)):
                    _add_label(found, match.group(1))
        if base == "setup.cfg":
            for match in re.finditer(r"(?im)^[ \t]*author\s*=\s*(.+)$", sample):
                _add_label(found, match.group(1))
        if base == "package.json":
            try:
                data = json.loads(sample)
            except json.JSONDecodeError:
                data = {}
            author = data.get("author") if isinstance(data, dict) else None
            if isinstance(author, str):
                _add_label(found, author)
            elif isinstance(author, dict):
                _add_label(found, author.get("name"))
        for match in _AUTHOR_ASSIGN.finditer(sample):
            _add_label(found, match.group(1))
        for match in _COPYRIGHT.finditer(sample):
            _add_label(found, match.group(1))
    return found


def _norm_owner(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _labels_match(labels, claimed_owner):
    claim = _norm_owner(claimed_owner)
    if not claim:
        return False
    for label in labels:
        text = _norm_owner(label)
        if text and (claim == text or claim in text or text in claim):
            return True
    return False


def verify_source_ownership(files, token="", store=None, claimed_owner=""):
    """Check labeled owners before any agent runs.

    A root owner file or a name written in the source must match the caller.
    When the source has no owner label, assume the upload is theirs.
    """
    token_text = owner_file_text(files)
    labels = named_owner_labels(files)
    if token_text is None and not labels:
        return {"assumed": True, "labels": []}
    if token_text is not None:
        if store is not None:
            store.check_source_token(token)
        if not body_matches_token(token_text, token):
            raise UnsafeTarget("The labeled owner does not match. The scan was refused.")
        if store is not None:
            store.claim(token)
    if labels and not _labels_match(labels, claimed_owner):
        raise UnsafeTarget("The labeled owner does not match. The scan was refused.")
    return {"assumed": False, "labels": labels}


def gate_before_agents(target, claimed_owner="", token="", store=None):
    """Refuse the scan before the council starts when ownership does not pass."""
    if target.get("ownership_checked"):
        return {"skipped": True}
    kind = target.get("kind")
    if kind == "url":
        if target.get("ownership_verified") is not True:
            raise UnsafeTarget("Site ownership must pass before the agents run.")
        target["ownership_checked"] = True
        return {"assumed": False}
    result = verify_source_ownership(
        target.get("files") or {},
        token=token,
        store=store,
        claimed_owner=claimed_owner,
    )
    target["ownership_checked"] = True
    target["ownership_assumed"] = result["assumed"]
    return result


class OwnershipStore:
    """Short-lived tokens that bind a scan to one site or one source upload."""

    def __init__(self, ttl_seconds=TOKEN_TTL_SECONDS, clock=None):
        self.ttl_seconds = ttl_seconds
        self.clock = clock or time.time
        self._lock = threading.Lock()
        self._tokens = {}

    def issue_url(self, url, resolve=None):
        check_url(url, resolve=resolve)
        host = urlparse(url).hostname.lower().rstrip(".")
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._tokens[token] = {"kind": "url", "host": host, "issued": self.clock()}
        return {"token": token, "place_at": proof_url(url), "host": host}

    def issue_source(self):
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._tokens[token] = {"kind": "source", "host": None, "issued": self.clock()}
        return {"token": token, "file": OWNER_FILE}

    def _record(self, token, kind):
        text = str(token or "").strip()
        if not text:
            raise UnsafeTarget("An ownership token is required.")
        with self._lock:
            record = self._tokens.get(text)
        if not record or record["kind"] != kind:
            raise UnsafeTarget("Issue an ownership token before scanning this target.")
        if self.clock() - record["issued"] > self.ttl_seconds:
            with self._lock:
                self._tokens.pop(text, None)
            raise UnsafeTarget("This ownership token has expired. Issue a new one.")
        return text, record

    def check_url_token(self, token, url):
        text, record = self._record(token, "url")
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        if record["host"] != host:
            raise UnsafeTarget("This token was issued for a different site.")
        return text

    def check_source_token(self, token):
        text, _record = self._record(token, "source")
        return text

    def claim(self, token):
        text = str(token or "").strip()
        with self._lock:
            self._tokens.pop(text, None)


def verify_url_ownership(url, token, store, fetch_text, resolve=None):
    """Fetch the well-known file and accept the scan only when it holds this token."""
    check_url(url, resolve=resolve)
    store.check_url_token(token, url)
    location = proof_url(url)
    check_url(location, resolve=resolve)
    try:
        body = fetch_text(location)
    except UnsafeTarget:
        raise
    except Exception as exc:
        raise UnsafeTarget("The ownership file could not be read.") from exc
    if not body_matches_token(body, token):
        raise UnsafeTarget(
            "Publish the ownership token as the only text at /.well-known/cyber-risk-verify.txt on that site."
        )
    store.claim(token)
    return location


def _opener(redirect):
    opener = urllib.request.build_opener(redirect)

    def open_request(request):
        return opener.open(request, timeout=12)

    return open_request


def safe_urlopen(resolve=None):
    """Open a URL and refuse a redirect that leaves the public-host rules."""

    class Handler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            check_redirect(newurl, resolve=resolve)
            return urllib.request.HTTPRedirectHandler.redirect_request(
                self, req, fp, code, msg, headers, newurl
            )

    return _opener(Handler)


def read_proof_body(url, resolve=None, opener=None):
    """Read the ownership file. Redirects are refused."""
    check_url(url, resolve=resolve)

    class Handler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise UnsafeTarget("The ownership file must be served directly, without a redirect.")

    open_request = opener or _opener(Handler)
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "CyberRiskSafeScanner/1.0"},
    )
    try:
        with open_request(request) as resp:
            return resp.read(256).decode("utf-8", errors="replace")
    except UnsafeTarget:
        raise
    except Exception as exc:
        raise UnsafeTarget("The ownership file could not be read.") from exc
