"""Read installed package versions from uploaded manifests.

Only exact versions are kept. Ranges such as ^1.2.3 are skipped because they
are not a single installed version. A package-lock.json replaces package.json.
"""

import json
import re
from pathlib import Path


_REQ_EXACT = re.compile(
    r"^([A-Za-z0-9_][A-Za-z0-9_.\-]*)(?:\[[^\]]+\])?\s*==\s*([^\s#;]+)"
)
_GO_REQUIRE = re.compile(
    r"^\s*(?:require\s+)?([A-Za-z0-9][A-Za-z0-9_.\-/]*)\s+v(\d+[^\s]*)",
    re.MULTILINE,
)
_EXACT_SEMVER = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def _add(found, ecosystem, name, version):
    name = (name or "").strip()
    version = (version or "").strip()
    if not name or not version:
        return
    key = (ecosystem, name.lower() if ecosystem == "PyPI" else name)
    if key in found:
        return
    found[key] = {
        "name": name,
        "version": version.lstrip("vV") if version[:1] in "vV" else version,
        "ecosystem": ecosystem,
    }


def _requirements(text, found):
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith(("-", "git+", "http://", "https://")):
            continue
        match = _REQ_EXACT.match(stripped)
        if not match:
            continue
        _add(found, "PyPI", match.group(1), match.group(2))


def _package_json(text, found):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, raw in deps.items():
            match = _EXACT_SEMVER.match(str(raw).strip())
            if match:
                _add(found, "npm", name, match.group(1))


def _package_lock(text, found):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return False
    packages = data.get("packages")
    if isinstance(packages, dict):
        added = False
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                continue
            name = meta.get("name") or Path(path).name
            if not name:
                continue
            _add(found, "npm", name, str(version))
            added = True
        if added:
            return True
    deps = data.get("dependencies")
    if not isinstance(deps, dict):
        return False
    for name, meta in deps.items():
        if isinstance(meta, dict) and meta.get("version"):
            _add(found, "npm", name, str(meta["version"]))
    return True


def _go_mod(text, found):
    for name, version in _GO_REQUIRE.findall(text):
        if name == "go":
            continue
        _add(found, "Go", name, version)


def packages_from_files(files):
    """Return exact {name, version, ecosystem} rows from known manifests."""
    files = files or {}
    found = {}
    lock_paths = [path for path in files if Path(path).name == "package-lock.json"]
    locked = False
    for path in lock_paths:
        locked = _package_lock(files[path], found) or locked
    for path, text in files.items():
        name = Path(path).name
        if name == "requirements.txt":
            _requirements(text, found)
        elif name == "package.json" and not locked:
            _package_json(text, found)
        elif name == "go.mod":
            _go_mod(text, found)
    return list(found.values())
