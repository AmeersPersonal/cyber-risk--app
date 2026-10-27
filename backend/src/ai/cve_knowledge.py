"""Local CVE knowledge base for agent context and after-action defenses.

On initialization, common CVE names stay in common_cves.json. Seeded entries
have a matching zero_days/<cve_name>.json file with how it works and how to
defend against it. Catalog IDs do not each get a file.
"""

import json
from pathlib import Path

from data_policy import assert_static_dataset_text, permit_project_source

KNOWLEDGE_DIR = Path(__file__).resolve().parent / "cve_knowledge"
COMMON_LIST_PATH = KNOWLEDGE_DIR / "common_cves.json"
ZERO_DAYS_DIR = KNOWLEDGE_DIR / "zero_days"

# High-level educational entries only (no exploit steps or payloads).
_SEED = (
    {
        "cve_name": "CVE-2021-44228",
        "how_it_works": (
            "Log4Shell: untrusted input can trigger Log4j message lookup, causing the "
            "logger to resolve remote references and load attacker-controlled code paths."
        ),
        "defend_against": (
            "Upgrade Log4j to a fixed release, disable message lookups, remove JndiLookup "
            "where applicable, block outbound LDAP/RMI from app hosts, and validate all log inputs."
        ),
    },
    {
        "cve_name": "CVE-2022-22965",
        "how_it_works": (
            "Spring4Shell: data binding on certain Spring MVC setups can let attackers "
            "overwrite ClassLoader-related properties and reach remote code execution."
        ),
        "defend_against": (
            "Upgrade Spring Framework to patched versions, avoid binding request data to "
            "Object/Class hierarchies, and restrict dangerous property paths in binders."
        ),
    },
    {
        "cve_name": "CVE-2017-5638",
        "how_it_works": (
            "Apache Struts 2 Jakarta multipart parser mishandled Content-Type, allowing "
            "OGNL evaluation of attacker-controlled header values."
        ),
        "defend_against": (
            "Upgrade Struts to a patched release, restrict Content-Type handling, and place "
            "a WAF rule for anomalous multipart Content-Type values as defense in depth."
        ),
    },
    {
        "cve_name": "CVE-2014-0160",
        "how_it_works": (
            "Heartbleed: a bounds error in OpenSSL heartbeat messages could leak process "
            "memory, including secrets such as private keys or session material."
        ),
        "defend_against": (
            "Upgrade OpenSSL, revoke and replace exposed certificates and keys, rotate "
            "session secrets, and verify TLS endpoints no longer advertise vulnerable builds."
        ),
    },
    {
        "cve_name": "CVE-2021-34527",
        "how_it_works": (
            "PrintNightmare: flawed Windows Print Spooler privilege checks could allow "
            "installation of malicious printer drivers leading to privilege escalation."
        ),
        "defend_against": (
            "Apply Microsoft patches, disable the Print Spooler where unused, restrict "
            "point-and-print, and monitor spooler service privilege changes."
        ),
    },
    {
        "cve_name": "CVE-2023-34362",
        "how_it_works": (
            "MOVEit Transfer SQL injection in a web endpoint could allow unauthorized "
            "database access and subsequent file theft from the transfer application."
        ),
        "defend_against": (
            "Apply Progress MOVEit patches immediately, review accounts created during the "
            "exposure window, rotate credentials, and place the admin interfaces behind VPN/SSO."
        ),
    },
    {
        "cve_name": "CVE-2019-0708",
        "how_it_works": (
            "BlueKeep: a remote code execution flaw in legacy Remote Desktop Services on "
            "unpatched Windows hosts reachable over RDP."
        ),
        "defend_against": (
            "Apply Microsoft updates, disable RDP if unused, require Network Level Authentication, "
            "and block RDP exposure on the public internet."
        ),
    },
    {
        "cve_name": "CVE-2021-26855",
        "how_it_works": (
            "ProxyLogon: Exchange Server server-side request forgery in the CAS layer could "
            "be chained to authenticated remote code execution on vulnerable servers."
        ),
        "defend_against": (
            "Patch Exchange, restrict Outlook Web Access exposure, enable MFA for admin access, "
            "and hunt for unusual ASPX webshells and mailbox export activity."
        ),
    },
)


def _safe_name(cve_name):
    name = (cve_name or "").strip().replace("/", "_").replace("\\", "_")
    if not name:
        raise ValueError("cve_name is required")
    return name


def zero_day_path(cve_name, root=None):
    root = Path(root) if root else ZERO_DAYS_DIR
    return root / f"{_safe_name(cve_name)}.json"


def write_cve_file(entry, root=None):
    path = zero_day_path(entry["cve_name"], root=root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "cve_name": entry["cve_name"],
        "how_it_works": entry["how_it_works"],
        "defend_against": entry["defend_against"],
    }
    text = json.dumps(payload, indent=2)
    assert_static_dataset_text(text, "cve_knowledge")
    path.write_text(text, encoding="utf-8")
    return path


def initialize_cve_knowledge(force=False, knowledge_dir=None):
    """Keep the common CVE list and write zero-day files for seeded entries."""
    permit_project_source("cve_knowledge")
    base = Path(knowledge_dir) if knowledge_dir else KNOWLEDGE_DIR
    common_path = base / "common_cves.json"
    zero_dir = base / "zero_days"
    zero_dir.mkdir(parents=True, exist_ok=True)

    names = [item["cve_name"] for item in _SEED]
    listed = []
    if common_path.exists() and common_path.stat().st_size > 0 and not force:
        try:
            loaded = json.loads(common_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = []
        if isinstance(loaded, list):
            listed = [str(item) for item in loaded if item]
    if force or not listed:
        listed = list(names)
    else:
        for name in names:
            if name not in listed:
                listed.append(name)
    text = json.dumps(listed, indent=2) + "\n"
    current = common_path.read_text(encoding="utf-8") if common_path.exists() else ""
    if current != text:
        common_path.write_text(text, encoding="utf-8")

    written = []
    for entry in _SEED:
        path = zero_day_path(entry["cve_name"], root=zero_dir)
        if force or not path.exists():
            write_cve_file(entry, root=zero_dir)
            written.append(entry["cve_name"])

    return {
        "common_list": str(common_path),
        "zero_days_dir": str(zero_dir),
        "count": len(listed),
        "written": written,
    }


def load_common_cve_names(knowledge_dir=None):
    initialize_cve_knowledge(knowledge_dir=knowledge_dir)
    base = Path(knowledge_dir) if knowledge_dir else KNOWLEDGE_DIR
    path = base / "common_cves.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [str(item) for item in data if item]


def load_cve_entry(cve_name, knowledge_dir=None):
    base = Path(knowledge_dir) if knowledge_dir else KNOWLEDGE_DIR
    path = zero_day_path(cve_name, root=base / "zero_days")
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
        assert_static_dataset_text(text, "cve_knowledge")
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("cve_name", cve_name)
    data.setdefault("how_it_works", "")
    data.setdefault("defend_against", "")
    return data


def load_all_cve_knowledge(knowledge_dir=None):
    initialize_cve_knowledge(knowledge_dir=knowledge_dir)
    entries = []
    for name in load_common_cve_names(knowledge_dir=knowledge_dir):
        entry = load_cve_entry(name, knowledge_dir=knowledge_dir)
        if entry:
            entries.append(entry)
    return entries


def defense_for_cve(cve_name, knowledge_dir=None):
    entry = load_cve_entry(cve_name, knowledge_dir=knowledge_dir)
    if not entry:
        return None
    return entry.get("defend_against") or None


def agent_context(limit=8, knowledge_dir=None):
    """Compact local CVE context for council agents."""
    entries = load_all_cve_knowledge(knowledge_dir=knowledge_dir)[:limit]
    lines = []
    for entry in entries:
        lines.append(
            f"{entry['cve_name']}: {entry.get('how_it_works', '')[:160]} "
            f"Defend: {entry.get('defend_against', '')[:160]}"
        )
    return {
        "common_cves": [entry["cve_name"] for entry in entries],
        "briefs": lines,
        "text": " | ".join(lines),
    }


# Initialize on import so scans always have local context ready.
initialize_cve_knowledge()
