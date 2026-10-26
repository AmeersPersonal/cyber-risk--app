"""Populate Zetaris with CVE data from NIST NVD, CISA KEV, and OSV.

Run once (or periodically) to seed the Zetaris data layer before analysis.
Usage:  python -m ai.setup_zetaris [--reset]
"""

import argparse
import json
import sys
import urllib.request

from ai.cve_manger import (
    _merge_items,
    cross_check_summary,
    fetch_cisa_kev,
    fetch_nist_nvd,
    fetch_osv_for_fingerprints,
)
from ai.zetaris_client import ZetarisClient

CVE_TABLE = "cve_items"

CREATE_TABLE_SQL = f"""
CREATE TABLE IF NOT EXISTS {CVE_TABLE} (
    cve_id       VARCHAR(40)   NOT NULL,
    vendor       VARCHAR(256),
    product      VARCHAR(256),
    name         VARCHAR(256),
    date_added   VARCHAR(16),
    description  VARCHAR(2000),
    cvss_score   DECIMAL(4,1),
    severity     VARCHAR(40),
    sources      VARCHAR(256),
    fetched_at   VARCHAR(32)
)
""".strip()

DROP_TABLE_SQL = f"DROP TABLE IF EXISTS {CVE_TABLE}"


def _escape(value):
    """Escape a string value for SQL insertion."""
    if value is None:
        return "NULL"
    text = str(value).replace("'", "''").replace("\\", "\\\\")
    return f"'{text}'"


def _insert_sql(item, fetched_at):
    sources = ",".join(item.get("sources") or [])
    score = item.get("cvss_score")
    score_literal = str(score) if score is not None else "NULL"
    return (
        f"INSERT INTO {CVE_TABLE} "
        f"(cve_id, vendor, product, name, date_added, description, "
        f"cvss_score, severity, sources, fetched_at) VALUES ("
        f"{_escape(item.get('cve_id'))}, "
        f"{_escape(item.get('vendor'))}, "
        f"{_escape(item.get('product'))}, "
        f"{_escape(item.get('name'))}, "
        f"{_escape(item.get('date_added'))}, "
        f"{_escape((item.get('description') or '')[:2000])}, "
        f"{score_literal}, "
        f"{_escape(item.get('severity'))}, "
        f"{_escape(sources)}, "
        f"{_escape(fetched_at)})"
    )


def fetch_all_cves(limit=50):
    """Fetch CVEs from all three public sources and merge them."""
    opener = urllib.request.urlopen
    groups = []
    sources_ok = []
    errors = {}

    for source_name, loader in (
        ("cisa_kev", lambda: fetch_cisa_kev(opener, limit=limit)),
        ("nist_nvd", lambda: fetch_nist_nvd(opener, limit=limit)),
        ("osv", lambda: fetch_osv_for_fingerprints(opener, [], limit=limit)),
    ):
        try:
            items = loader()
            groups.append(items)
            sources_ok.append(source_name)
            print(f"  {source_name}: fetched {len(items)} items")
        except Exception as exc:
            errors[source_name] = str(exc)
            print(f"  {source_name}: FAILED - {exc}")

    merged = _merge_items(groups)
    print(f"  Merged: {len(merged)} unique CVEs from {sources_ok}")
    return merged, sources_ok, errors


def setup(client=None, reset=False, limit=50):
    """Full pipeline: fetch CVEs -> create table -> insert rows into Zetaris."""
    client = client or ZetarisClient()

    if not client.configured():
        print("ERROR: Zetaris is not configured.")
        print("Set ZETARIS_API_KEY and ZETARIS_ORG_ID in .env or environment.")
        return {"ok": False, "error": "not configured"}

    print("Step 1: Fetching CVEs from NIST NVD, CISA KEV, OSV...")
    items, sources_ok, errors = fetch_all_cves(limit=limit)
    if not items:
        print("ERROR: No CVEs fetched from any source.")
        return {"ok": False, "error": "no CVEs fetched", "fetch_errors": errors}

    if reset:
        print("Step 2: Dropping existing table...")
        result = client.write_sql(DROP_TABLE_SQL)
        if not result.get("ok"):
            print(f"  Warning: DROP failed - {result.get('error')}")

    print("Step 2: Creating table in Zetaris...")
    result = client.write_sql(CREATE_TABLE_SQL)
    if not result.get("ok"):
        print(f"  Warning: CREATE may have failed - {result.get('error')}")
        print("  (Table may already exist, continuing with inserts...)")

    from ai.cve_manger import _now
    fetched_at = _now()

    print(f"Step 3: Inserting {len(items)} CVEs into Zetaris...")
    inserted = 0
    failed = 0
    for item in items:
        sql = _insert_sql(item, fetched_at)
        result = client.write_sql(sql)
        if result.get("ok"):
            inserted += 1
        else:
            failed += 1
            if failed <= 3:
                print(f"  Insert failed for {item.get('cve_id')}: {result.get('error')}")

    print(f"Done: {inserted} inserted, {failed} failed out of {len(items)} CVEs.")
    cross = cross_check_summary(items)

    return {
        "ok": inserted > 0,
        "inserted": inserted,
        "failed": failed,
        "total": len(items),
        "sources": sources_ok,
        "fetch_errors": errors,
        "cross_check": cross,
    }


def main():
    parser = argparse.ArgumentParser(description="Populate Zetaris with CVE data")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop and recreate the CVE table before inserting",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max CVEs to fetch per source (default: 50)",
    )
    args = parser.parse_args()
    result = setup(reset=args.reset, limit=args.limit)
    if not result.get("ok"):
        sys.exit(1)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
