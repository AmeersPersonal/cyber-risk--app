"""Populate Zetaris with CVE data from NIST NVD, CISA KEV, and OSV.

Architecture:
  1. Create a ``cve_data`` database in the Zetaris PostgreSQL container.
  2. Create the ``cve_items`` table inside it.
  3. Register the database as a Zetaris datasource (``CVE_PG``).
  4. Fetch CVEs from public sources and bulk-insert into PostgreSQL.
  5. Zetaris queries go through ``CVE_PG.cve_items``.

Run once (or periodically) to seed the Zetaris data layer before analysis.
Usage:  python -m ai.setup_zetaris [--reset] [--limit N]
"""

import argparse
import json
import subprocess
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

PG_CONTAINER = "zetaris-postgres-1"
PG_DB = "cve_data"
CVE_TABLE = "cve_items"
ZETARIS_DS_NAME = "CVE_PG"
ZETARIS_TABLE = f"{ZETARIS_DS_NAME}.{CVE_TABLE}"

CREATE_TABLE_PG = f"""
CREATE TABLE IF NOT EXISTS {CVE_TABLE} (
    cve_id       VARCHAR(50)  PRIMARY KEY,
    vendor       VARCHAR(256),
    product      VARCHAR(256),
    name         VARCHAR(500),
    date_added   VARCHAR(50),
    description  TEXT,
    cvss_score   DOUBLE PRECISION,
    severity     VARCHAR(50),
    sources      VARCHAR(256),
    fetched_at   VARCHAR(50)
);
""".strip()

DROP_TABLE_PG = f"DROP TABLE IF EXISTS {CVE_TABLE};"


def _pg_creds():
    """Read PostgreSQL credentials from the running Docker container."""
    result = subprocess.run(
        ["docker", "inspect", PG_CONTAINER,
         "--format", "{{range .Config.Env}}{{println .}}{{end}}"],
        capture_output=True, text=True, timeout=10,
    )
    env = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return {
        "user": env.get("POSTGRES_USER", "zetaris"),
        "password": env.get("POSTGRES_PASSWORD", ""),
    }


def _psql(sql, db=PG_DB):
    """Execute SQL inside the PostgreSQL container."""
    result = subprocess.run(
        ["docker", "exec", PG_CONTAINER, "psql", "-U", "zetaris", "-d", db, "-c", sql],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return {"ok": False, "error": result.stderr.strip()}
    return {"ok": True, "output": result.stdout.strip()}


def _escape_pg(value):
    if value is None:
        return "NULL"
    text = str(value).replace("'", "''")
    return f"'{text}'"


def _insert_values(items, fetched_at, batch_size=50):
    """Generate batched INSERT statements for PostgreSQL."""
    statements = []
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        rows = []
        for item in batch:
            sources = ",".join(item.get("sources") or [])
            score = item.get("cvss_score")
            score_lit = str(score) if score is not None else "NULL"
            rows.append(
                f"({_escape_pg(item.get('cve_id'))}, "
                f"{_escape_pg(item.get('vendor'))}, "
                f"{_escape_pg(item.get('product'))}, "
                f"{_escape_pg(item.get('name'))}, "
                f"{_escape_pg(item.get('date_added'))}, "
                f"{_escape_pg((item.get('description') or '')[:2000])}, "
                f"{score_lit}, "
                f"{_escape_pg(item.get('severity'))}, "
                f"{_escape_pg(sources)}, "
                f"{_escape_pg(fetched_at)})"
            )
        stmt = (
            f"INSERT INTO {CVE_TABLE} "
            f"(cve_id, vendor, product, name, date_added, description, "
            f"cvss_score, severity, sources, fetched_at) VALUES\n"
            + ",\n".join(rows)
            + "\nON CONFLICT (cve_id) DO UPDATE SET "
            "vendor=EXCLUDED.vendor, product=EXCLUDED.product, "
            "name=EXCLUDED.name, date_added=EXCLUDED.date_added, "
            "description=EXCLUDED.description, cvss_score=EXCLUDED.cvss_score, "
            "severity=EXCLUDED.severity, sources=EXCLUDED.sources, "
            "fetched_at=EXCLUDED.fetched_at;"
        )
        statements.append(stmt)
    return statements


def setup_postgres(reset=False):
    """Create the cve_data database and cve_items table in PostgreSQL."""
    print("Step 1a: Ensuring PostgreSQL database exists...")
    result = subprocess.run(
        ["docker", "exec", PG_CONTAINER, "psql", "-U", "zetaris", "-d", "postgres",
         "-tc", f"SELECT 1 FROM pg_database WHERE datname = '{PG_DB}'"],
        capture_output=True, text=True, timeout=10,
    )
    if "1" not in result.stdout:
        print(f"  Creating database {PG_DB}...")
        _psql(f"CREATE DATABASE {PG_DB} OWNER zetaris;", db="postgres")
    else:
        print(f"  Database {PG_DB} already exists.")

    if reset:
        print("  Dropping existing table (--reset)...")
        _psql(DROP_TABLE_PG)

    print("Step 1b: Creating cve_items table...")
    result = _psql(CREATE_TABLE_PG)
    if result.get("ok"):
        print("  Table ready.")
    else:
        print(f"  Warning: {result.get('error')}")


def register_datasource(client):
    """Register the PostgreSQL cve_data DB as a Zetaris datasource."""
    print("Step 2: Registering datasource in Zetaris...")
    pg = _pg_creds()
    jdbc_url = f"jdbc:postgresql://postgres:5432/{PG_DB}"

    create_ds = (
        f'CREATE DATASOURCE {ZETARIS_DS_NAME} '
        f'DESCRIBE BY "CVE vulnerability data" '
        f'OPTIONS ('
        f'jdbcdriver "org.postgresql.Driver", '
        f'jdbcurl "{jdbc_url}", '
        f'username "{pg["user"]}", '
        f'password "{pg["password"]}"'
        f')'
    )

    existing = client.run_sql("SHOW DATASOURCES")
    ds_names = [
        row[0] for row in (existing.get("data") or [])
        if isinstance(row, list) and row
    ]
    if ZETARIS_DS_NAME in ds_names:
        print(f"  Datasource {ZETARIS_DS_NAME} already registered.")
    else:
        result = client.write_sql(create_ds)
        if result.get("ok"):
            print(f"  Datasource {ZETARIS_DS_NAME} created.")
        else:
            print(f"  Warning: {result.get('error', '')}")

    print("  Registering tables...")
    result = client.write_sql(f"REGISTER DATASOURCE TABLES FROM {ZETARIS_DS_NAME}")
    if result.get("ok"):
        print("  Tables registered.")
    else:
        print(f"  Warning: {result.get('error')}")

    result = client.run_sql(f"SHOW TABLES IN {ZETARIS_DS_NAME}")
    if result.get("ok"):
        tables = result.get("data") or []
        print(f"  Zetaris sees {len(tables)} table(s): {[r[0] if isinstance(r, list) else r for r in tables]}")
    else:
        print(f"  Could not list tables: {result.get('error')}")


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


def insert_cves(items, fetched_at):
    """Bulk-insert CVE items into PostgreSQL."""
    print(f"Step 4: Inserting {len(items)} CVEs into PostgreSQL...")
    statements = _insert_values(items, fetched_at)
    inserted = 0
    failed = 0
    for stmt in statements:
        result = _psql(stmt)
        if result.get("ok"):
            output = result.get("output", "")
            if "INSERT" in output:
                count = output.split()[-1] if output.split() else "0"
                try:
                    inserted += int(count)
                except ValueError:
                    inserted += 1
        else:
            failed += 1
            if failed <= 3:
                print(f"  Batch insert failed: {result.get('error', '')[:200]}")
    print(f"  Inserted/updated: {inserted}, failed batches: {failed}")
    return inserted, failed


def verify_zetaris(client, limit=5):
    """Verify data is queryable through Zetaris."""
    print("Step 5: Verifying Zetaris query...")
    result = client.run_sql(
        f"SELECT cve_id, vendor, cvss_score, severity FROM {ZETARIS_TABLE} LIMIT {limit}"
    )
    if result.get("ok"):
        rows = result.get("data") or []
        print(f"  Zetaris returned {len(rows)} rows.")
        for row in rows[:3]:
            print(f"    {row}")
    else:
        print(f"  Query failed: {result.get('error')}")

    count_result = client.run_sql(f"SELECT COUNT(*) as total FROM {ZETARIS_TABLE}")
    if count_result.get("ok"):
        total = (count_result.get("data") or [[0]])[0]
        print(f"  Total CVEs in Zetaris: {total}")


def setup(client=None, reset=False, limit=50):
    """Full pipeline: PG setup -> Zetaris registration -> fetch CVEs -> insert -> verify."""
    client = client or ZetarisClient()

    if not client.configured():
        print("ERROR: Zetaris is not configured.")
        print("Set ZETARIS_API_KEY and ZETARIS_ORG_ID in .env or environment.")
        return {"ok": False, "error": "not configured"}

    setup_postgres(reset=reset)
    register_datasource(client)

    print("Step 3: Fetching CVEs from NIST NVD, CISA KEV, OSV...")
    items, sources_ok, errors = fetch_all_cves(limit=limit)
    if not items:
        print("ERROR: No CVEs fetched from any source.")
        return {"ok": False, "error": "no CVEs fetched", "fetch_errors": errors}

    from ai.cve_manger import _now
    fetched_at = _now()

    inserted, failed = insert_cves(items, fetched_at)
    verify_zetaris(client)

    cross = cross_check_summary(items)
    return {
        "ok": inserted > 0,
        "inserted": inserted,
        "failed_batches": failed,
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
