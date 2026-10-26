import importlib.util
import io
import sys
import unittest
import zipfile
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ai import cve_manger
from ai.council import ThreatCouncil
from ai.main import files_from_zip, run_scan
from ai.meterless_scout import Scout
from ai.tool import ARSENAL, list_tools, run_tool
from ai.zetaris_client import ZetarisClient, assert_readonly_sql
from cyber_tools import access_control, click_jacking, session, sql_inject, xss
from report import build_report

ATTACK_TYPE_TOOLS = {
    "injection",
    "xss",
    "csrf",
    "broken_authentication",
    "access_control",
    "ssrf",
    "file_upload_abuse",
    "clickjacking",
    "business_logic",
    "api_mass_assignment",
    "denial_of_service",
    "supply_chain",
    "misconfiguration",
    "cryptographic_failures",
    "account_takeover",
}


def _load_api_module():
    spec = importlib.util.spec_from_file_location("cyber_risk_api", SRC / "fastapi.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ArsenalTests(unittest.TestCase):
    def test_preloaded_tools_are_registered(self):
        names = {item["name"] for item in list_tools()}
        expected = {
            "click_jacking",
            "sql_inject",
            "session",
            "file_trasnfer",
            "website_element_manipulation",
            "pen_test",
        } | ATTACK_TYPE_TOOLS
        self.assertEqual(names, expected)
        self.assertTrue(ATTACK_TYPE_TOOLS.issubset(names))

    def test_unknown_tool_is_rejected(self):
        result = run_tool("custom_exploit_script", {"kind": "source", "files": {}})
        self.assertEqual(result["status"], "error")
        self.assertIn("preloaded arsenal", result["findings"][0]["detail"])


class ToolCheckTests(unittest.TestCase):
    def test_sql_inject_flags_string_built_sql(self):
        result = sql_inject.run(
            {
                "kind": "source",
                "files": {
                    "app.py": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
                },
            }
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_sql_inject_passes_parameterized_sql(self):
        result = sql_inject.run(
            {
                "kind": "source",
                "files": {"app.py": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"},
            }
        )
        self.assertEqual(result["status"], "pass")

    def test_click_jacking_requires_frame_header(self):
        missing = click_jacking.run(
            {"kind": "url", "url": "https://example.test", "http": {"headers": {}, "body": ""}}
        )
        present = click_jacking.run(
            {
                "kind": "url",
                "url": "https://example.test",
                "http": {"headers": {"x-frame-options": "DENY"}, "body": ""},
            }
        )
        self.assertEqual(missing["status"], "fail")
        self.assertEqual(present["status"], "pass")

    def test_session_requires_cookie_flags(self):
        result = session.run(
            {
                "kind": "url",
                "http": {"headers": {"set-cookie": "session=abc"}},
            }
        )
        self.assertEqual(result["status"], "fail")
        self.assertIn("httponly", result["findings"][0]["evidence"])

    def test_xss_flags_unsafe_rendering(self):
        result = xss.run(
            {
                "kind": "source",
                "files": {"page.jsx": "return <div dangerouslySetInnerHTML={{__html: html}} />"},
            }
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_access_control_flags_unprotected_route(self):
        result = access_control.run(
            {
                "kind": "source",
                "files": {
                    "api.py": "@app.get('/admin/users')\ndef users():\n    return db.all()\n"
                },
            }
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["severity"], "high")


class ScanAndCveTests(unittest.TestCase):
    def test_run_scan_uses_council_not_blind_full_arsenal(self):
        council = ThreatCouncil(max_rounds=2, tools_per_round=3)
        report = run_scan(
            {
                "kind": "source",
                "files": {
                    "app.py": "cursor.execute('SELECT * FROM t WHERE id=' + user_id)",
                    "requirements.txt": "django==3.2.0",
                },
            },
            cve_source={
                "fetched_at": None,
                "source": "cisa_kev",
                "count": 1,
                "items": [
                    {
                        "cve_id": "CVE-0000-0001",
                        "vendor": "Django",
                        "product": "Django",
                        "name": "Example",
                        "date_added": "2024-01-01",
                        "description": "A Django issue",
                    }
                ],
            },
            council=council,
            company_hint="Acme Corp",
        )
        self.assertTrue(report["tools"])
        self.assertLessEqual(len(report["tools"]), len(ARSENAL))
        self.assertIn("debate", report["council"])
        self.assertGreaterEqual(report["summary"]["council_rounds"], 1)
        self.assertEqual(report["council"]["engines"]["meterless_scout"], "meterless-scout-local")
        self.assertEqual(report["summary"]["matched_cve_count"], 1)
        self.assertTrue(any(item["severity"] == "high" for item in report["findings"]))

    def test_parse_and_match_kev(self):
        items = cve_manger.parse_kev(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-1",
                        "vendorProject": "Nginx",
                        "product": "nginx",
                        "vulnerabilityName": "Example",
                        "dateAdded": "2024-01-01",
                        "shortDescription": "banner issue",
                    }
                ]
            }
        )
        self.assertEqual(items[0]["cve_id"], "CVE-1")
        matched = cve_manger.match_cves(items, ["nginx/1.18"])
        self.assertEqual(matched[0]["cve_id"], "CVE-1")

    def test_build_report_counts_findings(self):
        report = build_report(
            [
                {
                    "tool": "sql_inject",
                    "status": "fail",
                    "findings": [
                        {
                            "tool": "sql_inject",
                            "severity": "high",
                            "title": "x",
                            "detail": "y",
                            "evidence": "",
                        }
                    ],
                }
            ]
        )
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["summary"]["severity"]["high"], 1)

    def test_files_from_zip_reads_source_only(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("app.py", "print(1)")
            archive.writestr("photo.bin", b"\x00\x01")
        files = files_from_zip(buffer.getvalue())
        self.assertEqual(files, {"app.py": "print(1)"})


class ApiTests(unittest.TestCase):
    def test_health_and_tools_routes(self):
        here = str(SRC)
        if here in sys.path:
            sys.path.remove(here)
        sys.modules.pop("fastapi", None)
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            sys.path.insert(0, here)
            self.skipTest("fastapi is not installed")
        sys.path.insert(0, here)

        client = TestClient(_load_api_module().create_app())
        health = client.get("/health")
        tools = client.get("/tools")
        self.assertEqual(health.status_code, 200)
        body = health.json()
        self.assertEqual(body["status"], "ok")
        self.assertIn("zetaris_configured", body["engines"])
        self.assertIn("meterless", body["engines"])
        self.assertEqual(len(tools.json()["tools"]), 21)


class CouncilAndIntegrationTests(unittest.TestCase):
    def test_zetaris_rejects_non_readonly_sql(self):
        with self.assertRaises(ValueError):
            assert_readonly_sql("DROP TABLE users")
        self.assertEqual(assert_readonly_sql("SELECT 1"), "SELECT 1")

    def test_zetaris_offline_fallback(self):
        client = ZetarisClient(cfg={"rest_url": "http://example", "org_id": "", "api_key": "", "threat_sql": ""})
        result = client.company_threat_context("Acme", fingerprints=["django"])
        self.assertEqual(result["source"], "local_fallback")

    def test_scout_emits_execution_contract(self):
        decision = Scout().decide(
            prompt="Analyze auth and session risk for this company",
            used_tools=[],
            max_tools=3,
        )
        self.assertIn("executionContract", decision)
        self.assertEqual(decision["executionContract"]["policy"], "defensive_arsenal_only")
        self.assertTrue(decision["toolPlan"])

    def test_council_agents_debate_and_choose_tools(self):
        council = ThreatCouncil(max_rounds=1, tools_per_round=2)
        session = council.analyze(
            {
                "kind": "source",
                "files": {"app.py": "password = 'hardcoded-secret-value'\n"},
            },
            company_hint="Acme",
            fingerprints=["django"],
        )
        self.assertEqual(len(session["debate"]), 1)
        self.assertEqual(len(session["debate"][0]["proposals"]), 5)
        self.assertTrue(session["debate"][0]["chosen_tools"])
        self.assertTrue(session["tool_results"])
        self.assertEqual(session["engines"]["council"], "parallel-threat-council")


if __name__ == "__main__":
    unittest.main()
