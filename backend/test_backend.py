import importlib.util
import io
import sys
import unittest
import zipfile
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import tempfile

from ai import cve_manger
from ai.council import ThreatCouncil
from ai.cve_knowledge import (
    agent_context,
    initialize_cve_knowledge,
    load_cve_entry,
    load_common_cve_names,
    zero_day_path,
)
from ai.debate_manger import DebateManager
from ai.main import files_from_zip, run_scan
from ai.meterless_scout import Scout
from ai.tool import ARSENAL, list_tools, run_tool
from ai.zetaris_client import ZetarisClient, assert_readonly_sql
from cyber_tools import access_control, click_jacking, session, sql_inject, xss
from report import after_action_report, build_report

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
        self.assertIn("nist_score", report["summary"])
        self.assertGreaterEqual(report["summary"]["nist_score"], 1)
        self.assertLessEqual(report["summary"]["nist_score"], 10)
        self.assertIn("explanation", report["nist"])
        self.assertIn("next_steps", report["after_action_report"])

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

    def test_cross_check_merges_nist_and_cisa(self):
        merged = cve_manger._merge_items(
            [
                [
                    {
                        "cve_id": "CVE-2024-1",
                        "vendor": "Nginx",
                        "product": "nginx",
                        "name": "Example",
                        "description": "kev",
                        "cvss_score": None,
                        "severity": "known_exploited",
                        "sources": ["cisa_kev"],
                    }
                ],
                [
                    {
                        "cve_id": "CVE-2024-1",
                        "vendor": "nginx",
                        "product": "nginx",
                        "name": "CVE-2024-1",
                        "description": "nvd detail",
                        "cvss_score": 9.8,
                        "severity": "critical",
                        "sources": ["nist_nvd"],
                    }
                ],
            ]
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(set(merged[0]["sources"]), {"cisa_kev", "nist_nvd"})
        self.assertEqual(merged[0]["cvss_score"], 9.8)
        check = cve_manger.cross_check_summary(merged)
        self.assertEqual(check["confirmed_by_multiple_sources"], 1)

    def test_build_report_nist_score_and_after_action(self):
        report = build_report(
            [
                {
                    "tool": "sql_inject",
                    "status": "fail",
                    "findings": [
                        {
                            "tool": "sql_inject",
                            "severity": "high",
                            "title": "Unsafe SQL",
                            "detail": "Use bound parameters.",
                            "evidence": "app.py:1",
                        }
                    ],
                },
                {
                    "tool": "session",
                    "status": "pass",
                    "findings": [
                        {
                            "tool": "session",
                            "severity": "info",
                            "title": "Flags present",
                            "detail": "ok",
                            "evidence": "",
                        }
                    ],
                },
            ],
            cves={
                "matched": [
                    {
                        "cve_id": "CVE-2024-1",
                        "product": "django",
                        "sources": ["cisa_kev", "nist_nvd"],
                        "cvss_score": 8.1,
                        "description": "Example issue",
                    }
                ],
                "items": [
                    {"cve_id": "CVE-2024-1", "sources": ["cisa_kev", "nist_nvd"]},
                    {"cve_id": "CVE-2024-2", "sources": ["osv"]},
                ],
                "sources": ["cisa_kev", "nist_nvd", "osv"],
                "cross_check": {"by_source": {"cisa_kev": 1, "nist_nvd": 1, "osv": 1}},
            },
        )
        self.assertEqual(report["summary"]["finding_count"], 2)
        self.assertEqual(report["summary"]["severity"]["high"], 1)
        self.assertGreaterEqual(report["nist"]["score"], 1)
        self.assertLessEqual(report["nist"]["score"], 10)
        self.assertIn("sql_inject", report["nist"]["tools_used"])
        self.assertEqual(report["nist"]["failed"][0]["tool"], "sql_inject")
        self.assertEqual(report["nist"]["passed"][0]["tool"], "session")
        self.assertIn("NIST/CVSS-aligned risk score", report["narrative"])
        self.assertTrue(report["after_action_report"]["next_steps"])
        self.assertEqual(report["cves"]["tried"][0]["cve_id"], "CVE-2024-1")

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


class CveKnowledgeTests(unittest.TestCase):
    def test_initialization_writes_common_list_and_zero_day_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = initialize_cve_knowledge(force=True, knowledge_dir=tmp)
            names = load_common_cve_names(knowledge_dir=tmp)
            self.assertGreaterEqual(len(names), 1)
            self.assertEqual(result["count"], len(names))
            sample = names[0]
            path = zero_day_path(sample, root=Path(tmp) / "zero_days")
            self.assertTrue(path.exists())
            entry = load_cve_entry(sample, knowledge_dir=tmp)
            self.assertEqual(entry["cve_name"], sample)
            self.assertIn("how_it_works", entry)
            self.assertIn("defend_against", entry)

    def test_after_action_uses_local_defend_against(self):
        aar = after_action_report(
            findings=[],
            matched_cves=[
                {
                    "cve_id": "CVE-2021-44228",
                    "sources": ["cisa_kev"],
                    "cvss_score": 10,
                    "description": "log4j",
                }
            ],
            outcomes={"failed": [], "passed": [], "info": [], "used": []},
            cve_knowledge={
                "CVE-2021-44228": {
                    "cve_name": "CVE-2021-44228",
                    "how_it_works": "lookup abuse",
                    "defend_against": "Upgrade Log4j and disable message lookups.",
                }
            },
        )
        self.assertIn("Upgrade Log4j", aar["next_steps"][0]["detail"])

    def test_agent_context_includes_common_cves(self):
        context = agent_context(limit=3)
        self.assertTrue(context["common_cves"])
        self.assertTrue(context["text"])


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
        self.assertEqual(session["engines"]["debate_manager"], "debate-manager-local")
        self.assertIn("debate_manager", session["debate"][0])


class DebateManagerTests(unittest.TestCase):
    def test_rejects_bare_agree_without_reasoning(self):
        manager = DebateManager(session_id="test-bare")
        check = manager.validate_argument("I agree")
        self.assertFalse(check["ok"])
        self.assertIn("bare_agree_disagree", check["violations"])

    def test_accepts_reasoned_tool_argument(self):
        manager = DebateManager(session_id="test-reason")
        check = manager.validate_argument(
            "attacker_mindset: we should run injection because prior findings show high risk input paths."
        )
        self.assertTrue(check["ok"])

    def test_resolves_duplicate_collision_and_overlooked_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Path(tmp) / "storage"
            manager = DebateManager(
                storage_dir=storage,
                session_id="test-collision",
            )
            sample = manager.load_sample_conversation()
            self.assertIsNotNone(sample)
            moderated = manager.moderate_round(
                sample["round"],
                sample["proposals"],
                used_tools=[],
                max_tools=4,
            )
            self.assertIn("defender", moderated["resolution"]["invalid_agents"])
            collision_types = {item["type"] for item in moderated["collisions"]}
            self.assertIn("unreasoned_stance", collision_types)
            self.assertIn("duplicate_tool", collision_types)
            self.assertTrue(moderated["chosen_tools"])
            self.assertLessEqual(len(moderated["chosen_tools"]), 4)
            # Defender's bare agree must not keep xss solely from that agent;
            # reasoned votes and overlooked fills still produce a plan.
            stored = manager.load_agent_context("debate_manager")
            self.assertTrue(stored)
            self.assertEqual(stored[-1]["resolution"]["invalid_agents"], ["defender"])

    def test_guidelines_prompt_includes_reasoning_rules(self):
        manager = DebateManager(session_id="test-guidelines")
        prompt = manager.guidelines_prompt()
        self.assertIn("agree", prompt.lower())
        self.assertIn("reasoning", prompt.lower())
        sections = manager.load_guidelines()
        self.assertGreaterEqual(len(sections), 3)


if __name__ == "__main__":
    unittest.main()
