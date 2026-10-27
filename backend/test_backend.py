import importlib.util
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import tempfile
from unittest.mock import patch

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
from ai.manifests import packages_from_files
from ai.meterless_scout import Scout
from ai.model_client import parse_model_decision
from ai.tool import ARSENAL, list_tools, run_tool
from ai.zetaris_client import ZetarisClient, assert_readonly_sql
from cyber_tools import (
    access_control,
    clickjacking,
    cloud_config,
    cors,
    ddos,
    graphql,
    injection,
    insecure_deserialization,
    jwt,
    load_balancing,
    oauth,
    path_traversal,
    prototype_pollution,
    rate_limit,
    security_logging,
    sensitive_data,
    session,
    session_fixation,
    ssti,
    tls_posture,
    user_enumeration,
    xss,
    xxe,
)
from report import after_action_report, build_report, render_pdf

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
    "user_enumeration",
    "ddos",
    "rate_limit",
    "load_balancing",
    "cors",
    "path_traversal",
    "xxe",
    "insecure_deserialization",
    "ssti",
    "oauth",
    "jwt",
    "prototype_pollution",
    "graphql",
    "session_fixation",
    "security_logging",
    "tls_posture",
    "sensitive_data",
    "cloud_config",
}


def _load_api_module():
    spec = importlib.util.spec_from_file_location("cyber_risk_api", SRC / "fastapi.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _test_client(app):
    here = str(SRC)
    if here in sys.path:
        sys.path.remove(here)
    sys.modules.pop("fastapi", None)
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        sys.path.insert(0, here)
        raise unittest.SkipTest("fastapi is not installed")
    sys.path.insert(0, here)
    return TestClient(app)


def _api_client(module=None):
    here = str(SRC)
    if here in sys.path:
        sys.path.remove(here)
    sys.modules.pop("fastapi", None)
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        sys.path.insert(0, here)
        raise unittest.SkipTest("fastapi is not installed")
    sys.path.insert(0, here)
    return TestClient((module or _load_api_module()).create_app())


class ArsenalTests(unittest.TestCase):
    def test_preloaded_tools_are_registered(self):
        names = {item["name"] for item in list_tools()}
        expected = {
            "session",
            "website_element_manipulation",
            "pen_test",
        } | ATTACK_TYPE_TOOLS
        self.assertEqual(names, expected)
        self.assertTrue(ATTACK_TYPE_TOOLS.issubset(names))

    def test_additional_method_reviews_collected_source(self):
        result = run_tool(
            "certificate_transparency",
            {"kind": "source", "files": {"app.py": "print('ok')"}},
        )
        self.assertEqual(result["status"], "info")
        self.assertEqual(result["tool"], "certificate_transparency")
        self.assertIn("starting set", result["findings"][0]["detail"])

    def test_stay_inspect_overrides_extra_methods(self):
        skipped = run_tool(
            "certificate_transparency",
            {"kind": "source", "files": {"app.py": "print('ok')"}, "stay_inspect": True},
        )
        self.assertEqual(skipped["findings"][0]["title"], "Command overridden by stay-inspect")

    def test_command_shaped_method_is_rejected(self):
        result = run_tool("nmap -sV", {"kind": "source", "files": {}})
        self.assertEqual(result["status"], "error")


class ToolCheckTests(unittest.TestCase):
    def test_injection_flags_string_built_sql(self):
        result = injection.run(
            {
                "kind": "source",
                "files": {
                    "app.py": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
                },
            }
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_injection_passes_parameterized_sql(self):
        result = injection.run(
            {
                "kind": "source",
                "files": {"app.py": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"},
            }
        )
        self.assertEqual(result["status"], "pass")

    def test_clickjacking_requires_frame_header(self):
        missing = clickjacking.run(
            {"kind": "url", "url": "https://example.test", "http": {"headers": {}, "body": ""}}
        )
        present = clickjacking.run(
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

    def test_user_enumeration_flags_distinct_login_message(self):
        result = user_enumeration.run(
            {
                "kind": "source",
                "files": {
                    "auth.py": "def login(user):\n    if not user:\n        return 'user not found'\n"
                },
            }
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["severity"], "medium")

    def test_user_enumeration_accepts_generic_login_message(self):
        result = user_enumeration.run(
            {
                "kind": "source",
                "files": {
                    "auth.py": "def login(user):\n    return 'invalid email or password'\n"
                },
            }
        )
        self.assertEqual(result["status"], "pass")

    def test_user_enumeration_does_not_probe_a_live_url(self):
        result = user_enumeration.run(
            {
                "kind": "url",
                "url": "https://example.test/login",
                "http": {"status": 200, "headers": {}, "body": "Sign in"},
            }
        )
        self.assertEqual(result["status"], "info")
        self.assertIn("not run", result["findings"][0]["title"].lower())

    def test_ddos_flags_missing_request_cap(self):
        result = ddos.run({"kind": "source", "files": {"app.py": "def index():\n    return 'ok'\n"}})
        self.assertEqual(result["status"], "fail")
        self.assertIn("cap", result["findings"][0]["title"].lower())

    def test_ddos_accepts_body_limit_without_sending_traffic(self):
        result = ddos.run(
            {
                "kind": "source",
                "files": {"app.py": "app.config['MAX_CONTENT_LENGTH'] = 1000000\n"},
            }
        )
        self.assertEqual(result["status"], "pass")

    def test_ddos_reads_edge_header_only(self):
        result = ddos.run(
            {
                "kind": "url",
                "url": "https://example.test",
                "http": {"status": 200, "headers": {"cf-ray": "abc"}, "body": ""},
            }
        )
        self.assertEqual(result["status"], "pass")

    def test_rate_limit_flags_login_without_limiter(self):
        result = rate_limit.run(
            {
                "kind": "source",
                "files": {"app.py": "@app.route('/login')\ndef login():\n    return 'ok'\n"},
            }
        )
        self.assertEqual(result["status"], "fail")

    def test_rate_limit_accepts_limiter_on_login(self):
        result = rate_limit.run(
            {
                "kind": "source",
                "files": {
                    "app.py": "from flask_limiter import Limiter\n@app.route('/login')\ndef login():\n    return 'ok'\n"
                },
            }
        )
        self.assertEqual(result["status"], "pass")

    def test_rate_limit_reads_policy_headers_only(self):
        missing = rate_limit.run(
            {
                "kind": "url",
                "url": "https://example.test/login",
                "http": {"status": 200, "headers": {}, "body": ""},
            }
        )
        limited = rate_limit.run(
            {
                "kind": "url",
                "url": "https://example.test/login",
                "http": {"status": 429, "headers": {}, "body": ""},
            }
        )
        self.assertEqual(missing["status"], "fail")
        self.assertEqual(limited["status"], "pass")

    def test_load_balancing_flags_untrusted_forwarded_address(self):
        result = load_balancing.run(
            {
                "kind": "source",
                "files": {"app.py": "ip = request.headers.get('X-Forwarded-For')\n"},
            }
        )
        self.assertEqual(result["status"], "fail")

    def test_load_balancing_accepts_trusted_proxy(self):
        result = load_balancing.run(
            {
                "kind": "source",
                "files": {
                    "app.py": "from werkzeug.middleware.proxy_fix import ProxyFix\nip = request.headers.get('X-Forwarded-For')\n"
                },
            }
        )
        self.assertEqual(result["status"], "pass")

    def test_load_balancing_flags_memory_sessions_behind_balancer(self):
        result = load_balancing.run(
            {
                "kind": "source",
                "files": {
                    "nginx.conf": "upstream app_servers {\n    proxy_pass http://app;\n}\n",
                    "app.py": "session['user'] = user_id\n",
                },
            }
        )
        self.assertEqual(result["status"], "fail")

    def test_scout_routes_availability_prompt(self):
        decision = Scout().decide(prompt="check ddos and load balancer hardening", used_tools=[])
        self.assertEqual(decision["intent"]["primary"], "threat.availability")
        planned = {item["tool"] for item in decision["toolPlan"]}
        self.assertTrue({"ddos", "rate_limit", "load_balancing"} <= planned)

    def test_added_tools_flag_unsafe_patterns_and_accept_hardened_ones(self):
        cases = [
            (
                "cors",
                cors,
                {
                    "kind": "url",
                    "url": "https://example.test",
                    "http": {
                        "headers": {
                            "access-control-allow-origin": "*",
                            "access-control-allow-credentials": "true",
                        }
                    },
                },
                "fail",
            ),
            (
                "cors-allow",
                cors,
                {
                    "kind": "url",
                    "url": "https://example.test",
                    "http": {"headers": {"access-control-allow-origin": "https://app.example"}},
                },
                "pass",
            ),
            (
                "path",
                path_traversal,
                {"kind": "source", "files": {"app.py": 'open(os.path.join(base, request.args.get("file")))\n'}},
                "fail",
            ),
            (
                "path-guard",
                path_traversal,
                {"kind": "source", "files": {"app.py": "open(os.path.join(base, secure_filename(name)))\n"}},
                "pass",
            ),
            (
                "xxe",
                xxe,
                {"kind": "source", "files": {"app.py": 'etree.parse(request.files["xml"])\n'}},
                "fail",
            ),
            (
                "xxe-safe",
                xxe,
                {"kind": "source", "files": {"app.py": "import defusedxml\netree.parse(data)\n"}},
                "pass",
            ),
            (
                "deser",
                insecure_deserialization,
                {"kind": "source", "files": {"app.py": "pickle.loads(request.data)\n"}},
                "fail",
            ),
            (
                "deser-safe",
                insecure_deserialization,
                {"kind": "source", "files": {"app.py": "yaml.safe_load(request.data)\n"}},
                "pass",
            ),
            (
                "ssti",
                ssti,
                {"kind": "source", "files": {"app.py": 'return render_template_string(request.args.get("name"))\n'}},
                "fail",
            ),
            (
                "oauth",
                oauth,
                {"kind": "source", "files": {"app.py": 'redirect_uri = request.args.get("redirect_uri")\n'}},
                "fail",
            ),
            (
                "oauth-state",
                oauth,
                {"kind": "source", "files": {"app.py": "def oauth_login():\n    state = token\n    return state\n"}},
                "pass",
            ),
            (
                "jwt",
                jwt,
                {"kind": "source", "files": {"app.js": 'localStorage.setItem("jwt", token)\n'}},
                "fail",
            ),
            (
                "jwt-exp",
                jwt,
                {
                    "kind": "source",
                    "files": {"app.js": 'jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" })\n'},
                },
                "pass",
            ),
            (
                "proto",
                prototype_pollution,
                {"kind": "source", "files": {"app.js": "Object.assign({}, req.body)\n"}},
                "fail",
            ),
            (
                "graphql",
                graphql,
                {"kind": "source", "files": {"app.js": "new ApolloServer({ introspection: true })\n"}},
                "fail",
            ),
            (
                "graphql-limited",
                graphql,
                {
                    "kind": "source",
                    "files": {"app.js": "new ApolloServer({ introspection: false, validationRules: [depthLimit(6)] })\n"},
                },
                "pass",
            ),
            (
                "fixation",
                session_fixation,
                {"kind": "source", "files": {"app.py": 'def login():\n    session["user"] = user.id\n'}},
                "fail",
            ),
            (
                "fixation-rotate",
                session_fixation,
                {
                    "kind": "source",
                    "files": {"app.py": 'def login():\n    session.regenerate()\n    session["user"] = user.id\n'},
                },
                "pass",
            ),
            (
                "logging",
                security_logging,
                {"kind": "source", "files": {"app.py": "def login():\n    return 'ok'\n"}},
                "fail",
            ),
            (
                "logging-present",
                security_logging,
                {"kind": "source", "files": {"app.py": "def login():\n    logger.info('login')\n"}},
                "pass",
            ),
            (
                "tls",
                tls_posture,
                {"kind": "url", "url": "https://example.test", "http": {"headers": {}}},
                "fail",
            ),
            (
                "tls-hsts",
                tls_posture,
                {
                    "kind": "url",
                    "url": "https://example.test",
                    "http": {"headers": {"strict-transport-security": "max-age=31536000"}},
                },
                "pass",
            ),
            (
                "tls-source",
                tls_posture,
                {"kind": "source", "files": {"app.py": "ctx.verify = False\n"}},
                "fail",
            ),
            (
                "sensitive",
                sensitive_data,
                {"kind": "source", "files": {"app.py": 'return {"password_hash": user.password_hash}\n'}},
                "fail",
            ),
            (
                "cloud",
                cloud_config,
                {"kind": "source", "files": {"Dockerfile": "FROM python:3.12\nUSER root\n"}},
                "fail",
            ),
            (
                "cloud-user",
                cloud_config,
                {"kind": "source", "files": {"Dockerfile": "FROM python:3.12\nUSER app\n"}},
                "pass",
            ),
        ]
        for label, tool, target, status in cases:
            with self.subTest(label):
                self.assertEqual(tool.run(target)["status"], status)


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
                        "vendor": "PyPI",
                        "product": "django",
                        "name": "Example",
                        "date_added": "2024-01-01",
                        "description": "A Django issue",
                        "cvss_score": 7.5,
                        "sources": ["osv"],
                        "affected": [
                            {
                                "package": {"name": "django", "ecosystem": "PyPI"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "3.2.1"}],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "cve_id": "CVE-0000-0099",
                        "vendor": "PyPI",
                        "product": "django",
                        "description": "django is mentioned but this build is already fixed",
                        "sources": ["osv"],
                        "affected": [
                            {
                                "package": {"name": "django", "ecosystem": "PyPI"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                                    }
                                ],
                            }
                        ],
                    },
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
        self.assertEqual(report["cves"]["matched"][0]["cve_id"], "CVE-0000-0001")
        self.assertTrue(report["cves"]["matched"][0]["version_confirmed"])
        self.assertEqual(report["summary"]["score_standard"], "confirmed_cvss")
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
        items[0]["affected"] = [
            {
                "package": {"name": "nginx", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.18.0"}, {"fixed": "1.18.1"}]}
                ],
            }
        ]
        matched = cve_manger.match_cves(
            items, [{"name": "nginx", "version": "1.18.0", "ecosystem": "PyPI"}]
        )
        self.assertEqual(matched[0]["cve_id"], "CVE-1")
        self.assertTrue(matched[0]["version_confirmed"])
        self.assertEqual(
            cve_manger.match_cves(
                items, [{"name": "nginx", "version": "1.25.0", "ecosystem": "PyPI"}]
            ),
            [],
        )
        self.assertEqual(
            cve_manger.match_cves(
                [{"cve_id": "CVE-2", "product": "nginx", "description": "nginx banner"}],
                [{"name": "nginx", "version": "1.18.0", "ecosystem": "PyPI"}],
            ),
            [],
        )

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
        self.assertIn("This score is a heuristic", report["narrative"])
        self.assertTrue(report["after_action_report"]["next_steps"])
        self.assertEqual(report["cves"]["tried"][0]["cve_id"], "CVE-2024-1")

    def test_render_pdf_is_a_downloadable_document(self):
        report = build_report(
            [
                {
                    "tool": "sql_inject",
                    "status": "fail",
                    "findings": [
                        {
                            "tool": "sql_inject",
                            "severity": "high",
                            "title": "Unsafe (SQL)",
                            "detail": "Use bound parameters.",
                            "evidence": "app.py:1",
                        }
                    ],
                }
            ],
            cves={
                "matched": [
                    {
                        "cve_id": "CVE-2024-1",
                        "sources": ["cisa_kev"],
                        "cvss_score": 8.1,
                        "description": "Example issue",
                    }
                ]
            },
        )
        report["target"] = {"kind": "url", "url": "https://example.com", "company": "Example"}
        pdf = render_pdf(report)
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"Cyber Risk Scan Report", pdf)
        self.assertIn(br"Unsafe \(SQL\)", pdf)
        self.assertIn(b"CVE-2024-1", pdf)
        self.assertIn(b"After-action report", pdf)
        self.assertIn(b"/Type /Page", pdf)
        self.assertIn(b"Page 1 of", pdf)

    def test_render_pdf_paginates_long_reports(self):
        findings = [
            {
                "tool": "xss",
                "severity": "medium",
                "title": f"Finding {index}",
                "detail": "Review this input path and encode output before rendering.",
                "evidence": f"file.py:{index}",
            }
            for index in range(40)
        ]
        pdf = render_pdf(
            {
                "summary": {"nist_score": 4, "nist_rating": "Medium", "finding_count": 40},
                "findings": findings,
                "narrative": "Long report.",
                "after_action_report": {"next_steps": []},
            }
        )
        self.assertNotIn(b"/Count 1", pdf)
        self.assertGreaterEqual(pdf.count(b"/Type /Page"), 2)

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
        self.assertEqual(len(tools.json()["tools"]), 36)
        self.assertEqual(client.get("/").status_code, 404)

    def test_report_pdf_route_returns_attachment(self):
        client = _api_client()
        response = client.post(
            "/report/pdf",
            json={
                "summary": {
                    "nist_score": 3,
                    "nist_rating": "Low",
                    "finding_count": 0,
                    "severity": {},
                },
                "narrative": "No material findings.",
                "findings": [],
                "after_action_report": {"summary": "Keep monitoring.", "next_steps": []},
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        disposition = response.headers["content-disposition"]
        self.assertIn("attachment", disposition)
        self.assertIn("cyber-risk-report.pdf", disposition)
        self.assertTrue(response.content.startswith(b"%PDF-"))

    def test_scan_url_format_pdf_downloads_report(self):
        from ai import main as scan_main

        sample = {
            "summary": {"nist_score": 2, "nist_rating": "Low", "finding_count": 0, "severity": {}},
            "narrative": "Patched scan.",
            "findings": [],
            "nist": {},
            "cves": {},
            "after_action_report": {"next_steps": []},
            "target": {"kind": "url", "url": "https://example.com", "company": "Example"},
        }
        original = scan_main.run_scan
        scan_main.run_scan = lambda *args, **kwargs: sample
        try:
            app = _load_api_module().create_app()
            app.state.resolve = lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))]

            def owned_body():
                issued = app.state.ownership.issue_url(
                    "https://example.com", resolve=app.state.resolve
                )
                app.state.proof_reader = lambda url, resolve=None: issued["token"]
                return {"url": "https://example.com", "ownership_token": issued["token"]}

            client = _test_client(app)
            pdf = client.post("/scan/url?format=pdf", json=owned_body())
            kept = client.post("/scan/url", json=owned_body())
            rejected = client.post("/scan/url?format=xml", json=owned_body())
            missing = client.post("/scan/url", json={"url": "https://example.com"})
            wrong = app.state.ownership.issue_url(
                "https://example.com", resolve=app.state.resolve
            )
            app.state.proof_reader = lambda url, resolve=None: "not-the-token"
            mismatched = client.post(
                "/scan/url",
                json={"url": "https://example.com", "ownership_token": wrong["token"]},
            )
        finally:
            scan_main.run_scan = original
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.headers["content-type"], "application/pdf")
        self.assertIn("attachment", pdf.headers["content-disposition"])
        self.assertTrue(pdf.content.startswith(b"%PDF-"))
        self.assertIn(b"Patched scan.", pdf.content)
        self.assertEqual(kept.status_code, 200)
        self.assertEqual(kept.json()["narrative"], "Patched scan.")
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(missing.status_code, 422)
        self.assertEqual(mismatched.status_code, 403)
        blocked = client.post(
            "/scan/url",
            json={
                "url": "https://example.com",
                "ownership_token": "unused",
                "stay_inspect": True,
            },
        )
        self.assertEqual(blocked.status_code, 403)
        self.assertIn("override", blocked.json()["detail"].lower())

    def test_run_scan_refuses_a_mismatched_owner_before_agents(self):
        import safety

        class Council:
            def analyze(self, *args, **kwargs):
                raise AssertionError("agents ran")

        with self.assertRaises(safety.UnsafeTarget):
            run_scan(
                {
                    "kind": "source",
                    "files": {"app.py": "Copyright (c) 2024 Other Person\n"},
                },
                council=Council(),
                company_hint="Acme",
            )
        with self.assertRaises(safety.UnsafeTarget):
            run_scan(
                {"kind": "url", "url": "https://example.com"},
                council=Council(),
            )

    def test_source_scan_refuses_a_mismatched_owner(self):
        from ai import main as scan_main

        sample = {
            "summary": {"nist_score": 1, "nist_rating": "Low", "finding_count": 0, "severity": {}},
            "narrative": "Source accepted.",
            "findings": [],
            "nist": {},
            "cves": {},
            "after_action_report": {"next_steps": []},
            "target": {"kind": "source"},
        }
        original = scan_main.run_scan
        scan_main.run_scan = lambda *args, **kwargs: sample
        try:
            app = _load_api_module().create_app()
            client = _test_client(app)
            issued = client.post("/verify/source").json()
            private = client.post("/verify/url", json={"url": "http://127.0.0.1"})
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("app.py", "print(1)")
                archive.writestr("cyber-risk-owner.txt", issued["token"])
            payload = buffer.getvalue()
            good = client.post(
                "/scan/source",
                files={"archive": ("app.zip", payload, "application/zip")},
                params={"ownership_token": issued["token"]},
            )
            bare = io.BytesIO()
            with zipfile.ZipFile(bare, "w") as archive:
                archive.writestr("app.py", "print(1)")
            unlabeled = client.post(
                "/scan/source",
                files={"archive": ("app.zip", bare.getvalue(), "application/zip")},
            )
            mismatch = io.BytesIO()
            with zipfile.ZipFile(mismatch, "w") as archive:
                archive.writestr("app.py", "Copyright (c) 2024 Other Person\nprint(1)\n")
            refused = client.post(
                "/scan/source",
                files={"archive": ("app.zip", mismatch.getvalue(), "application/zip")},
                params={"company": "Acme"},
            )
            other = client.post("/verify/source").json()
            wrong = io.BytesIO()
            with zipfile.ZipFile(wrong, "w") as archive:
                archive.writestr("app.py", "print(1)")
                archive.writestr("cyber-risk-owner.txt", "not-the-token")
            bad_token = client.post(
                "/scan/source",
                files={"archive": ("app.zip", wrong.getvalue(), "application/zip")},
                params={"ownership_token": other["token"]},
            )
        finally:
            scan_main.run_scan = original
        self.assertEqual(private.status_code, 403)
        self.assertEqual(good.status_code, 200)
        self.assertEqual(good.json()["narrative"], "Source accepted.")
        self.assertEqual(unlabeled.status_code, 200)
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(bad_token.status_code, 403)

    def test_github_scan_requires_token_and_github_repository(self):
        client = _api_client()
        missing_token = client.post("/scan/github", json={"repository": "owner/repo"})
        invalid_host = client.post(
            "/scan/github",
            json={"repository": "https://example.com/owner/repo"},
            headers={"Authorization": "Bearer test-token"},
        )
        self.assertEqual(missing_token.status_code, 401)
        self.assertEqual(invalid_host.status_code, 400)

    def test_github_scan_rejects_repository_not_owned_by_token_user(self):
        module = _load_api_module()
        def github_json(path, token):
            self.assertEqual(token, "test-token")
            if path == "/user":
                return {"login": "another-user"}
            return {"owner": {"login": "repo-owner"}}

        with patch.object(module, "_github_api_json", side_effect=github_json), patch.object(
            module,
            "_download_github_archive",
            side_effect=AssertionError("non-owner must not download the repository"),
        ):
            response = _api_client(module).post(
                "/scan/github",
                json={"repository": "repo-owner/private-repo"},
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertIn("owned", response.json()["detail"])

    def test_github_scan_sends_owned_archive_to_source_scanner(self):
        module = _load_api_module()
        from ai import main as scan_main

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("project/src/app.py", "print('source')")
        captured = {}

        def github_json(path, token):
            self.assertEqual(token, "test-token")
            if path == "/user":
                return {"login": "repo-owner"}
            return {"owner": {"login": "Repo-Owner"}}

        def fake_scan(target, company_hint=""):
            captured["target"] = target
            captured["company_hint"] = company_hint
            return {"target": {"kind": "source"}, "summary": {}}

        with patch.object(module, "_github_api_json", side_effect=github_json), patch.object(
            module,
            "_download_github_archive",
            return_value=archive_buffer.getvalue(),
        ), patch.object(scan_main, "run_scan", side_effect=fake_scan):
            response = _api_client(module).post(
                "/scan/github",
                json={"repository": "https://github.com/repo-owner/project.git"},
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured["target"]["kind"], "source")
        self.assertEqual(captured["target"]["files"], {"project/src/app.py": "print('source')"})
        self.assertEqual(captured["company_hint"], "repo-owner/project")
        self.assertEqual(response.json()["target"]["url"], "https://github.com/repo-owner/project")

    def test_github_scan_treats_verified_owner_as_ownership_proof(self):
        module = _load_api_module()
        import safety
        from ai import main as scan_main

        files = {"project/app.py": "# Copyright (c) 2024 Jane Doe\nprint('hi')\n"}
        with self.assertRaises(safety.UnsafeTarget):
            safety.gate_before_agents(
                {"kind": "source", "files": dict(files)}, claimed_owner="janedoe/project"
            )

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            for name, text in files.items():
                archive.writestr(name, text)
        captured = {}

        def github_json(path, token):
            if path == "/user":
                return {"login": "janedoe"}
            return {"owner": {"login": "janedoe"}}

        def gated_scan(target, company_hint=""):
            captured["target"] = target
            captured["gate"] = safety.gate_before_agents(target, claimed_owner=company_hint)
            return {"target": {"kind": "source"}, "summary": {}}

        with patch.object(module, "_github_api_json", side_effect=github_json), patch.object(
            module,
            "_download_github_archive",
            return_value=archive_buffer.getvalue(),
        ), patch.object(scan_main, "run_scan", side_effect=gated_scan):
            response = _api_client(module).post(
                "/scan/github",
                json={"repository": "janedoe/project"},
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured["gate"], {"skipped": True})
        self.assertFalse(captured["target"]["ownership_assumed"])


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


class ZetarisCveIntegrationTests(unittest.TestCase):
    def _make_client(self, responses):
        """Build a ZetarisClient with a fake opener that returns canned responses."""
        call_log = []

        def opener(request, timeout=20):
            call_log.append(json.loads(request.data.decode("utf-8"))["sql"])
            body = responses.pop(0) if responses else {}
            raw = json.dumps(body).encode("utf-8")

            class Resp:
                def read(self):
                    return raw

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return Resp()

        client = ZetarisClient(
            cfg={
                "base_url": "http://zetaris.test",
                "query_path": "/api/proxy/sql-editor/sqls/run-query",
                "org_id": "org-1",
                "api_key": "key-1",
                "query_limit": 100,
                "threat_sql": "",
            },
            opener=opener,
        )
        return client, call_log

    def test_write_sql_sends_statement(self):
        client, log = self._make_client([{"ok": True}])
        result = client.write_sql("CREATE TABLE test (id INT)")
        self.assertTrue(result["ok"])
        self.assertEqual(log[0], "CREATE TABLE test (id INT)")

    def test_write_sql_offline_when_not_configured(self):
        client = ZetarisClient(
            cfg={"base_url": "http://x", "query_path": "/api/proxy/sql-editor/sqls/run-query", "org_id": "", "api_key": "", "query_limit": 1000, "threat_sql": ""}
        )
        result = client.write_sql("CREATE TABLE test (id INT)")
        self.assertFalse(result["ok"])
        self.assertEqual(result["mode"], "offline")

    def test_fetch_cves_from_zetaris_parses_rows(self):
        rows = [
            {
                "cve_id": "CVE-2024-1234",
                "vendor": "PyPI",
                "product": "django",
                "name": "CVE-2024-1234",
                "date_added": "2024-06-01",
                "description": "A django issue",
                "cvss_score": "9.1",
                "severity": "critical",
                "sources": "nist_nvd,cisa_kev",
            }
        ]
        client, _ = self._make_client([{"headers": list(rows[0].keys()), "data": rows}])
        items, ok = cve_manger.fetch_cves_from_zetaris(client, limit=10)
        self.assertTrue(ok)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["cve_id"], "CVE-2024-1234")
        self.assertEqual(items[0]["cvss_score"], 9.1)
        self.assertEqual(set(items[0]["sources"]), {"nist_nvd", "cisa_kev"})

    def test_fetch_cves_from_zetaris_returns_empty_on_failure(self):
        client = ZetarisClient(
            cfg={"base_url": "http://x", "query_path": "/api/proxy/sql-editor/sqls/run-query", "org_id": "", "api_key": "", "query_limit": 1000, "threat_sql": ""}
        )
        items, ok = cve_manger.fetch_cves_from_zetaris(client, limit=10)
        self.assertFalse(ok)
        self.assertEqual(items, [])

    def test_fetch_latest_cves_prefers_zetaris(self):
        zetaris_rows = [
            {
                "cve_id": "CVE-Z-001",
                "vendor": "PyPI",
                "product": "flask",
                "name": "CVE-Z-001",
                "date_added": "2024-01-01",
                "description": "Zetaris-loaded CVE",
                "cvss_score": "7.5",
                "severity": "high",
                "sources": "zetaris",
            }
        ]
        client, _ = self._make_client(
            [{"headers": list(zetaris_rows[0].keys()), "data": zetaris_rows}]
        )
        summary = cve_manger.fetch_latest_cves(
            packages=[],
            zetaris_client=client,
        )
        self.assertEqual(summary["source"], "zetaris")
        self.assertIn("zetaris", summary["sources"])
        self.assertEqual(summary["items"][0]["cve_id"], "CVE-Z-001")

    def test_zetaris_path_enriches_with_osv_affected_ranges(self):
        """Zetaris catalog + OSV version query = items with affected ranges."""
        zetaris_rows = [
            {
                "cve_id": "CVE-2024-1111",
                "vendor": "PyPI",
                "product": "django",
                "name": "CVE-2024-1111",
                "date_added": "2024-06-01",
                "description": "A django issue",
                "cvss_score": "9.8",
                "severity": "critical",
                "sources": "zetaris",
            }
        ]
        zetaris_client, _ = self._make_client(
            [{"headers": list(zetaris_rows[0].keys()), "data": zetaris_rows}]
        )

        class Body:
            def __init__(self, payload):
                self._data = json.dumps(payload).encode("utf-8")
            def read(self):
                return self._data
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def opener(request, timeout=20):
            url = request.full_url
            if "known_exploited" in url:
                return Body({"vulnerabilities": [{"cveID": "CVE-2024-1111"}]})
            return Body({
                "vulns": [{
                    "id": "GHSA-1",
                    "aliases": ["CVE-2024-1111"],
                    "summary": "django issue",
                    "affected": [{
                        "package": {"name": "Django", "ecosystem": "PyPI"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.1"}]}],
                    }],
                    "database_specific": {"cvss_score": 9.8},
                }]
            })

        summary = cve_manger.fetch_latest_cves(
            opener=opener,
            packages=[{"name": "django", "version": "3.2.0", "ecosystem": "PyPI"}],
            zetaris_client=zetaris_client,
        )
        self.assertEqual(summary["source"], "zetaris")
        self.assertIn("zetaris", summary["sources"])
        matched = cve_manger.match_cves(
            summary["items"],
            [{"name": "django", "version": "3.2.0", "ecosystem": "PyPI"}],
        )
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["cve_id"], "CVE-2024-1111")
        self.assertTrue(matched[0]["version_confirmed"])
        self.assertIn("cisa_kev", matched[0]["sources"])

    def test_setup_zetaris_insert_values(self):
        from ai.setup_zetaris import _insert_values, _escape_pg

        items = [
            {
                "cve_id": "CVE-2024-5678",
                "vendor": "PyPI",
                "product": "requests",
                "name": "CVE-2024-5678",
                "date_added": "2024-07-01",
                "description": "A request's issue with single quote",
                "cvss_score": 8.2,
                "severity": "high",
                "sources": ["nist_nvd", "osv"],
            }
        ]
        stmts = _insert_values(items, "2024-07-01T00:00:00Z")
        self.assertEqual(len(stmts), 1)
        self.assertIn("CVE-2024-5678", stmts[0])
        self.assertIn("INSERT INTO cve_items", stmts[0])
        self.assertIn("nist_nvd,osv", stmts[0])
        self.assertIn("ON CONFLICT", stmts[0])
        self.assertNotIn("''", _escape_pg("safe"))
        self.assertIn("''", _escape_pg("it's"))

    def test_setup_zetaris_batches_inserts(self):
        from ai.setup_zetaris import _insert_values

        items = [
            {"cve_id": f"CVE-{i}", "sources": ["test"]}
            for i in range(120)
        ]
        stmts = _insert_values(items, "2024-01-01T00:00:00Z", batch_size=50)
        self.assertEqual(len(stmts), 3)

    def test_fetch_cves_from_zetaris_uses_qualified_table(self):
        """The Zetaris query must use CVE_PG.cve_items (schema-qualified)."""
        client, log = self._make_client(
            [{"headers": ["cve_id"], "data": [["CVE-1"]]}]
        )
        cve_manger.fetch_cves_from_zetaris(client, limit=5)
        self.assertIn("CVE_PG.cve_items", log[0])


class CouncilAndIntegrationTests(unittest.TestCase):
    def test_zetaris_rejects_non_readonly_sql(self):
        with self.assertRaises(ValueError):
            assert_readonly_sql("DROP TABLE users")
        self.assertEqual(assert_readonly_sql("SELECT 1"), "SELECT 1")

    def test_zetaris_offline_fallback(self):
        client = ZetarisClient(cfg={"base_url": "http://example", "query_path": "/api/proxy/sql-editor/sqls/run-query", "org_id": "", "api_key": "", "query_limit": 1000, "threat_sql": ""})
        result = client.company_threat_context("Acme", fingerprints=["django"])
        self.assertEqual(result["source"], "local_fallback")

    def test_scout_emits_execution_contract(self):
        decision = Scout().decide(
            prompt="Analyze auth and session risk for this company",
            used_tools=[],
            max_tools=3,
        )
        self.assertIn("executionContract", decision)
        self.assertEqual(decision["executionContract"]["policy"], "arsenal_first_open_methods")
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


class VersionMatchAndModelTests(unittest.TestCase):
    def test_manifests_keep_exact_versions_only(self):
        packages = packages_from_files(
            {
                "requirements.txt": "django==3.2.0\nrequests>=2.0\n",
                "pkg/package.json": json.dumps(
                    {"dependencies": {"left-pad": "1.2.3", "lodash": "^4.17.21"}}
                ),
                "go.mod": "module example.com/demo\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
            }
        )
        found = {(item["ecosystem"], item["name"], item["version"]) for item in packages}
        self.assertIn(("PyPI", "django", "3.2.0"), found)
        self.assertIn(("npm", "left-pad", "1.2.3"), found)
        self.assertIn(("Go", "github.com/gin-gonic/gin", "1.9.1"), found)
        self.assertNotIn(("PyPI", "requests", "2.0"), found)
        self.assertFalse(any(item["name"] == "lodash" for item in packages))

    def test_lockfile_versions_replace_package_json_ranges(self):
        packages = packages_from_files(
            {
                "package.json": json.dumps({"dependencies": {"left-pad": "1.0.0"}}),
                "package-lock.json": json.dumps(
                    {"packages": {"node_modules/lodash": {"version": "4.17.20"}}}
                ),
            }
        )
        names = {item["name"] for item in packages}
        self.assertIn("lodash", names)
        self.assertNotIn("left-pad", names)

    def test_lockfile_without_versions_does_not_hide_package_json(self):
        empty = packages_from_files(
            {
                "package.json": json.dumps({"dependencies": {"left-pad": "1.2.3"}}),
                "package-lock.json": json.dumps({"dependencies": {}}),
            }
        )
        invalid = packages_from_files(
            {
                "package.json": json.dumps({"dependencies": {"left-pad": "1.2.3"}}),
                "package-lock.json": json.dumps(
                    {"dependencies": {"lodash": "4.17.21", "broken": {"name": "nope"}}}
                ),
            }
        )
        valid = packages_from_files(
            {
                "package.json": json.dumps({"dependencies": {"left-pad": "1.0.0"}}),
                "package-lock.json": json.dumps(
                    {"dependencies": {"lodash": {"version": "4.17.20"}}}
                ),
            }
        )
        self.assertEqual({item["name"] for item in empty}, {"left-pad"})
        self.assertEqual({item["name"] for item in invalid}, {"left-pad"})
        self.assertEqual({item["name"] for item in valid}, {"lodash"})

    def test_duplicate_findings_count_once(self):
        finding = {
            "tool": "injection",
            "severity": "high",
            "title": "Unsafe SQL",
            "detail": "Use bound parameters.",
            "evidence": "app.py:1",
        }
        report = build_report(
            [
                {"tool": "injection", "status": "fail", "findings": [finding]},
                {"tool": "xss", "status": "fail", "findings": [dict(finding)]},
            ]
        )
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["summary"]["severity"]["high"], 1)

    def test_model_decision_keeps_methods_outside_the_starting_set(self):
        parsed = parse_model_decision(
            '```json\n{"argument":"Check injection because the handler builds a query.","votes":["injection","not_a_tool","nmap -sV"]}\n```',
            ["injection", "xss"],
        )
        self.assertEqual(parsed["votes"], ["injection", "not_a_tool"])
        self.assertNotIn("nmap -sV", parsed["votes"])

    def test_council_uses_model_votes_when_configured(self):
        class FakeModel:
            def configured(self):
                return True

            def complete(self, messages):
                self.last = messages
                return json.dumps(
                    {
                        "argument": "Run injection because the source may concatenate queries.",
                        "votes": ["injection", "not_a_tool", "xss"],
                    }
                )

        model = FakeModel()
        council = ThreatCouncil(model=model, max_rounds=1, tools_per_round=2)
        session = council.analyze(
            {"kind": "source", "files": {"app.py": "print('ok')"}},
            company_hint="Acme",
        )
        votes = [vote for proposal in session["debate"][0]["proposals"] for vote in proposal["votes"]]
        self.assertIn("not_a_tool", votes)
        self.assertIn("injection", votes)
        self.assertTrue(all(proposal.get("source") == "model" for proposal in session["debate"][0]["proposals"]))
        self.assertEqual(session["engines"]["meterless_model"], "meterless-chat")
        self.assertIn("starting set", model.last[0]["content"].lower())
        self.assertIn("not_a_tool", [item.get("tool") for item in session["tool_results"]])

    def test_version_query_badges_kev(self):
        class Body:
            def __init__(self, payload):
                self.payload = json.dumps(payload).encode("utf-8")

            def read(self):
                return self.payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(request, timeout=20):
            url = request.full_url
            if "known_exploited" in url:
                return Body({"vulnerabilities": [{"cveID": "CVE-2024-1111"}]})
            return Body(
                {
                    "vulns": [
                        {
                            "id": "GHSA-1",
                            "aliases": ["CVE-2024-1111"],
                            "summary": "Example django issue",
                            "affected": [
                                {
                                    "package": {"name": "Django", "ecosystem": "PyPI"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "3.2.1"}],
                                        }
                                    ],
                                }
                            ],
                            "database_specific": {"cvss_score": 9.8},
                        }
                    ]
                }
            )

        summary = cve_manger.fetch_latest_cves(
            opener=opener,
            packages=[{"name": "django", "version": "3.2.0", "ecosystem": "PyPI"}],
        )
        matched = cve_manger.match_cves(
            summary["items"],
            [{"name": "django", "version": "3.2.0", "ecosystem": "PyPI"}],
        )
        self.assertEqual(matched[0]["cve_id"], "CVE-2024-1111")
        self.assertIn("cisa_kev", matched[0]["sources"])
        self.assertTrue(matched[0]["kev"])
        self.assertEqual(matched[0]["cvss_score"], 9.8)


if __name__ == "__main__":
    unittest.main()
