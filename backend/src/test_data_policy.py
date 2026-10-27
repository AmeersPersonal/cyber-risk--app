import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parent
ROOT = SRC.parents[1]
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from data_policy import (
    NOT_PERMITTED,
    PERMITTED,
    PROJECT_SOURCES,
    SYNTHETIC_NOTICE,
    DataNotPermitted,
    assert_permitted,
    assert_static_dataset_text,
    permit_project_source,
    reject_committed_secrets,
)
from ai import cve_manger
from ai.cve_knowledge import load_cve_entry
from ai.setup_zetaris import fetch_all_cves


class RuleTextTests(unittest.TestCase):
    def test_readme_and_agents_state_section_11(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for text in (readme, agents):
            self.assertIn("11.1 Permitted", text)
            self.assertIn("11.2 Not permitted", text)
            for rule in PERMITTED + NOT_PERMITTED:
                self.assertIn(rule, text)

    def test_env_example_commits_no_secret_values(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        reject_committed_secrets(text)
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            if any(word in key.upper() for word in ("KEY", "PASSWORD", "TOKEN", "SECRET")):
                self.assertEqual(value.strip(), "")


class PermittedSourceTests(unittest.TestCase):
    def test_project_sources_are_permitted(self):
        for name in PROJECT_SOURCES:
            with self.subTest(name=name):
                self.assertIs(permit_project_source(name), PROJECT_SOURCES[name])

    def test_each_permitted_kind_passes(self):
        assert_permitted({"kind": "public_dataset", "licence": "Apache-2.0"})
        assert_permitted({"kind": "static_dataset", "size_bytes": 100})
        assert_permitted({"kind": "download_script", "login": False, "manual_steps": False})
        assert_permitted({"kind": "public_api", "login": False})
        assert_permitted({"kind": "synthetic", "notice": SYNTHETIC_NOTICE})

    def test_section_11_2_sources_are_refused(self):
        refused = (
            {"kind": "public_dataset", "licence": "proprietary", "restricted": True},
            {"kind": "static_dataset", "personal_data": True},
            {"kind": "public_api", "committed_secret": True},
            {"kind": "public_dataset", "licence": "CC-BY-4.0", "license_breach": True},
            {"kind": "malware"},
            {"kind": "exploit_code"},
            {"kind": "credential_harvesting"},
            {"kind": "harmful_automation"},
            {"kind": "public_api", "harmful": True},
            {"kind": "public_dataset"},
            {"kind": "download_script", "login": True},
            {"kind": "download_script", "manual_steps": True},
            {"kind": "public_api", "login": True},
            {"kind": "synthetic", "identified": False},
            {"kind": "static_dataset", "size_bytes": 2_000_000},
        )
        for source in refused:
            with self.subTest(source=source):
                with self.assertRaises(DataNotPermitted):
                    assert_permitted(source)

    def test_personal_data_needs_authorisation_and_safeguards(self):
        with self.assertRaises(DataNotPermitted):
            assert_permitted(
                {"kind": "static_dataset", "personal_data": True, "authorized": True}
            )
        assert_permitted(
            {
                "kind": "static_dataset",
                "personal_data": True,
                "authorized": True,
                "safeguards": True,
            }
        )

    def test_committed_secrets_in_dataset_text_are_refused(self):
        reject_committed_secrets("Log4j should be upgraded.")
        samples = (
            "-----BEGIN PRIVATE KEY-----\nabc",
            "-----BEGIN CERTIFICATE-----\nabc",
            "aws_key = AKIAIOSFODNN7EXAMPLE",
            "token = 'ghp_1234567890abcdefghij'",
            'api_key = "sk-live-abcdefghijklmnopqrstuvwxyz"',
        )
        for sample in samples:
            with self.subTest(sample=sample[:24]):
                with self.assertRaises(DataNotPermitted):
                    assert_static_dataset_text(sample)


class WiredSourceTests(unittest.TestCase):
    def test_public_fetches_check_the_policy_before_the_network(self):
        def opener(*_args, **_kwargs):
            raise AssertionError("network should not be called")

        with patch("ai.cve_manger.permit_project_source", side_effect=DataNotPermitted("refused")):
            for call in (
                lambda: cve_manger.fetch_cisa_kev(opener),
                lambda: cve_manger.fetch_nist_nvd(opener),
                lambda: cve_manger.fetch_osv_for_fingerprints(opener, ["flask"]),
                lambda: cve_manger.fetch_kev_ids(opener),
                lambda: cve_manger.query_osv_version(
                    opener, {"name": "flask", "ecosystem": "PyPI", "version": "1.0.0"}
                ),
            ):
                with self.subTest(call=call):
                    with self.assertRaises(DataNotPermitted):
                        call()

    def test_local_cve_knowledge_loads_under_the_policy(self):
        entry = load_cve_entry("CVE-2021-44228")
        self.assertEqual(entry["cve_name"], "CVE-2021-44228")
        self.assertNotIn("BEGIN PRIVATE KEY", entry["how_it_works"])

    def test_demo_data_is_labeled_synthetic(self):
        demo = ROOT / "aegis-demo"
        mock = (demo / "src" / "data" / "mock.ts").read_text(encoding="utf-8")
        sample = (demo / "src" / "data" / "sample.json").read_text(encoding="utf-8")
        copy = (demo / "sample.json").read_text(encoding="utf-8")
        self.assertIn(SYNTHETIC_NOTICE, mock)
        self.assertIn('"data_classification": "synthetic"', sample)
        self.assertIn('"data_classification": "synthetic"', copy)

    def test_download_script_checks_the_policy_first(self):
        with patch(
            "data_policy.permit_project_source",
            side_effect=DataNotPermitted("refused"),
        ):
            with self.assertRaises(DataNotPermitted):
                fetch_all_cves()


if __name__ == "__main__":
    unittest.main()
