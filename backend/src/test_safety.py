import io
import sys
import unittest
import zipfile
from pathlib import Path

SRC = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from safety import (
    OWNER_FILE,
    UnsafeTarget,
    OwnershipStore,
    assert_action_allowed,
    check_archive,
    check_redirect,
    check_url,
    require_authorization,
    gate_before_agents,
    stay_inspect_enabled,
    verify_source_ownership,
    verify_url_ownership,
)


def _public(_host, _port):
    return [(None, None, None, None, ("93.184.216.34", 0))]


def _private(_host, _port):
    return [(None, None, None, None, ("10.1.1.1", 0))]


def _zip(name="app.py", payload=b"print(1)"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, payload)
    return buffer.getvalue()


class SafetyTests(unittest.TestCase):
    def test_authorization_must_be_explicit(self):
        require_authorization(True)
        with self.assertRaises(UnsafeTarget):
            require_authorization(False)
        with self.assertRaises(UnsafeTarget):
            require_authorization(None)

    def test_public_https_url_is_allowed(self):
        self.assertEqual(
            check_url("https://example.com/path", resolve=_public),
            "https://example.com/path",
        )

    def test_private_and_local_targets_are_refused(self):
        for url in (
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://192.168.0.8/",
            "http://169.254.169.254/",
            "http://localhost/",
            "http://metadata.google.internal/",
            "file:///tmp/secret",
            "http://2130706433/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(UnsafeTarget):
                    check_url(url, resolve=_public)

    def test_hostname_that_resolves_private_is_refused(self):
        with self.assertRaises(UnsafeTarget):
            check_url("https://internal.example", resolve=_private)

    def test_redirect_uses_the_same_rules(self):
        self.assertTrue(check_redirect("https://example.com", resolve=_public))
        with self.assertRaises(UnsafeTarget):
            check_redirect("http://127.0.0.1/admin", resolve=_public)

    def test_archive_limits_and_paths(self):
        self.assertTrue(check_archive(_zip()))
        with self.assertRaises(UnsafeTarget):
            check_archive(_zip("../secret.txt"))
        with self.assertRaises(UnsafeTarget):
            check_archive(b"not-a-zip")
        with self.assertRaises(UnsafeTarget):
            check_archive(_zip(payload=b"x" * 1_000_001))

    def test_only_inspection_actions_are_allowed(self):
        assert_action_allowed("inspect")
        assert_action_allowed("match_cve")
        assert_action_allowed("report")
        with self.assertRaises(UnsafeTarget):
            assert_action_allowed("exploit")

    def test_stay_inspect_is_off_until_override(self):
        self.assertFalse(stay_inspect_enabled(False, False))
        self.assertFalse(stay_inspect_enabled(False, True))
        with self.assertRaises(UnsafeTarget):
            stay_inspect_enabled(True, False)
        self.assertTrue(stay_inspect_enabled(True, True))


class OwnershipTests(unittest.TestCase):
    def test_url_proof_must_match_the_issued_site(self):
        store = OwnershipStore()
        issued = store.issue_url("https://example.com/app", resolve=_public)
        seen = []

        def fetch(url):
            seen.append(url)
            return issued["token"]

        verify_url_ownership(
            "https://example.com/app",
            issued["token"],
            store,
            fetch,
            resolve=_public,
        )
        self.assertEqual(seen, ["https://example.com/.well-known/cyber-risk-verify.txt"])
        with self.assertRaises(UnsafeTarget):
            verify_url_ownership(
                "https://example.com/app",
                issued["token"],
                store,
                fetch,
                resolve=_public,
            )

    def test_url_proof_rejects_a_different_host_and_a_wrong_body(self):
        store = OwnershipStore()
        issued = store.issue_url("https://example.com", resolve=_public)
        with self.assertRaises(UnsafeTarget):
            verify_url_ownership(
                "https://other.example",
                issued["token"],
                store,
                lambda url: issued["token"],
                resolve=_public,
            )
        with self.assertRaises(UnsafeTarget):
            verify_url_ownership(
                "https://example.com",
                issued["token"],
                store,
                lambda url: "not-the-token",
                resolve=_public,
            )
        with self.assertRaises(UnsafeTarget):
            store.issue_url("http://127.0.0.1", resolve=_public)

    def test_source_proof_uses_the_root_owner_file(self):
        store = OwnershipStore()
        issued = store.issue_source()
        matched = verify_source_ownership(
            {OWNER_FILE: issued["token"] + "\n", "app.py": "print(1)"},
            issued["token"],
            store,
        )
        self.assertFalse(matched["assumed"])
        again = store.issue_source()
        assumed = verify_source_ownership(
            {"nested/" + OWNER_FILE: again["token"], "app.py": "print(1)"},
            again["token"],
            store,
        )
        self.assertTrue(assumed["assumed"])
        with self.assertRaises(UnsafeTarget):
            verify_source_ownership({OWNER_FILE: "wrong"}, again["token"], store)

    def test_unlabeled_source_is_assumed(self):
        result = verify_source_ownership({"app.py": "print(1)"})
        self.assertTrue(result["assumed"])
        self.assertEqual(result["labels"], [])

    def test_labeled_owner_must_match_before_a_scan(self):
        with self.assertRaises(UnsafeTarget):
            verify_source_ownership(
                {"app.py": "Copyright (c) 2024 Other Person\nprint(1)\n"},
                claimed_owner="Acme",
            )
        matched = verify_source_ownership(
            {
                "lib.py": "__author__ = 'Acme Security'\n",
                "package.json": '{"author": "Acme Security"}',
            },
            claimed_owner="Acme",
        )
        self.assertFalse(matched["assumed"])
        self.assertIn("Acme Security", matched["labels"])

    def test_gate_runs_before_agents(self):
        with self.assertRaises(UnsafeTarget):
            gate_before_agents({"kind": "url", "url": "https://example.com"})
        labeled = {
            "kind": "source",
            "files": {"app.py": "Copyright (c) 2020 Other Person\n"},
        }
        with self.assertRaises(UnsafeTarget):
            gate_before_agents(labeled, claimed_owner="Acme")
        unlabeled = {"kind": "source", "files": {"app.py": "print(1)"}}
        assumed = gate_before_agents(unlabeled)
        self.assertTrue(assumed["assumed"])
        verified = {
            "kind": "url",
            "url": "https://example.com",
            "ownership_verified": True,
        }
        self.assertFalse(gate_before_agents(verified)["assumed"])


if __name__ == "__main__":
    unittest.main()
