"""Tests for the manifests module, especially scoped npm package handling."""

import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ai.manifests import _npm_name_from_path, packages_from_files


class TestNpmNameFromPath(unittest.TestCase):
    def test_plain_package(self):
        self.assertEqual(_npm_name_from_path("node_modules/vite"), "vite")

    def test_scoped_package(self):
        self.assertEqual(
            _npm_name_from_path("node_modules/@tailwindcss/vite"),
            "@tailwindcss/vite",
        )

    def test_nested_scoped_package(self):
        self.assertEqual(
            _npm_name_from_path("node_modules/@vitejs/plugin-react"),
            "@vitejs/plugin-react",
        )

    def test_deeply_nested_node_modules(self):
        self.assertEqual(
            _npm_name_from_path("node_modules/foo/node_modules/@bar/baz"),
            "@bar/baz",
        )

    def test_no_node_modules(self):
        result = _npm_name_from_path("some/other/path")
        self.assertEqual(result, "path")

    def test_empty_after_node_modules(self):
        self.assertEqual(_npm_name_from_path("node_modules"), "")


class TestPackageLockScopedPackages(unittest.TestCase):
    def _make_lock(self, packages):
        return json.dumps({"lockfileVersion": 3, "packages": packages})

    def test_scoped_and_plain_vite_both_extracted(self):
        lock = self._make_lock({
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/@tailwindcss/vite": {"version": "4.3.3"},
            "node_modules/vite": {"version": "8.3.5"},
        })
        pkgs = packages_from_files({"package-lock.json": lock})
        by_name = {p["name"]: p for p in pkgs}
        self.assertIn("vite", by_name)
        self.assertIn("@tailwindcss/vite", by_name)
        self.assertEqual(by_name["vite"]["version"], "8.3.5")
        self.assertEqual(by_name["@tailwindcss/vite"]["version"], "4.3.3")

    def test_scoped_package_not_shadowed(self):
        lock = self._make_lock({
            "": {"name": "test", "version": "0.1.0"},
            "node_modules/@vitejs/plugin-react": {"version": "4.5.2"},
            "node_modules/vite": {"version": "8.0.0"},
        })
        pkgs = packages_from_files({"package-lock.json": lock})
        names = [p["name"] for p in pkgs]
        self.assertIn("@vitejs/plugin-react", names)
        self.assertIn("vite", names)
        self.assertEqual(len(names), len(set(names)))

    def test_meta_name_takes_precedence(self):
        lock = self._make_lock({
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/@scope/pkg": {
                "name": "@scope/pkg",
                "version": "2.0.0",
            },
        })
        pkgs = packages_from_files({"package-lock.json": lock})
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]["name"], "@scope/pkg")
        self.assertEqual(pkgs[0]["version"], "2.0.0")


if __name__ == "__main__":
    unittest.main()
