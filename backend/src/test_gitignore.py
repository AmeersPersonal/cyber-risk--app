import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class GitIgnoreTests(unittest.TestCase):
    def is_ignored(self, path: str) -> bool:
        result = subprocess.run(
            ["git", "check-ignore", "-q", "--", path],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def test_python_artifacts_are_ignored(self):
        self.assertTrue(self.is_ignored("__pycache__/agent.pyc"))
        self.assertTrue(self.is_ignored(".venv/Scripts/python.exe"))
        self.assertTrue(self.is_ignored("agent.egg-info/PKG-INFO"))

    def test_secrets_and_local_analysis_artifacts_are_ignored(self):
        self.assertTrue(self.is_ignored(".env"))
        self.assertTrue(self.is_ignored("secrets/api.pem"))
        self.assertTrue(self.is_ignored("secrets/api.key"))
        self.assertTrue(self.is_ignored("secrets/api.p12"))
        self.assertTrue(self.is_ignored("secrets/api.pfx"))
        self.assertTrue(self.is_ignored("credentials.json"))
        self.assertTrue(self.is_ignored("secrets.json"))
        self.assertTrue(self.is_ignored("logs/analysis.log"))
        self.assertTrue(self.is_ignored("models/threat.safetensors"))
        self.assertTrue(self.is_ignored("intel_cache/feed.json"))
        self.assertTrue(self.is_ignored("data/raw/capture.pcap"))

    def test_source_and_env_example_are_tracked(self):
        self.assertFalse(self.is_ignored("agent.py"))
        self.assertFalse(self.is_ignored(".env.example"))
        self.assertFalse(self.is_ignored("AGENTS.md"))


if __name__ == "__main__":
    unittest.main()
