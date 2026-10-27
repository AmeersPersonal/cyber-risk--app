import unittest
from pathlib import Path

AGENTS = Path(__file__).resolve().parents[2] / "AGENTS.md"


class AgentsProjectSectionTests(unittest.TestCase):
    def setUp(self):
        self.text = AGENTS.read_text(encoding="utf-8")

    def test_project_names_the_hackathon(self):
        self.assertIn("## Project", self.text)
        self.assertIn("GenWorks Open Agent Hackathon", self.text)

    def test_inputs_are_url_or_source_code(self):
        self.assertIn("The user provides a URL or uploads source code.", self.text)

    def test_tests_run_in_a_safe_environment_against_zero_days(self):
        self.assertIn("the AI creates a safe environment and runs the tests there.", self.text)
        self.assertIn(
            "track the latest zero-day CVEs and tests the user's application against them.",
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
