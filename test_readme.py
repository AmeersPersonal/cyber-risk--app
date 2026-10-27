import unittest
from pathlib import Path

README = Path(__file__).resolve().parent / "README.md"


class ReadmeTests(unittest.TestCase):
    def setUp(self):
        self.text = README.read_text(encoding="utf-8")

    def test_readme_names_the_hackathon_and_education(self):
        self.assertIn("GenWorks Open Agent Hackathon", self.text)
        self.assertIn("education", self.text.lower())

    def test_readme_disclaims_liability(self):
        lowered = self.text.lower()
        self.assertIn("disclaimer", lowered)
        self.assertIn("as is", lowered)
        self.assertIn("disclaim all liability", lowered)
        self.assertIn("maximum extent permitted by law", lowered)
        self.assertIn("explicit permission", lowered)


if __name__ == "__main__":
    unittest.main()
