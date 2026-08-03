import tempfile
import unittest
from pathlib import Path

import validate_artifact_inventory as module


class ValidateArtifactInventoryTests(unittest.TestCase):
    def test_extract_inventory_section_returns_expected_block(self):
        report = """
## 9) Prior section
- `docs/schemas/not-in-inventory.md`

## 9) Machine-Readable Governance Artifacts (linked)
- `docs/schemas/README.md`
- `Makefile`

## 11) Next section
- `docs/schemas/also-not-in-inventory.md`
"""
        extracted = module.extract_inventory_section(report)
        self.assertIn("docs/schemas/README.md", extracted)
        self.assertNotIn("also-not-in-inventory", extracted)

    def test_extract_inventory_section_supports_legacy_heading(self):
        report = """
## 10) Generated artifact inventory
- `docs/schemas/README.md`
"""
        extracted = module.extract_inventory_section(report)
        self.assertIn("docs/schemas/README.md", extracted)

    def test_collect_inventory_paths_filters_supported_entries(self):
        inventory = """
- `docs/schemas/README.md`
- `https://example.com/not-a-repo-path`
- `Makefile`
- `notes/todo.md`
- `.pre-commit-config.yaml`
"""
        self.assertEqual(
            module.collect_inventory_paths(inventory),
            ["docs/schemas/README.md", "Makefile", ".pre-commit-config.yaml"],
        )

    def test_find_duplicate_paths(self):
        duplicates = module.find_duplicate_paths(
            ["docs/a.md", "docs/b.md", "docs/a.md", "docs/a.md", "docs/c.md", "docs/b.md"]
        )
        self.assertEqual(duplicates, ["docs/a.md", "docs/b.md"])

    def test_validate_inventory_paths_returns_missing_with_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            repo_root.joinpath("docs/schemas").mkdir(parents=True)
            repo_root.joinpath("docs/schemas/exists.md").write_text("ok", encoding="utf-8")
            repo_root.joinpath("Makefile").write_text("all:\n\t@true\n", encoding="utf-8")

            missing = module.validate_inventory_paths(
                ["docs/schemas/exists.md", "Makefile", "docs/schemas/missing.md"],
                repo_root,
            )
            self.assertEqual(missing, ["docs/schemas/missing.md"])


if __name__ == "__main__":
    unittest.main()
