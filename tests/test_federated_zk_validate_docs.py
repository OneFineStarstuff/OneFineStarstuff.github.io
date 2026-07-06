from pathlib import Path
import importlib.util
import tempfile
import unittest


def load_module():
    mod_path = Path("docs/federated-zk-compliance/validate_docs.py")
    spec = importlib.util.spec_from_file_location("validate_docs", mod_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class FederatedZkValidateDocsTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_is_external_variants(self):
        self.assertTrue(self.module.is_external("https://example.com"))
        self.assertTrue(self.module.is_external("http://example.com"))
        self.assertTrue(self.module.is_external("mailto:test@example.com"))
        self.assertFalse(self.module.is_external("#section"))
        self.assertFalse(self.module.is_external("README.md"))

    def test_resolve_target_relative_path(self):
        source = Path("docs/federated-zk-compliance/README.md").resolve()
        target = self.module.resolve_target(source, "_index.md")
        self.assertEqual(target.name, "_index.md")
        self.assertTrue(target.exists())

    def test_slugify_and_anchor_extraction(self):
        p = Path("docs/federated-zk-compliance/_index.md")
        anchors = self.module.extract_anchors(p)
        self.assertIn("quick-navigation", anchors)
        self.assertEqual(
            self.module.slugify("01 — Layered Architecture and Formal Model"),
            "01-layered-architecture-and-formal-model",
        )

    def test_validate_fails_on_missing_anchor(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a.md"
            b = root / "b.md"
            a.write_text("# Doc A\n\n[Broken](b.md#nope)\n", encoding="utf-8")
            b.write_text("# Target\n", encoding="utf-8")

            checked, error_count, errors = self.module.validate([a])
            self.assertEqual(checked, 1)
            self.assertEqual(error_count, 1)
            self.assertIn("missing anchor", errors[0])

    def test_validate_passes_for_valid_local_links(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a.md"
            b = root / "b.md"
            a.write_text("# Doc A\n\n[Good](b.md#target)\n", encoding="utf-8")
            b.write_text("# Target\n", encoding="utf-8")

            checked, error_count, errors = self.module.validate([a, b])
            self.assertEqual(checked, 1)
            self.assertEqual(error_count, 0)
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
