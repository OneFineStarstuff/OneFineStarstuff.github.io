# pylint: disable=missing-docstring, no-member, import-outside-toplevel, unused-import, wrong-import-order, no-name-in-module, redefined-outer-name, protected-access, line-too-long, duplicate-code , assignment-from-none, wrong-import-position
import unittest

from nlp_module import NLPModule


class TestNLPModule(unittest.TestCase):
    def setUp(self):
        self.nlp = NLPModule()

    def test_generate_text(self):
        result = self.nlp.generate_text("Hello")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
