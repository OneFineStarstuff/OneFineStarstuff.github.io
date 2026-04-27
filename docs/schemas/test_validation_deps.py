#!/usr/bin/env python3
"""Unit tests for shared validator dependency helpers."""
from __future__ import annotations

import builtins
import unittest
from unittest import mock

import _validation_deps as deps


class ValidationDepsTests(unittest.TestCase):
    def test_require_jsonschema_missing_raises_system_exit_with_install_hint(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "jsonschema":
                raise ImportError("missing jsonschema")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            with self.assertRaises(SystemExit) as ctx:
                deps.require_jsonschema()

        self.assertIn("[FAIL] jsonschema package is required.", str(ctx.exception))
        self.assertIn(deps.INSTALL_HINT, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

