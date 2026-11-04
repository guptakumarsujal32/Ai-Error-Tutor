"""
Unit Tests for Security Hardening Features.

Tests the defenses implemented for:
1. Sandbox restricted builtins and guarded imports
2. Strict input character limit (DoS mitigation)
3. AST reflection attribute blocking (__subclasses__, __bases__)
4. Healed code import egress gate
5. Output buffer size caps
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.error_capture import ErrorCapture
from src.security import CodeSecurityValidator
from src.pipeline import AIErrorTutor


class TestSecurityHardening(unittest.TestCase):

    def setUp(self):
        self.capturer = ErrorCapture(timeout_seconds=2.0)
        self.validator = CodeSecurityValidator()
        self.tutor = AIErrorTutor(use_ai=False)

    def test_input_size_limit_blocked(self):
        """Code exceeding 10,000 characters is rejected immediately."""
        massive_code = "x = 1\n" + ("# filler comment line\n" * 500)
        massive_code += "x = 2"
        self.assertGreater(len(massive_code), 10000)

        success, err = self.capturer.execute_code(massive_code)
        self.assertFalse(success)
        self.assertEqual(err['error_type'], 'SecurityError')
        self.assertIn('10000', err['message'])

        # Pipeline test
        res = self.tutor.analyze_code(massive_code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, 'SecurityError')

    def test_restricted_builtins_blocked_in_sandbox(self):
        """Attempts to call restricted builtins like open() or eval() raise PermissionError."""
        code_eval = "eval('1 + 1')"
        success, err = self.capturer.execute_code(code_eval)
        self.assertFalse(success)
        self.assertIn(err['error_type'], ('SecurityError', 'PermissionError'))

    def test_ast_introspection_attributes_blocked(self):
        """Access to __subclasses__ and __bases__ is caught and blocked by AST validator."""
        code = "subclasses = ().__class__.__bases__[0].__subclasses__()"
        is_safe, warnings = self.validator.validate(code)
        self.assertFalse(is_safe)
        blocked_cats = [w.category for w in warnings if w.level == 'BLOCKED']
        self.assertTrue(any('introspection' in c or 'obfuscated' in c for c in blocked_cats))

    def test_healed_code_unauthorized_imports_blocked(self):
        """Healed code introducing unapproved imports is blocked by egress gate."""
        original_code = "x = 1\ny = x + '2'"
        malicious_fix = "import socket\nx = 1\ny = str(x) + '2'"

        is_safe = self.tutor._is_healed_code_safe_to_verify(malicious_fix, original_code)
        self.assertFalse(is_safe, "Candidate introducing unapproved import 'socket' must be blocked.")

    def test_healed_code_safe_standard_import_permitted(self):
        """Healed code introducing standard math library is permitted."""
        original_code = "area = pi * (r ** 2)"
        legitimate_fix = "import math\narea = math.pi * (r ** 2)"

        is_safe = self.tutor._is_healed_code_safe_to_verify(legitimate_fix, original_code)
        self.assertTrue(is_safe, "Candidate introducing standard math library should be permitted.")


if __name__ == '__main__':
    unittest.main()
