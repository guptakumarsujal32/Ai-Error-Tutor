"""
Test Suite for Sandbox Auto-Fix Verification and Iterative Refinement (Max 3 Attempts)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.pipeline import AIErrorTutor


class TestFixVerification(unittest.TestCase):
    """Test verification and iterative refinement of recommended code fixes."""

    def setUp(self):
        self.tutor = AIErrorTutor(use_ai=False)

    def test_clean_single_attempt_fix_verification(self):
        """Test a bug where the generated fix runs cleanly in 1 verification attempt."""
        buggy_code = "prnt('Hello World')"
        result = self.tutor.analyze_code(buggy_code)

        self.assertFalse(result.success)
        self.assertIsNotNone(result.corrected_code)
        self.assertTrue(result.fix_verified, "Recommended fix should pass sandbox verification.")
        self.assertGreaterEqual(result.fix_verification_attempts, 1)
        self.assertLessEqual(result.fix_verification_attempts, 3)

        # Ensure the corrected code actually executes cleanly
        success, exec_err = self.tutor.error_capture.execute_code(result.corrected_code)
        self.assertTrue(success, f"Corrected code still throws: {exec_err}")

    def test_uncalled_builtin_function_fix_verification(self):
        """Test that print(abs+2) produces verified executable code."""
        buggy_code = "print(abs + 2)"
        result = self.tutor.analyze_code(buggy_code)

        self.assertFalse(result.success)
        self.assertIsNotNone(result.corrected_code)
        self.assertTrue(result.fix_verified, "abs+2 fix should be verified.")
        self.assertIn("abs(", result.corrected_code)

        # Verify sandbox execution
        success, exec_err = self.tutor.error_capture.execute_code(result.corrected_code)
        self.assertTrue(success, f"Corrected code failed execution: {exec_err}")

    def test_infinite_loop_timeout_fix_verification(self):
        """Test that while True loop produces a bounded verified loop."""
        buggy_code = "while True:\n    pass"
        result = self.tutor.analyze_code(buggy_code)

        self.assertFalse(result.success)
        self.assertEqual(result.error_type, "TimeoutError")
        self.assertIsNotNone(result.corrected_code)
        self.assertTrue(result.fix_verified, "Timeout fix should pass sandbox verification without hanging.")

        success, exec_err = self.tutor.error_capture.execute_code(result.corrected_code)
        self.assertTrue(success, f"Timeout fix failed execution: {exec_err}")

    def test_iterative_refinement_max_3_attempts(self):
        """Test that iterative refinement respects the max 3 attempts limit."""
        original_code = "bad_var_xyz"
        original_error = {'error_type': 'NameError', 'message': "name 'bad_var_xyz' is not defined", 'line_number': 1}

        # Case 1: Initial candidate is deliberately invalid
        bad_initial = "still_broken_var_123"
        code, is_ver, attempts = self.tutor._verify_and_refine_fix(
            initial_code=bad_initial,
            original_code=original_code,
            original_error=original_error,
            max_attempts=3
        )

        self.assertLessEqual(attempts, 3, f"Attempts should never exceed 3, got {attempts}")

    def test_syntax_error_fix_verification(self):
        """Test missing colon syntax error produces verified code."""
        buggy_code = "def calculate_total(a, b)\n    return a + b\n\nprint(calculate_total(3, 4))"
        result = self.tutor.analyze_code(buggy_code)

        self.assertFalse(result.success)
        self.assertEqual(result.error_type, "SyntaxError")
        self.assertIsNotNone(result.corrected_code)
        self.assertTrue(result.fix_verified)

        success, exec_err = self.tutor.error_capture.execute_code(result.corrected_code)
        self.assertTrue(success, f"Syntax fix failed execution: {exec_err}")


if __name__ == '__main__':
    unittest.main()
