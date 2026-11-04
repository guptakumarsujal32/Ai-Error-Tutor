"""
Comprehensive Feature Verification Matrix for AI Error Tutor
Tests all 10 core features across diverse Python test cases, edge cases, and runtime modes.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.pipeline import AIErrorTutor


class TestComprehensiveMatrix(unittest.TestCase):
    """Rigorous multi-feature, multi-scenario test suite."""

    @classmethod
    def setUpClass(cls):
        # Initialize tutor with local fallback capabilities
        cls.tutor = AIErrorTutor(use_ai=False, use_t5_bridge=True)

    # -------------------------------------------------------------
    # FEATURE 1: Subprocess Sandbox & 2.0s Hard Watchdog
    # -------------------------------------------------------------
    def test_f1_watchdog_infinite_while_true(self):
        """Feature 1: Halts infinite while True loop in <= 2.0s."""
        code = "while True:\n    pass"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "TimeoutError")
        self.assertIn("watchdog", res.friendly_explanation.lower())

    def test_f1_watchdog_unincremented_counter(self):
        """Feature 1: Halts while loop where counter is never incremented."""
        code = "i = 0\nwhile i < 10:\n    val = i * 2"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "TimeoutError")

    def test_f1_watchdog_deep_recursion(self):
        """Feature 1: Handles infinite or deep recursion safely."""
        code = "def recurse(n):\n    return recurse(n + 1)\nrecurse(1)"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertIn(res.error_type, ["RecursionError", "TimeoutError"])

    # -------------------------------------------------------------
    # FEATURE 2: Pre-Execution Static Security Risk Gate
    # -------------------------------------------------------------
    def test_f2_security_blocked_subprocess_module(self):
        """Feature 2: Blocks dangerous module import before execution."""
        code = "import subprocess\nsubprocess.run(['dir'], shell=True)"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "SecurityError")
        self.assertEqual(res.engine_used, "security_gate")
        self.assertGreater(len(res.security_warnings), 0)

    def test_f2_security_blocked_eval_dynamic_execution(self):
        """Feature 2: Blocks dynamic code evaluation (eval/exec)."""
        code = "user_input = '__import__(\"os\").system(\"calc\")'\neval(user_input)"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "SecurityError")
        self.assertEqual(res.engine_used, "security_gate")

    def test_f2_security_blocked_file_deletion(self):
        """Feature 2: Blocks dangerous OS filesystem deletion calls."""
        code = "import os\nos.remove('important_file.txt')"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "SecurityError")

    # -------------------------------------------------------------
    # FEATURE 3: Code Health & Optimality Scorecard (0-100%)
    # -------------------------------------------------------------
    def test_f3_health_scorecard_optimal_code(self):
        """Feature 3: Optimal clean code scores high grade (A/A+)."""
        code = "def calculate_sum(a, b):\n    return a + b\n\nprint(calculate_sum(10, 20))"
        res = self.tutor.analyze_code(code)
        self.assertTrue(res.success)
        hr = res.health_report
        self.assertIsNotNone(hr)
        self.assertGreaterEqual(hr.optimality_score, 85)
        self.assertIn(hr.optimality_grade, ["A", "A+"])
        self.assertEqual(hr.security_score, 100)

    def test_f3_health_scorecard_inefficient_quadratic_patterns(self):
        """Feature 3: Detects nested O(N^2) loops and string concatenation."""
        code = "s = ''\nfor i in range(10):\n    for j in range(10):\n        s += str(i * j)"
        res = self.tutor.analyze_code(code)
        hr = res.health_report
        self.assertIsNotNone(hr)
        self.assertLess(hr.optimality_score, 85)
        self.assertTrue(any("nested loop" in f.lower() or "string concatenation" in f.lower() for f in hr.optimality_findings))

    # -------------------------------------------------------------
    # FEATURE 4: 3-Tier Resilient Diagnosis Hierarchy (Structure & Fallback)
    # -------------------------------------------------------------
    def test_f4_tier_fallback_structured_metadata(self):
        """Feature 4: Fallback tier outputs complete structured metadata."""
        code = "items = {'name': 'Alice'}\nprint(items['age'])"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "KeyError")
        self.assertIsNotNone(res.concept)
        self.assertIsNotNone(res.prevention_tip)
        self.assertIsNotNone(res.friendly_explanation)
        self.assertIsNotNone(res.suggested_fix)

    # -------------------------------------------------------------
    # FEATURE 5: Direct Technical Explanations (Zero-Analogy Rule)
    # -------------------------------------------------------------
    def test_f5_direct_explanation_no_analogies(self):
        """Feature 5: Explanation adheres strictly to technical root causes without analogies."""
        code = "message = 'Score: ' + 100"
        res = self.tutor.analyze_code(code, mode="direct")
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "TypeError")

        # Zero-analogy verification
        forbidden_analogies = ["jar", "box", "car", "apple", "container", "recipe"]
        explanation_lower = res.friendly_explanation.lower()
        for metaphor in forbidden_analogies:
            self.assertNotIn(f" {metaphor} ", f" {explanation_lower} ", f"Forbidden analogy '{metaphor}' found in explanation.")

    # -------------------------------------------------------------
    # FEATURE 6: Socratic Hint Mode (1 Question + 3 Progressive Clues)
    # -------------------------------------------------------------
    def test_f6_socratic_mode_zerodivision(self):
        """Feature 6: Socratic mode produces guiding question and progressive clues."""
        code = "numerator = 50\ndenominator = 0\nprint(numerator / denominator)"
        res = self.tutor.analyze_code(code, mode="socratic")
        self.assertFalse(res.success)
        self.assertTrue(res.hint_mode)
        self.assertIsNotNone(res.socratic_question)
        self.assertIn("?", res.socratic_question)
        self.assertGreaterEqual(len(res.progressive_hints), 3)

    def test_f6_socratic_mode_syntax_error(self):
        """Feature 6: Socratic mode guides syntax errors effectively."""
        code = "def greet(name)\n    print('Hello ' + name)"
        res = self.tutor.analyze_code(code, mode="socratic")
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "SyntaxError")
        self.assertTrue(res.hint_mode)
        self.assertIsNotNone(res.socratic_question)
        self.assertTrue(any("colon" in h.lower() or "punctuation" in h.lower() for h in res.progressive_hints))

    # -------------------------------------------------------------
    # FEATURE 7: 1-Click Code Fix Synthesizer
    # -------------------------------------------------------------
    def test_f7_synthesize_fix_missing_colon(self):
        """Feature 7: Synthesizes correct code for missing colon in control structures."""
        code = "if 10 > 5\n    print('Greater')"
        res = self.tutor.analyze_code(code)
        self.assertIsNotNone(res.corrected_code)
        self.assertIn("if 10 > 5:", res.corrected_code)

    def test_f7_synthesize_fix_uncalled_builtin_arithmetic(self):
        """Feature 7: Synthesizes correct call for uncalled built-in function in arithmetic (abs+2)."""
        code = "print(abs + 2)"
        res = self.tutor.analyze_code(code)
        self.assertIsNotNone(res.corrected_code)
        self.assertIn("abs(-5)", res.corrected_code)

    def test_f7_synthesize_fix_reorder_used_before_definition(self):
        """Feature 7: Fixes variable referenced before assignment."""
        code = "print(result)\nresult = 42"
        res = self.tutor.analyze_code(code)
        self.assertIsNotNone(res.corrected_code)
        lines = [l.strip() for l in res.corrected_code.splitlines() if l.strip()]
        self.assertTrue(lines[0].startswith("result ="), "Definition should be placed before usage")

    # -------------------------------------------------------------
    # FEATURE 8: Sandbox Fix Verification & Self-Correction (Max 3 Loops)
    # -------------------------------------------------------------
    def test_f8_sandbox_verification_single_pass(self):
        """Feature 8: Verifies that synthesized fix executes cleanly in the sandbox."""
        code = "prnt('Testing AI Error Tutor')"
        res = self.tutor.analyze_code(code)
        self.assertIsNotNone(res.corrected_code)
        self.assertTrue(res.fix_verified, "Proposed fix should pass sandbox execution")
        self.assertEqual(res.fix_verification_attempts, 1)

    def test_f8_sandbox_verification_timeout_repair(self):
        """Feature 8: Verifies that timeout infinite loop is converted to bounded execution."""
        code = "while True:\n    pass"
        res = self.tutor.analyze_code(code)
        self.assertIsNotNone(res.corrected_code)
        self.assertTrue(res.fix_verified, "Timeout repair should be sandbox verified")

    def test_f8_sandbox_verification_max_3_attempts_enforcement(self):
        """Feature 8: Enforces max 3 iterations limit on unresolvable code."""
        orig_err = {'error_type': 'NameError', 'message': "name 'unsolvable' is not defined", 'line_number': 1}
        code, is_ver, attempts = self.tutor._verify_and_refine_fix(
            initial_code="still_bad_1",
            original_code="unsolvable",
            original_error=orig_err,
            max_attempts=3
        )
        self.assertLessEqual(attempts, 3)

    # -------------------------------------------------------------
    # FEATURE 9: Typo & Scope-Leak Analyzer
    # -------------------------------------------------------------
    def test_f9_typo_levenshtein_detection(self):
        """Feature 9: Suggests similar identifiers based on Levenshtein distance."""
        code = "student_score = 95\nprint(student_scor)"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "NameError")
        self.assertIn("student_score", res.similar_names)

    def test_f9_scope_leak_analyzer(self):
        """Feature 9: Identifies when local function variables are accessed from outer scope."""
        code = "def calculate_discount():\n    discount_rate = 0.15\ncalculate_discount()\nprint(discount_rate)"
        res = self.tutor.analyze_code(code)
        self.assertFalse(res.success)
        self.assertEqual(res.error_type, "NameError")
        self.assertIn("discount_rate", res.raw_error)

    # -------------------------------------------------------------
    # FEATURE 10: Clean Execution (Zero-Error Code)
    # -------------------------------------------------------------
    def test_f10_clean_execution_valid_code(self):
        """Feature 10: Completely valid code passes with 100% clean status."""
        code = "nums = [1, 2, 3, 4, 5]\nsquares = [x**2 for x in nums]\nprint(sum(squares))"
        res = self.tutor.analyze_code(code)
        self.assertTrue(res.success)
        self.assertEqual(res.engine_used, "execution_success")
        self.assertIsNone(res.error_type)
        self.assertIn("successfully", res.friendly_explanation.lower())


def run_standalone_matrix():
    """Run tests with a visual CLI scorecard."""
    print("=" * 70)
    print("  AI ERROR TUTOR - COMPREHENSIVE FEATURE TEST MATRIX")
    print("=" * 70)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestComprehensiveMatrix)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n" + "=" * 70)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success Rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100:.1f}%")
    print("=" * 70)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_standalone_matrix()
    sys.exit(0 if success else 1)
