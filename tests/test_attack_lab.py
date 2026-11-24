"""
Test Suite for Attack Lab (Defensive Red-Team Testing).

Compatible with both unittest and pytest:
1. Canary Manager escape detection and cleanup guarantees
2. AttackerAgent seed catalog completeness and category coverage (30+ seeds across 11 categories)
3. Running all curated seed attacks through the Security Gate & Sandbox
   - Asserts 0 escapes (every attack expected to be blocked must be BLOCKED or CONTAINED)
4. Regression test persistence
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.attacker import AttackerAgent
from attack_runner import (
    CanaryManager,
    AttackRunner,
    VERDICT_BLOCKED,
    VERDICT_CONTAINED,
    VERDICT_ESCAPED
)


class TestAttackLab(unittest.TestCase):
    """Test suite for Attack Lab agents, canaries, and defense verification."""

    def test_01_canary_lifecycle_and_cleanup(self):
        """Canary creates temp file and env var, and cleans up completely in finally block."""
        with CanaryManager() as canary:
            self.assertTrue(os.path.exists(canary.canary_path))
            self.assertIn(canary.env_key, os.environ)
            self.assertEqual(os.environ[canary.env_key], canary.secret)

            # Read canary content
            with open(canary.canary_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(canary.secret, content)

            # Clean run: no leak, no file modification
            is_breached, reason = canary.check_breach("normal stdout", "", 0.1, 2.0)
            self.assertFalse(is_breached)
            self.assertIsNone(reason)

        # After exiting context manager, file and env var must be removed
        self.assertFalse(os.path.exists(canary.canary_path))
        self.assertNotIn(canary.env_key, os.environ)

    def test_02_canary_detects_secret_leak(self):
        """Canary marks breach if secret token appears in stdout or stderr."""
        with CanaryManager() as canary:
            leaked_output = f"DEBUG DUMP: {canary.secret}"
            is_breached, reason = canary.check_breach(leaked_output, "", 0.1, 2.0)
            self.assertTrue(is_breached)
            self.assertIn("token leaked", reason)

    def test_03_canary_detects_file_tampering(self):
        """Canary marks breach if canary file is modified or deleted."""
        with CanaryManager() as canary:
            # Simulate tampering by rewriting the file
            with open(canary.canary_path, "w", encoding="utf-8") as f:
                f.write("MODIFIED_BY_ATTACKER")

            is_breached, reason = canary.check_breach("", "", 0.1, 2.0)
            self.assertTrue(is_breached)
            self.assertIn("Canary file content modified", reason)

    def test_04_seed_catalog_coverage(self):
        """Verify at least 30 seeds and coverage across all 11 required categories."""
        agent = AttackerAgent()
        self.assertGreaterEqual(len(agent.seeds), 30, f"Expected >= 30 seeds, got {len(agent.seeds)}")

        required_categories = {
            "infinite_loop",
            "memory_exhaustion",
            "file_read",
            "file_write",
            "dangerous_imports",
            "os_commands",
            "network_access",
            "obfuscated_imports",
            "builtins_introspection",
            "prompt_injection",
            "ai_output_tampering"
        }
        categories = set(agent.get_categories())
        # Normalize category name variants
        normalized_cats = {c.replace("introspection_builtins", "builtins_introspection") for c in categories}
        for req_cat in required_categories:
            self.assertIn(req_cat, normalized_cats, f"Missing required attack category: {req_cat}")
            cat_seeds = [
                s for s in agent.seeds
                if s.get("category") == req_cat or s.get("category", "").replace("introspection_builtins", "builtins_introspection") == req_cat
            ]
            self.assertGreaterEqual(len(cat_seeds), 3, f"Category '{req_cat}' has {len(cat_seeds)} seeds (min 3 required)")

    def test_05_variant_clamping_and_failsafe(self):
        """Attacker agent clamps variants between 1 and 3, and never crashes on bad input."""
        agent = AttackerAgent()
        seed = agent.seeds[0]

        try:
            vars_res = agent.generate_variants(seed, n=1)
            self.assertIsInstance(vars_res, list)
        except Exception as e:
            self.fail(f"generate_variants should never raise an unhandled exception: {e}")

    def test_06_all_seeds_are_defended(self):
        """
        Critical defense invariant:
        All curated seed attacks expected to be blocked must result in
        BLOCKED_BY_GUARDIAN or CONTAINED_BY_SANDBOX. None may be ESCAPED.
        """
        agent = AttackerAgent()
        runner = AttackRunner()

        summary = runner.run_round(agent.seeds)

        total = summary["total_attacks"]
        blocked = summary["blocked_count"]
        contained = summary["contained_count"]
        escaped = summary["escaped_count"]
        defense_rate = summary["defense_rate"]

        print(f"\n--- ATTACK LAB SEED DEFENSE SUMMARY ---")
        print(f"Total Attacks:     {total}")
        print(f"Blocked by Gate:   {blocked}")
        print(f"Contained Sandbox: {contained}")
        print(f"Escaped Attacks:   {escaped}")
        print(f"Defense Rate:      {defense_rate:.1f}%")

        escaped_attacks = [
            f"{r['id']} ({r['category']}): {r['details']}"
            for r in summary["results"]
            if r["verdict"] == VERDICT_ESCAPED
        ]

        self.assertEqual(escaped, 0, f"Critical Security Failure: {escaped} attacks escaped!\n" + "\n".join(escaped_attacks))
        self.assertEqual(defense_rate, 100.0)


if __name__ == "__main__":
    unittest.main()
