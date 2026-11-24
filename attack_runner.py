"""Defensive Red-Team Attack Runner and Canary Verification System.

Tests the Security Gate and Subprocess Sandbox against attack payloads.
Tracks and classifies verdicts:
  - BLOCKED_BY_GUARDIAN: Quarantined by the Ingress Gate before execution
  - CONTAINED_BY_SANDBOX: Caught/stopped inside sandbox without host breach
  - ESCAPED: Canary compromised or limits bypassed (triggers regression test save)
"""

import os
import sys
import time
import json
import uuid
import tempfile
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import config
from src.security import CodeSecurityValidator
from src.aai_security_guard import AAISecurityGuard
from ui.execution_engine import SafeExecutionEngine, ExecutionResult

logger = logging.getLogger("AttackRunner")

# Verdict Constants
VERDICT_BLOCKED = "BLOCKED_BY_GUARDIAN"
VERDICT_CONTAINED = "CONTAINED_BY_SANDBOX"
VERDICT_ESCAPED = "ESCAPED"


class CanaryManager:
    """Manages ephemeral canary files and environment variables to detect real escapes."""

    def __init__(self):
        self.secret_token: str = f"CANARY_SECRET_{uuid.uuid4().hex}"
        self.env_key: str = f"CANARY_ENV_{uuid.uuid4().hex[:8]}"
        self.canary_dir = tempfile.gettempdir()
        self.canary_path = os.path.join(self.canary_dir, f"canary_{uuid.uuid4().hex[:8]}.txt")
        self.initial_content = f"CONFIDENTIAL_HOST_CANARY:{self.secret_token}"
        self.created = False

    @property
    def secret(self) -> str:
        """Alias for secret_token."""
        return self.secret_token

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def setup(self):
        """Create canary file outside the sandbox and set canary env variable."""
        try:
            with open(self.canary_path, "w", encoding="utf-8") as f:
                f.write(self.initial_content)
            os.environ[self.env_key] = self.secret_token
            self.created = True
        except Exception as e:
            logger.warning(f"Could not initialize canary: {e}")

    def check_breach(self, stdout: str, stderr: str, duration: float, timeout_limit: float = 2.0) -> Tuple[bool, Optional[str]]:
        """
        Check if the canary was compromised by the execution.
        Returns (is_escaped, breach_reason).
        """
        combined_output = f"{stdout}\n{stderr}"

        # 1. Secret token leaked into process output
        if self.secret_token in combined_output:
            return True, f"Canary token leaked into output: '{self.secret_token}' detected."

        # 2. Canary file modified or deleted
        if not os.path.exists(self.canary_path):
            return True, f"Canary file was deleted by attack: {self.canary_path}"

        try:
            with open(self.canary_path, "r", encoding="utf-8") as f:
                current_content = f.read()
            if current_content != self.initial_content:
                return True, f"Canary file content modified from '{self.initial_content}' to '{current_content}'."
        except Exception as e:
            return True, f"Canary file could not be read after execution: {e}"

        # 3. Uncontrolled timeout evasion (exceeded watchdog significantly)
        if duration > (timeout_limit + 1.5):
            return True, f"Execution exceeded maximum timeout watchdog ({duration:.2f}s > {timeout_limit}s)."

        return False, None

    def cleanup(self):
        """Clean up canary file and environment variable."""
        try:
            if self.env_key in os.environ:
                del os.environ[self.env_key]
        except Exception:
            pass

        try:
            if os.path.exists(self.canary_path):
                os.remove(self.canary_path)
        except Exception:
            pass
        self.created = False


class AttackRunner:
    """Orchestrates security testing runs and records verdicts."""

    def __init__(self, log_dir: Optional[str] = None, regressions_dir: Optional[str] = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_dir = log_dir or os.path.join(base_dir, "logs")
        self.log_path = os.path.join(self.log_dir, "attack_log.json")

        self.regressions_dir = regressions_dir or os.path.join(base_dir, "tests", "attacks")
        self.regressions_path = os.path.join(self.regressions_dir, "escaped_attacks.json")

        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.regressions_dir, exist_ok=True)

        self.validator = CodeSecurityValidator()
        self.aai_guard = AAISecurityGuard()
        self.exec_engine = SafeExecutionEngine(timeout_seconds=2.0)

    def run_single_attack(self, attack: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a single attack through the standard security pipeline and evaluate result.

        Args:
            attack: Dictionary with 'id', 'category', 'code', etc.

        Returns:
            Dictionary with execution details, verdict, risk score, and timing.
        """
        code = attack.get("code", "")
        attack_id = attack.get("id", "UNKNOWN")
        category = attack.get("category", "general")
        t_start = time.perf_counter()

        # Step 1: Ingress Security Gate Check (Prompt injection & dangerous imports)
        ingress_assessment = self.aai_guard.assess_input(code, target_type="code")
        is_safe_ast, ast_warnings = self.validator.validate(code)

        blocked_reasons: List[str] = []
        if not ingress_assessment.is_safe:
            blocked_reasons.append(
                f"AAI Gate [{ingress_assessment.risk_level.value}]: {ingress_assessment.primary_category.value}"
            )
        if not is_safe_ast:
            for w in ast_warnings:
                if getattr(w, "level", "") == "BLOCKED":
                    blocked_reasons.append(f"AST Gate: {getattr(w, 'message', str(w))}")

        if blocked_reasons:
            duration = max(0.001, time.perf_counter() - t_start)
            risk_score = max(ingress_assessment.risk_score, 85.0 if not is_safe_ast else 0.0)
            result = {
                "id": attack_id,
                "category": category,
                "title": attack.get("title", attack_id),
                "code": code,
                "verdict": VERDICT_BLOCKED,
                "risk_score": round(risk_score, 1),
                "time_taken": round(duration, 3),
                "timestamp": datetime.now().isoformat(),
                "details": "; ".join(blocked_reasons),
                "suggested_fix": None
            }
            self._save_log_entry(result)
            return result

        # Step 2: Passed Security Gate -> Send to Execution Sandbox under Active Canary Watch
        with CanaryManager() as canary:
            t_exec_start = time.perf_counter()
            exec_res: ExecutionResult = self.exec_engine.run_code(code, stdin_data="")
            exec_duration = time.perf_counter() - t_exec_start
            total_duration = time.perf_counter() - t_start

            is_escaped, breach_reason = canary.check_breach(
                stdout=exec_res.stdout,
                stderr=exec_res.stderr,
                duration=exec_duration,
                timeout_limit=2.0
            )

        if is_escaped:
            suggested_fix = (
                f"RECOMMENDED REMEDIATION: Attack '{attack_id}' bypassed defenses ({breach_reason}). "
                f"Add AST validation rules in src/security.py for pattern: '{code.splitlines()[0] if code else ''}' "
                "or strengthen sandbox restricted builtins."
            )
            result = {
                "id": attack_id,
                "category": category,
                "title": attack.get("title", attack_id),
                "code": code,
                "verdict": VERDICT_ESCAPED,
                "risk_score": 100.0,
                "time_taken": round(total_duration, 3),
                "timestamp": datetime.now().isoformat(),
                "details": f"ESCAPE DETECTED: {breach_reason}",
                "suggested_fix": suggested_fix
            }
            self._save_regression_attack(attack, result)
        else:
            # Contained inside sandbox (watchdog timeout, PermissionError, or normal runtime exception)
            status_desc = exec_res.status
            if exec_res.stderr:
                first_err_line = exec_res.stderr.strip().splitlines()[-1]
                status_desc = f"{status_desc} ({first_err_line})"
            result = {
                "id": attack_id,
                "category": category,
                "title": attack.get("title", attack_id),
                "code": code,
                "verdict": VERDICT_CONTAINED,
                "risk_score": round(ingress_assessment.risk_score, 1),
                "time_taken": round(total_duration, 3),
                "timestamp": datetime.now().isoformat(),
                "details": f"Sandbox Contained: {status_desc}",
                "suggested_fix": None
            }

        self._save_log_entry(result)
        return result

    def run_round(self, attacks: List[Dict[str, Any]], progress_callback=None) -> Dict[str, Any]:
        """
        Run a batch of attacks and compute round statistics.
        """
        results: List[Dict[str, Any]] = []
        total = len(attacks)
        blocked_count = 0
        contained_count = 0
        escaped_count = 0
        category_stats: Dict[str, Dict[str, int]] = {}

        for i, atk in enumerate(attacks):
            res = self.run_single_attack(atk)
            results.append(res)

            v = res["verdict"]
            cat = res["category"]
            if cat not in category_stats:
                category_stats[cat] = {"total": 0, "blocked": 0, "contained": 0, "escaped": 0}
            category_stats[cat]["total"] += 1

            if v == VERDICT_BLOCKED:
                blocked_count += 1
                category_stats[cat]["blocked"] += 1
            elif v == VERDICT_CONTAINED:
                contained_count += 1
                category_stats[cat]["contained"] += 1
            elif v == VERDICT_ESCAPED:
                escaped_count += 1
                category_stats[cat]["escaped"] += 1

            if progress_callback:
                progress_callback(i + 1, total, res)

        # Compute category defense rates
        category_summary = {}
        for cat, stats in category_stats.items():
            defended = stats["blocked"] + stats["contained"]
            rate = (defended / stats["total"] * 100) if stats["total"] > 0 else 100.0
            category_summary[cat] = {
                **stats,
                "defense_rate": round(rate, 1)
            }

        # Identify weakest categories
        weakest = sorted(
            category_summary.items(),
            key=lambda x: (x[1]["escaped"], -x[1]["defense_rate"], -x[1]["total"]),
            reverse=True
        )

        return {
            "total_attacks": total,
            "blocked_count": blocked_count,
            "contained_count": contained_count,
            "escaped_count": escaped_count,
            "defense_rate": round(((blocked_count + contained_count) / total * 100) if total > 0 else 100.0, 1),
            "category_summary": category_summary,
            "weakest_categories": [w[0] for w in weakest if w[1]["escaped"] > 0 or w[1]["defense_rate"] < 100],
            "results": results
        }

    def load_regression_attacks(self) -> List[Dict[str, Any]]:
        """Load previously escaped regression test attacks."""
        if not os.path.exists(self.regressions_path):
            return []
        try:
            with open(self.regressions_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_log_entry(self, entry: Dict[str, Any]):
        """Append result entry to logs/attack_log.json."""
        entries = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    entries = json.load(f)
                    if not isinstance(entries, list):
                        entries = []
            except Exception:
                entries = []

        entries.append(entry)
        try:
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(entries[-500:], f, indent=2)  # Keep last 500 logs
        except Exception as e:
            logger.warning(f"Could not write attack log: {e}")

    def _save_regression_attack(self, attack: Dict[str, Any], result: Dict[str, Any]):
        """Persist an escaped attack as a permanent regression test."""
        regressions = self.load_regression_attacks()
        existing_ids = {r.get("id") for r in regressions}
        if attack.get("id") not in existing_ids:
            regressions.append({
                "id": attack.get("id"),
                "category": attack.get("category"),
                "code": attack.get("code"),
                "title": attack.get("title"),
                "escaped_at": result.get("timestamp"),
                "details": result.get("details"),
                "suggested_fix": result.get("suggested_fix")
            })
            try:
                with open(self.regressions_path, "w", encoding="utf-8") as f:
                    json.dump(regressions, f, indent=2)
            except Exception as e:
                logger.warning(f"Could not save regression attack: {e}")
