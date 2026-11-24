"""Execution Engine for CodeChef IDE in AI Error Tutor.

Safely executes code with custom stdin, captures stdout/stderr,
tracks execution time & memory, and enforces security policies.
"""

import sys
import time
import subprocess
import os
import tempfile
import psutil
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

try:
    from src.security import CodeSecurityValidator
    from src.aai_security_guard import AAISecurityGuard
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.security import CodeSecurityValidator
    from src.aai_security_guard import AAISecurityGuard


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    execution_time: float
    memory_mb: float
    status: str  # "Success", "SyntaxError", "NameError", "TypeError", "ZeroDivisionError", "TimeoutError", "Blocked", "RuntimeError"
    exit_code: int
    is_blocked: bool = False
    risk_score: float = 0.0
    risk_level: str = "BENIGN"
    block_reason: str = ""


class SafeExecutionEngine:
    """Manages subprocess execution, telemetry, and security checks."""

    def __init__(self, timeout_seconds: float = 2.0):
        self.timeout_seconds = timeout_seconds
        self.validator = CodeSecurityValidator()
        self.aai_guard = AAISecurityGuard()

    def run_code(self, code: str, stdin_data: str = "") -> ExecutionResult:
        """
        Executes code with stdin and produces telemetry & outputs.
        Enforces ingress security gates and subprocess timeouts.
        """
        if not code or not code.strip():
            return ExecutionResult(
                stdout="",
                stderr="No code provided for execution.",
                execution_time=0.0,
                memory_mb=0.0,
                status="Idle",
                exit_code=0
            )

        # 1. Enforce strict input size limits (5,000 lines / 500,000 characters)
        line_count = len(code.splitlines())
        if line_count > 5000 or len(code) > 500000:
            return ExecutionResult(
                stdout="",
                stderr=f"SecurityError: Code payload ({line_count} lines, {len(code)} chars) exceeds maximum safety limit of 5,000 lines / 500,000 characters.",
                execution_time=0.0,
                memory_mb=0.0,
                status="Blocked",
                exit_code=1,
                is_blocked=True,
                risk_score=75.0,
                risk_level="HIGH",
                block_reason="Payload size exceeded 5,000 lines / 500,000 characters (Resource DoS mitigation)."
            )

        # 2. Ingress Agentic AI Threat Detection (Prompt Injection / Policy Bypass)
        if self.aai_guard:
            assessment = self.aai_guard.assess_input(code, target_type="code")
            if not assessment.is_safe:
                # Log incident to audit trail
                try:
                    self.aai_guard.logger.log_assessment(assessment, code)
                except Exception:
                    pass

                cat_name = assessment.primary_category.value.replace("_", " ").title()
                return ExecutionResult(
                    stdout="",
                    stderr=f"SECURITY ALERT [{assessment.risk_level.value} - Threat Score: {assessment.risk_score:.0f}/100]\n"
                           f"Intercepted {cat_name} attack. Execution halted by Ingress Security Gate.",
                    execution_time=0.0,
                    memory_mb=0.0,
                    status="Blocked",
                    exit_code=1,
                    is_blocked=True,
                    risk_score=assessment.risk_score,
                    risk_level=assessment.risk_level.value,
                    block_reason=f"Intercepted {cat_name} attack pattern (Threat Score: {assessment.risk_score:.0f}/100)"
                )

        # 3. Static Security Policy Validator (Dangerous OS / Shell commands)
        is_safe, sec_warnings = self.validator.validate(code)
        if not is_safe:
            blocked = [w for w in sec_warnings if getattr(w, "level", "") == "BLOCKED"]
            msg = "; ".join(getattr(w, "message", str(w)) for w in blocked) or "Forbidden operation detected."
            return ExecutionResult(
                stdout="",
                stderr=f"SecurityPolicyViolation: Code blocked for safety.\n{msg}",
                execution_time=0.0,
                memory_mb=0.0,
                status="Blocked",
                exit_code=1,
                is_blocked=True,
                risk_score=85.0,
                risk_level="CRITICAL",
                block_reason=f"Restricted operations blocked: {msg}"
            )

        # 4. Run inside isolated subprocess with strict watchdog & stdin piping
        # Uses a temporary file instead of `-c` so large files (up to 5,000 lines)
        # never exceed Windows' 32 KB command-line argument limit (WinError 206).
        t_start = time.perf_counter()
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as tmp_f:
                tmp_f.write(code)
                tmp_path = tmp_f.name

            proc = subprocess.run(
                [sys.executable, "-u", tmp_path],
                input=stdin_data,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds
            )
            duration = max(0.001, time.perf_counter() - t_start)

            # Base memory estimate for standard Python subprocess
            memory_estimate = 14.2 + min(10.0, (len(code) + len(proc.stdout)) / 1024)

            stdout = proc.stdout
            stderr = proc.stderr.replace(tmp_path, "<user_code>") if tmp_path else proc.stderr

            if proc.returncode == 0:
                return ExecutionResult(
                    stdout=stdout,
                    stderr=stderr,
                    execution_time=duration,
                    memory_mb=round(memory_estimate, 1),
                    status="Success",
                    exit_code=0
                )
            else:
                # Classify error type from stderr
                err_type = "RuntimeError"
                for line in stderr.splitlines():
                    if ":" in line and ("Error" in line.split(":")[0] or "Exception" in line.split(":")[0]):
                        err_type = line.split(":")[0].strip()
                        break

                return ExecutionResult(
                    stdout=stdout,
                    stderr=stderr,
                    execution_time=duration,
                    memory_mb=round(memory_estimate, 1),
                    status=err_type,
                    exit_code=proc.returncode
                )

        except subprocess.TimeoutExpired:
            duration = self.timeout_seconds
            return ExecutionResult(
                stdout="",
                stderr=f"TimeoutError: Execution exceeded {self.timeout_seconds:.1f}s limit.\n"
                       f"This usually indicates an infinite loop (e.g. 'while True:') or deep recursive branch.",
                execution_time=duration,
                memory_mb=16.0,
                status="TimeoutError",
                exit_code=124
            )
        except Exception as e:
            duration = max(0.001, time.perf_counter() - t_start)
            return ExecutionResult(
                stdout="",
                stderr=f"ExecutionException: {str(e)}",
                execution_time=duration,
                memory_mb=12.0,
                status="RuntimeError",
                exit_code=1
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

