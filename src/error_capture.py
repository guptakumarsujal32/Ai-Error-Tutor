import sys
import json
import traceback
import subprocess
from typing import Dict, Optional, Tuple
from io import StringIO

try:
    from .security import CodeSecurityValidator, SecurityWarning
except ImportError:
    from security import CodeSecurityValidator, SecurityWarning


class ErrorCapture:

    def __init__(self, timeout_seconds: float = 2.0):
        self.last_error: Optional[Dict] = None
        self.security_validator = CodeSecurityValidator()
        self.timeout_seconds = timeout_seconds

    def execute_code(self, code: str, stdin_data: str = "") -> Tuple[bool, Optional[Dict]]:
        """
        Execute Python code inside an isolated subprocess and capture any errors.

        First validates code for security risks. If dangerous patterns
        are found (BLOCKED level), the code is NOT executed.

        Enforces a strict timeout (default 2.0s) to prevent infinite loops
        (e.g., `while True: pass`) or CPU resource exhaustion from freezing the server.

        Args:
            code: Python code string to execute

        Returns:
            Tuple of (success: bool, error_info: dict or None)
        """
        # Step -0.5: Enforce strict input size limits (5,000 lines / 500,000 chars)
        MAX_INPUT_LINES = 5000
        MAX_INPUT_LENGTH = 500000
        line_count = len(code.splitlines())
        if line_count > MAX_INPUT_LINES or len(code) > MAX_INPUT_LENGTH:
            error_info = {
                'error_type': 'SecurityError',
                'message': f"Code blocked: Input size ({line_count} lines, {len(code)} chars) exceeds maximum safety limit ({MAX_INPUT_LINES} lines / {MAX_INPUT_LENGTH} chars).",
                'line_number': 1,
                'offset': None,
                'code_context': code[:120],
                'raw_traceback': 'SecurityError: Payload too large for learning sandbox.',
                'full_code': code,
                'security_warnings': [
                    SecurityWarning(
                        level='BLOCKED',
                        category='resource_dos',
                        message=f"Input exceeds {MAX_INPUT_LINES} lines / {MAX_INPUT_LENGTH} character limit.",
                        line_number=1,
                        code_snippet=code[:60]
                    )
                ]
            }
            self.last_error = error_info
            return False, error_info

        # Step 0: Security validation BEFORE execution
        is_safe, warnings = self.security_validator.validate(code)

        # Step 0.5: Bandit scans the source before it can reach execution
        if is_safe:
            try:
                bandit_safe, bandit_warnings = self.security_validator.scan_with_bandit(code)
                warnings.extend(bandit_warnings)
                is_safe = bandit_safe
            except RuntimeError as error:
                warnings.append(SecurityWarning(
                    level='BLOCKED',
                    category='bandit_scan_failure',
                    message=str(error),
                    line_number=1,
                    code_snippet=code.splitlines()[0].strip() if code.splitlines() else '',
                ))
                is_safe = False

        if not is_safe:
            # Code contains blocked patterns — do NOT execute
            blocked = [w for w in warnings if w.level == 'BLOCKED']
            warning_messages = '; '.join(w.message for w in blocked)

            error_info = {
                'error_type': 'SecurityError',
                'message': f"Code blocked for safety: {warning_messages}",
                'line_number': blocked[0].line_number if blocked else None,
                'offset': None,
                'code_context': blocked[0].code_snippet if blocked else code,
                'raw_traceback': self.security_validator.format_warnings(),
                'full_code': code,
                'security_warnings': warnings
            }

            self.last_error = error_info
            return False, error_info

        # Step 1: Execute in isolated subprocess with strict timeout & restricted environment
        runner_script = """
import sys
import json
import traceback
from io import StringIO

# Cap recursion depth to prevent native C-stack exhaustion / segmentation faults
sys.setrecursionlimit(500)

payload_raw = sys.stdin.read(750000)
try:
    _payload = json.loads(payload_raw)
    code = _payload.get('code', '')
    user_stdin = _payload.get('stdin', '')
except Exception:
    code = payload_raw
    user_stdin = ""

old_stdin = sys.stdin
sys.stdin = StringIO(user_stdin)
old_stdout = sys.stdout
old_stderr = sys.stderr
sys.stdout = StringIO()
sys.stderr = StringIO()

# Prepare restricted builtins dictionary
raw_builtins = __builtins__
if hasattr(raw_builtins, '__dict__'):
    safe_builtins = dict(raw_builtins.__dict__)
else:
    safe_builtins = dict(raw_builtins)

BLOCKED_BUILTIN_NAMES = {
    'open', 'eval', 'exec', 'compile', 'breakpoint',
    'exit', 'quit'
}

def _make_blocked_builtin(name):
    def _blocked(*args, **kwargs):
        raise PermissionError(f"Access to restricted builtin '{name}()' is blocked in the learning sandbox.")
    return _blocked

for b_name in BLOCKED_BUILTIN_NAMES:
    if b_name in safe_builtins:
        safe_builtins[b_name] = _make_blocked_builtin(b_name)

# Guard dynamic imports against blocked modules
orig_import = safe_builtins.get('__import__')
RESTRICTED_MODULES = {
    'subprocess', 'commands', 'ctypes', 'multiprocessing',
    'socket', 'http', 'urllib', 'requests', 'ftplib',
    'xmlrpc', 'smtplib', 'poplib', 'imaplib',
    'importlib', 'code', 'codeop', 'signal', 'resource',
    'shutil', 'os', 'sys', 'pathlib'
}

def _guarded_import(name, *args, **kwargs):
    root = name.split('.')[0]
    if root in RESTRICTED_MODULES:
        raise PermissionError(f"Import of '{name}' is restricted in the learning sandbox.")
    if orig_import:
        return orig_import(name, *args, **kwargs)
    raise ImportError(f"Import mechanism unavailable for: {name}")

safe_builtins['__import__'] = _guarded_import

result = {}
try:
    compiled = compile(code, '<user_code>', 'exec')
    namespace = {'__builtins__': safe_builtins}
    exec(compiled, namespace, namespace)
    result = {'success': True}
except SyntaxError as e:
    result = {
        'success': False,
        'error_type': 'SyntaxError',
        'message': str(e.msg) if e.msg else str(e),
        'line_number': e.lineno,
        'offset': e.offset,
        'raw_traceback': f"SyntaxError: {e.msg} (line {e.lineno})"
    }
except BaseException as e:
    tb = traceback.extract_tb(e.__traceback__)
    user_tb = [frame for frame in tb if frame.filename == '<user_code>']
    line_number = user_tb[-1].lineno if user_tb else (tb[-1].lineno if tb else None)
    result = {
        'success': False,
        'error_type': type(e).__name__,
        'message': str(e),
        'line_number': line_number,
        'offset': None,
        'raw_traceback': ''.join(traceback.format_exception(type(e), e, e.__traceback__))
    }
finally:
    sys.stdout = old_stdout
    sys.stderr = old_stderr

# Protect against JSON buffer overflow
out_str = json.dumps(result)
if len(out_str) > 50000:
    out_str = json.dumps({
        'success': False,
        'error_type': 'OutputLimitExceeded',
        'message': 'Sandbox output exceeded buffer safety limit (50KB).',
        'line_number': None,
        'offset': None,
        'raw_traceback': 'OutputLimitExceeded: Sandbox output truncated.'
    })

sys.stdout.write(out_str)
"""

        payload = json.dumps({'code': code, 'stdin': stdin_data or ""})
        has_heavy_import = any(
            pkg in code for pkg in ("import pandas", "from pandas", "import numpy", "from numpy", "import scipy", "import matplotlib", "import sklearn")
        )
        exec_timeout = max(self.timeout_seconds, 6.0) if has_heavy_import else self.timeout_seconds
        try:
            proc = subprocess.run(
                [sys.executable, "-c", runner_script],
                input=payload,
                text=True,
                capture_output=True,
                timeout=exec_timeout
            )

            if proc.stdout.strip():
                sub_res = json.loads(proc.stdout.strip())
                if sub_res.get('success'):
                    success = True
                    error_info = None
                else:
                    success = False
                    line_num = sub_res.get('line_number')
                    error_info = {
                        'error_type': sub_res.get('error_type'),
                        'message': sub_res.get('message'),
                        'line_number': line_num,
                        'offset': sub_res.get('offset'),
                        'code_context': self._get_context_lines(code, line_num) if line_num else code,
                        'raw_traceback': sub_res.get('raw_traceback', ''),
                        'full_code': code
                    }
            else:
                # Process produced non-JSON stderr / crash
                success = False
                error_info = {
                    'error_type': 'RuntimeError',
                    'message': proc.stderr.strip() or "Process terminated unexpectedly.",
                    'line_number': None,
                    'offset': None,
                    'code_context': code,
                    'raw_traceback': proc.stderr.strip(),
                    'full_code': code
                }

        except subprocess.TimeoutExpired:
            success = False
            error_info = {
                'error_type': 'TimeoutError',
                'message': f"Execution timed out after {self.timeout_seconds}s limit. This is often caused by an infinite loop (e.g. 'while True:') or deep recursion.",
                'line_number': None,
                'offset': None,
                'code_context': code,
                'raw_traceback': f"TimeoutError: Execution exceeded {self.timeout_seconds}s sandbox wall-clock limit.",
                'full_code': code
            }
        except Exception as e:
            # Fallback to in-process execution if subprocess invocation fails
            success = False
            error_info = {
                'error_type': 'ExecutionError',
                'message': str(e),
                'line_number': None,
                'offset': None,
                'code_context': code,
                'raw_traceback': traceback.format_exc(),
                'full_code': code
            }

        # Attach any security warnings (WARNING level) to the result
        if warnings:
            if error_info is None:
                # Code ran successfully but has warnings — create a minimal
                # info dict with ONLY security_warnings to avoid missing-key
                # issues if anyone accesses error_info fields downstream
                error_info = {
                    'error_type': None,
                    'message': None,
                    'line_number': None,
                    'offset': None,
                    'code_context': None,
                    'raw_traceback': None,
                    'full_code': code,
                    'security_warnings': warnings
                }
            else:
                error_info['security_warnings'] = warnings

        self.last_error = error_info
        return success, error_info

    def execute_resilient(
        self,
        code: str,
        stdin_data: str = "",
        total_timeout: Optional[float] = None,
        per_stmt_timeout: Optional[float] = None,
    ) -> Dict:
        """
        Pass 2 Resilient Dynamic Execution inside the isolated subprocess sandbox.

        Transforms the module with AST so each top-level statement executes in its
        own try/except block sharing a single namespace, collecting ALL runtime
        exceptions in one run while detecting cascade errors and enforcing both
        total and per-statement timeouts.
        """
        import config as _cfg
        total_t = float(total_timeout if total_timeout is not None else getattr(_cfg, "TOTAL_SANDBOX_TIMEOUT", self.timeout_seconds))
        stmt_t = float(per_stmt_timeout if per_stmt_timeout is not None else getattr(_cfg, "PER_STATEMENT_TIMEOUT", 0.6))

        # Size limits (5,000 lines / 500,000 chars)
        line_count = len(code.splitlines())
        if line_count > 5000 or len(code) > 500000:
            return {
                "blocked": True,
                "status": "Blocked",
                "block_reason": f"Input size ({line_count} lines, {len(code)} chars) exceeds 5,000 lines / 500,000 chars.",
                "stdout": "",
                "stderr": "",
                "issues": [],
            }

        # Security Gate validation BEFORE execution
        is_safe, warnings = self.security_validator.validate(code)
        if not is_safe:
            blocked_msgs = [w.message for w in warnings if w.level == "BLOCKED"]
            return {
                "blocked": True,
                "status": "Blocked",
                "block_reason": "; ".join(blocked_msgs) or "Security policy violation.",
                "stdout": "",
                "stderr": "",
                "issues": [],
                "security_warnings": warnings,
            }

        resilient_runner = r"""
import sys
import ast
import re
import json
import time
import traceback
from io import StringIO

sys.setrecursionlimit(500)

payload_raw = sys.stdin.read(750000)
_payload = json.loads(payload_raw)
code = _payload.get('code', '')
user_stdin = _payload.get('stdin', '')
total_timeout = float(_payload.get('total_timeout', 2.0))
per_stmt_timeout = float(_payload.get('per_stmt_timeout', 0.6))
code_lines = code.splitlines()

old_stdin = sys.stdin
old_stdout = sys.stdout
old_stderr = sys.stderr
buf_out = StringIO()
buf_err = StringIO()
sys.stdin = StringIO(user_stdin)
sys.stdout = buf_out
sys.stderr = buf_err

raw_builtins = __builtins__
safe_builtins = dict(raw_builtins.__dict__) if hasattr(raw_builtins, '__dict__') else dict(raw_builtins)

BLOCKED_BUILTIN_NAMES = {
    'open', 'eval', 'exec', 'compile', 'breakpoint',
    'exit', 'quit'
}

def _make_blocked_builtin(name):
    def _blocked(*args, **kwargs):
        raise PermissionError(f"Access to restricted builtin '{name}()' is blocked in the learning sandbox.")
    return _blocked

for b_name in BLOCKED_BUILTIN_NAMES:
    if b_name in safe_builtins:
        safe_builtins[b_name] = _make_blocked_builtin(b_name)

orig_import = safe_builtins.get('__import__')
RESTRICTED_MODULES = {
    'subprocess', 'commands', 'ctypes', 'multiprocessing',
    'socket', 'http', 'urllib', 'requests', 'ftplib',
    'xmlrpc', 'smtplib', 'poplib', 'imaplib',
    'importlib', 'code', 'codeop', 'signal', 'resource',
    'shutil', 'os', 'sys', 'pathlib'
}

def _guarded_import(name, *args, **kwargs):
    root = name.split('.')[0]
    if root in RESTRICTED_MODULES:
        raise PermissionError(f"Import of '{name}' is restricted in the learning sandbox.")
    if orig_import:
        return orig_import(name, *args, **kwargs)
    raise ImportError(f"Import mechanism unavailable for: {name}")

safe_builtins['__import__'] = _guarded_import

def _extract_target_names(node):
    names = set()
    if isinstance(node, ast.Name):
        names.add(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            names.update(_extract_target_names(elt))
    elif isinstance(node, ast.Starred):
        names.update(_extract_target_names(node.value))
    return names

def _collect_assigned_names(stmt):
    names = set()
    if isinstance(stmt, ast.Assign):
        for t in stmt.targets:
            names.update(_extract_target_names(t))
    elif isinstance(stmt, ast.AnnAssign):
        names.update(_extract_target_names(stmt.target))
    elif isinstance(stmt, ast.AugAssign):
        names.update(_extract_target_names(stmt.target))
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(stmt.name)
    elif isinstance(stmt, ast.Import):
        for alias in stmt.names:
            names.add(alias.asname or alias.name.split('.')[0])
    elif isinstance(stmt, ast.ImportFrom):
        for alias in stmt.names:
            if alias.name != '*':
                names.add(alias.asname or alias.name)
    elif isinstance(stmt, ast.For):
        names.update(_extract_target_names(stmt.target))
    elif isinstance(stmt, ast.With):
        for item in stmt.items:
            if item.optional_vars:
                names.update(_extract_target_names(item.optional_vars))
    return names

def _stmt_source(stmt):
    ln = getattr(stmt, 'lineno', None)
    if ln and 1 <= ln <= len(code_lines):
        return code_lines[ln - 1].strip()
    return ""

result = {'blocked': False, 'status': 'Success', 'issues': [], 'stdout': '', 'stderr': ''}
try:
    tree = ast.parse(code, filename='<user_code>')
except SyntaxError as e:
    result = {
        'blocked': False,
        'status': 'SyntaxError',
        'issues': [{
            'id': 1,
            'type': 'SyntaxError',
            'message': str(e.msg) if e.msg else str(e),
            'line': e.lineno or 1,
            'stmt_line': e.lineno or 1,
            'traceback_line': code_lines[(e.lineno or 1) - 1] if code_lines and 1 <= (e.lineno or 1) <= len(code_lines) else '',
            'statement': code_lines[(e.lineno or 1) - 1].strip() if code_lines and 1 <= (e.lineno or 1) <= len(code_lines) else '',
            'cascade_of': None,
        }],
        'stdout': '',
        'stderr': f"SyntaxError: {e.msg} (line {e.lineno})",
    }
    sys.stdout = old_stdout
    sys.stderr = old_stderr
    sys.stdout.write(json.dumps(result))
    raise SystemExit(0)

namespace = {'__builtins__': safe_builtins}
issues = []
failed_defs = {}

total_deadline = time.perf_counter() + total_timeout
stmt_deadline = [0.0]

def _watchdog_trace(frame, event, arg):
    if frame.f_code.co_filename != '<user_code>':
        return None
    if event == 'line' or event == 'call':
        now = time.perf_counter()
        if now > total_deadline:
            raise TimeoutError(f"Execution exceeded total sandbox timeout ({total_timeout:.1f}s).")
        if now > stmt_deadline[0]:
            raise TimeoutError(f"Statement timed out after {per_stmt_timeout:.1f}s (possible infinite loop).")
    return _watchdog_trace

for stmt in tree.body:
    if time.perf_counter() >= total_deadline:
        issues.append({
            'id': len(issues) + 1,
            'type': 'TimeoutError',
            'message': f"Total sandbox timeout ({total_timeout:.1f}s) reached; remaining statements skipped.",
            'line': getattr(stmt, 'lineno', 1),
            'stmt_line': getattr(stmt, 'lineno', 1),
            'traceback_line': _stmt_source(stmt),
            'statement': _stmt_source(stmt),
            'cascade_of': None,
        })
        break

    mod = ast.Module(body=[stmt], type_ignores=[])
    compiled_stmt = compile(mod, '<user_code>', 'exec')
    is_import_stmt = isinstance(stmt, (ast.Import, ast.ImportFrom))
    t_stmt_start = time.perf_counter()
    stmt_deadline[0] = min(t_stmt_start + per_stmt_timeout, total_deadline)

    try:
        if not is_import_stmt:
            sys.settrace(_watchdog_trace)
        exec(compiled_stmt, namespace, namespace)
    except BaseException as e:
        sys.settrace(None)
        tb = traceback.extract_tb(e.__traceback__)
        user_frames = [f for f in tb if f.filename == '<user_code>']
        err_line = user_frames[-1].lineno if user_frames else getattr(stmt, 'lineno', 1)
        tb_src = code_lines[err_line - 1].strip() if code_lines and 1 <= err_line <= len(code_lines) else ''
        err_type = type(e).__name__
        err_msg = str(e)

        cascade_of = None
        if err_type == 'NameError':
            m = re.search(r"name '(\w+)' is not defined", err_msg)
            if m and m.group(1) in failed_defs:
                cascade_of = failed_defs[m.group(1)]

        issue_id = len(issues) + 1
        root_cause_id = cascade_of if cascade_of is not None else issue_id
        for var_name in _collect_assigned_names(stmt):
            if var_name not in namespace:
                failed_defs[var_name] = root_cause_id

        issues.append({
            'id': issue_id,
            'type': err_type,
            'message': err_msg,
            'line': err_line,
            'stmt_line': getattr(stmt, 'lineno', err_line),
            'traceback_line': tb_src,
            'statement': _stmt_source(stmt),
            'cascade_of': cascade_of,
        })
    finally:
        sys.settrace(None)
        if is_import_stmt:
            imp_elapsed = time.perf_counter() - t_stmt_start
            total_deadline += min(imp_elapsed, 5.0)

sys.stdout = old_stdout
sys.stderr = old_stderr

result = {
    'blocked': False,
    'status': 'Success' if not issues else 'Errors',
    'issues': issues,
    'stdout': buf_out.getvalue()[:20000],
    'stderr': buf_err.getvalue()[:10000],
}

out_str = json.dumps(result)
if len(out_str) > 150000:
    result['stdout'] = result['stdout'][:2000] + '... [TRUNCATED]'
    result['issues'] = result['issues'][:50]
    out_str = json.dumps(result)

sys.stdout.write(out_str)
"""

        payload = json.dumps({
            "code": code,
            "stdin": stdin_data or "",
            "total_timeout": total_t,
            "per_stmt_timeout": stmt_t,
        })

        has_heavy_import = any(
            pkg in code for pkg in ("import pandas", "from pandas", "import numpy", "from numpy", "import scipy", "import matplotlib", "import sklearn")
        )
        sub_timeout = (total_t + 5.0) if has_heavy_import else (total_t + 0.8)
        try:
            proc = subprocess.run(
                [sys.executable, "-c", resilient_runner],
                input=payload,
                text=True,
                capture_output=True,
                timeout=sub_timeout,
            )
            if proc.stdout.strip():
                return json.loads(proc.stdout.strip())
            return {
                "blocked": False,
                "status": "RuntimeError",
                "stdout": "",
                "stderr": proc.stderr.strip() or "Resilient sandbox exited without output.",
                "issues": [{
                    "id": 1,
                    "type": "RuntimeError",
                    "message": proc.stderr.strip() or "Process terminated unexpectedly.",
                    "line": 1,
                    "stmt_line": 1,
                    "traceback_line": "",
                    "statement": "",
                    "cascade_of": None,
                }],
            }
        except subprocess.TimeoutExpired:
            return {
                "blocked": False,
                "status": "TimeoutError",
                "stdout": "",
                "stderr": f"TimeoutError: Execution exceeded {total_t:.1f}s total sandbox limit.",
                "issues": [{
                    "id": 1,
                    "type": "TimeoutError",
                    "message": f"Execution exceeded {total_t:.1f}s total sandbox limit.",
                    "line": 1,
                    "stmt_line": 1,
                    "traceback_line": "",
                    "statement": "",
                    "cascade_of": None,
                }],
            }
        except Exception as e:
            return {
                "blocked": False,
                "status": "ExecutionError",
                "stdout": "",
                "stderr": str(e),
                "issues": [{
                    "id": 1,
                    "type": "ExecutionError",
                    "message": str(e),
                    "line": 1,
                    "stmt_line": 1,
                    "traceback_line": "",
                    "statement": "",
                    "cascade_of": None,
                }],
            }

    def _format_syntax_error(self, error: SyntaxError, code: str) -> Dict:
        """Format syntax errors with context."""
        return {
            'error_type': 'SyntaxError',
            'message': str(error.msg) if error.msg else str(error),
            'line_number': error.lineno,
            'offset': error.offset,
            'code_context': self._get_context_lines(code, error.lineno),
            'raw_traceback': f"SyntaxError: {error.msg} (line {error.lineno})",
            'full_code': code
        }

    def _format_runtime_error(self, error: BaseException, code: str) -> Dict:
        """Format runtime errors with full traceback."""

        if isinstance(error, SystemExit):
            return {
                'error_type': 'SystemExit',
                'message': f"Program attempted to exit with code: {error.code}",
                'line_number': None,
                'offset': None,
                'code_context': "sys.exit() called",
                'raw_traceback': "SystemExit triggered explicitly.",
                'full_code': code
            }

        tb = traceback.extract_tb(error.__traceback__)
        line_number = tb[-1].lineno if tb else None

        return {
            'error_type': type(error).__name__,
            'message': str(error),
            'line_number': line_number,
            'offset': None,
            'code_context': self._get_context_lines(code, line_number) if line_number else code,
            'raw_traceback': ''.join(traceback.format_exception(type(error), error, error.__traceback__)),
            'full_code': code
        }

    def _get_context_lines(self, code: str, line_number: int, context: int = 3) -> str:
        """Extract lines around the error for context."""
        if not line_number:
            return code

        lines = code.split('\n')
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)

        context_lines = []
        for i, line in enumerate(lines[start:end], start=start + 1):
            marker = ">>> " if i == line_number else "    "
            context_lines.append(f"{marker}{i}:  {line}")

        return '\n'.join(context_lines)


def capture_error(code: str) -> Tuple[bool, Optional[Dict]]:
    """Capture errors from code execution."""
    capturer = ErrorCapture()
    return capturer.execute_code(code)


if __name__ == "__main__":

    # Test 1: Normal error
    test_code = """
result = 10 / 0
"""
    success, error = capture_error(test_code)

    if not success:
        print("\n--- Error Captured! ---")
        print(f"Type:    {error['error_type']}")
        print(f"Message: {error['message']}")

        if error.get('line_number'):
            print(f"Line:    {error['line_number']}")
            print(f"\nContext:\n{error['code_context']}")
        else:
            print("Line:    Unknown")

    else:
        print("Execution successful!")

    # Test 2: Dangerous code
    print("\n" + "=" * 50)
    dangerous_code = """
import os
os.system('rm -rf /')
"""
    success, error = capture_error(dangerous_code)
    if not success:
        print("\n--- Security Block! ---")
        print(f"Type:    {error['error_type']}")
        print(f"Message: {error['message']}")