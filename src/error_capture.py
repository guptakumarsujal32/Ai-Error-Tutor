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

    def execute_code(self, code: str) -> Tuple[bool, Optional[Dict]]:
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
        # Step -0.5: Enforce strict input size limits
        MAX_INPUT_LENGTH = 10000
        if len(code) > MAX_INPUT_LENGTH:
            error_info = {
                'error_type': 'SecurityError',
                'message': f"Code blocked: Input length ({len(code)} chars) exceeds maximum safety limit ({MAX_INPUT_LENGTH} chars).",
                'line_number': 1,
                'offset': None,
                'code_context': code[:120],
                'raw_traceback': 'SecurityError: Payload too large for learning sandbox.',
                'full_code': code,
                'security_warnings': [
                    SecurityWarning(
                        level='BLOCKED',
                        category='resource_dos',
                        message=f"Input length exceeds {MAX_INPUT_LENGTH} character limit.",
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

code = sys.stdin.read(15000)
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

        try:
            proc = subprocess.run(
                [sys.executable, "-c", runner_script],
                input=code,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds
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