"""Multi-Pass Repair Loop Engine (analyze_all) for AI Error Tutor.

Architecture:
  Security Gate Pre-Check ->
    Pass 1: Static Scan (iterative syntax repair + single-sweep AST diagnostics) ->
    Pass 2: Resilient Dynamic Run (per-statement AST try/except inside sandbox + cascade tracking) ->
    Pass 3: Fix Loop (small ~30-line context for qwen2.5-coder:3b, <=3-line patch validation,
                      anti-trojan & import egress guards, Pass 2 re-verification, loop protection) ->
    Pass 4: Final Report (structured JSON report, unified diff, full sandbox verification).

Safety invariant:
  User code is NEVER executed outside the existing Security Gate and ErrorCapture sandbox.
"""

import ast
import re
import difflib
import builtins
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import config
from src.error_capture import ErrorCapture
from src.ast_parser import ASTContextExtractor
from src.security import CodeSecurityValidator
from src.aai_security_guard import AAISecurityGuard

try:
    from llm.ollama_client import OllamaClient
except ImportError:
    OllamaClient = None


BUILTIN_NAMES: Set[str] = set(dir(builtins))
COMMON_METHODS: List[str] = [
    "title", "upper", "lower", "strip", "lstrip", "rstrip", "split", "rsplit",
    "join", "replace", "find", "rfind", "index", "count", "startswith", "endswith",
    "format", "isdigit", "isalpha", "isalnum", "capitalize", "swapcase",
    "append", "extend", "insert", "remove", "pop", "clear", "copy", "sort", "reverse",
    "keys", "values", "items", "get", "update", "setdefault", "add", "discard",
    # Common NumPy / Pandas / Math attributes
    "array", "arange", "zeros", "ones", "linspace", "reshape", "mean", "median", "std",
    "dot", "exp", "log", "sqrt", "sin", "cos", "abs", "sum", "min", "max", "vstack", "hstack",
    "DataFrame", "Series", "read_csv", "read_excel", "to_csv", "concat", "merge",
    "groupby", "head", "tail", "describe", "info", "dropna", "fillna", "value_counts",
]
SAFE_PERMITTED_NEW_MODULES: Set[str] = {
    "math", "random", "re", "datetime", "collections",
    "itertools", "functools", "string",
    "statistics", "decimal", "fractions", "json", "csv",
    "numpy", "pandas", "scipy", "matplotlib",
}


class StaticASTScanner:
    """Single-sweep AST static analyzer reusing Levenshtein matching & symbol tables."""

    def __init__(self, ast_extractor: ASTContextExtractor):
        self.ast_extractor = ast_extractor

    def scan(self, code: str, tree: ast.AST) -> List[Dict[str, Any]]:
        """Collect all static errors and warnings in one AST sweep."""
        issues: List[Dict[str, Any]] = []
        lines = code.splitlines()

        # 1. Collect module-level & function-level symbols, imports, signatures
        imports: Dict[str, Tuple[int, str]] = {}           # bound_name -> (lineno, stmt_text)
        module_defs: Dict[str, int] = {}                   # name -> first def line
        func_sigs: Dict[str, Tuple[int, Optional[int], int]] = {}  # fn -> (min_args, max_args, lineno)
        all_loaded_names: Set[str] = set()
        module_assigns: Dict[str, int] = {}                # var -> lineno

        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    imports[bound] = (node.lineno, self._line_at(lines, node.lineno))
                    module_defs.setdefault(bound, node.lineno)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":
                        bound = alias.asname or alias.name
                        imports[bound] = (node.lineno, self._line_at(lines, node.lineno))
                        module_defs.setdefault(bound, node.lineno)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                module_defs.setdefault(node.name, node.lineno)
                pos_args = len(node.args.posonlyargs) + len(node.args.args)
                defaults = len(node.args.defaults)
                min_a = max(0, pos_args - defaults)
                max_a = None if node.args.vararg else pos_args
                func_sigs[node.name] = (min_a, max_a, node.lineno)
            elif isinstance(node, ast.ClassDef):
                module_defs.setdefault(node.name, node.lineno)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    for nm in self._target_names(t):
                        module_defs.setdefault(nm, node.lineno)
                        module_assigns.setdefault(nm, node.lineno)
            elif isinstance(node, ast.AnnAssign):
                for nm in self._target_names(node.target):
                    module_defs.setdefault(nm, node.lineno)
                    module_assigns.setdefault(nm, node.lineno)
            elif isinstance(node, ast.For):
                for nm in self._target_names(node.target):
                    module_defs.setdefault(nm, node.lineno)

        # Collect ALL loaded names across the entire AST (for unused import/var checks)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                all_loaded_names.add(node.id)

        # Track seen (type, line) to avoid duplicate static entries
        seen: Set[Tuple[str, int]] = set()

        def _add(issue_type: str, line: int, severity: str, message: str, extra: Optional[Dict] = None):
            key = (issue_type, line)
            if key in seen:
                return
            seen.add(key)
            entry = {
                "type": issue_type,
                "line": line,
                "severity": severity,
                "message": message,
                "source": "static",
            }
            if extra:
                entry.update(extra)
            issues.append(entry)

        # 2. Unused imports (Warning)
        for imp_name, (ln, _) in imports.items():
            if not imp_name.startswith("_") and imp_name not in all_loaded_names:
                _add(
                    "UnusedImport",
                    ln,
                    "warning",
                    f"Imported name '{imp_name}' is never used.",
                    {"symbol": imp_name},
                )

        # 3. Walk top-level statements & function bodies for detailed checks
        # 3a. Module-level use-before-assignment and undefined names
        defined_so_far: Set[str] = set(BUILTIN_NAMES) | set(imports.keys())
        # Pre-register functions & classes defined anywhere at module level for forward refs inside funcs
        all_module_symbols: Set[str] = set(BUILTIN_NAMES) | set(module_defs.keys())

        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined_so_far.add(stmt.name)
                self._check_function(stmt, all_module_symbols, func_sigs, _add)
            elif isinstance(stmt, ast.ClassDef):
                defined_so_far.add(stmt.name)
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._check_function(item, all_module_symbols, func_sigs, _add, is_method=True)
            else:
                # Check expressions in this top-level statement BEFORE recording its assignments
                self._check_stmt_loads(stmt, defined_so_far, module_defs, func_sigs, _add, in_function=False)
                # Record newly defined names from this statement
                defined_so_far.update(self._stmt_defined_names(stmt))

        # 3b. Unused module-level variables (only simple assignments not referenced anywhere)
        # Skip if file is huge (>500 lines) to avoid noisy warnings on stress files
        if len(lines) <= 500:
            for var_name, ln in module_assigns.items():
                if not var_name.startswith("_") and var_name not in all_loaded_names:
                    # Only flag if not reassigned via augassign (like counter += 1)
                    _add(
                        "UnusedVariable",
                        ln,
                        "warning",
                        f"Variable '{var_name}' is assigned but never used.",
                        {"symbol": var_name},
                    )

        # 4. Global structural checks across entire AST: bare except, literal type misuse, bad arg counts
        for node in ast.walk(tree):
            # Bare except (Warning)
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                _add(
                    "BareExcept",
                    node.lineno,
                    "warning",
                    "Bare 'except:' catches SystemExit and KeyboardInterrupt; specify 'except Exception:'.",
                )

            # Obvious literal type misuse: str + int/float or int/float + str (Error)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                lt = self._literal_type(node.left)
                rt = self._literal_type(node.right)
                if (lt == "str" and rt in ("int", "float")) or (rt == "str" and lt in ("int", "float")):
                    _add(
                        "TypeError",
                        node.lineno,
                        "error",
                        f"Cannot concatenate '{lt}' and '{rt}' literals directly with '+'.",
                    )

            # Wrong number of arguments for known module-level functions (Error)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                fn = node.func.id
                if fn in func_sigs and not any(isinstance(a, ast.Starred) for a in node.args) and not node.keywords:
                    min_a, max_a, _ = func_sigs[fn]
                    n_args = len(node.args)
                    if n_args < min_a:
                        _add(
                            "TypeError",
                            node.lineno,
                            "error",
                            f"{fn}() missing {min_a - n_args} required positional argument(s) (got {n_args}, expected at least {min_a}).",
                        )
                    elif max_a is not None and n_args > max_a:
                        _add(
                            "TypeError",
                            node.lineno,
                            "error",
                            f"{fn}() takes at most {max_a} positional argument(s) but {n_args} were given.",
                        )

        issues.sort(key=lambda x: (x["line"], 0 if x["severity"] == "error" else 1))
        return issues

    def _check_function(
        self,
        fn_node: ast.AST,
        outer_symbols: Set[str],
        func_sigs: Dict[str, Tuple[int, Optional[int], int]],
        add_fn: Callable,
        is_method: bool = False,
    ) -> None:
        """Analyze a single function for mutable defaults, missing return paths,
        UnboundLocalError (use before local assignment), undefined names, and unused locals."""
        # 1. Mutable default arguments (Warning)
        all_defaults = list(fn_node.args.defaults) + [d for d in fn_node.args.kw_defaults if d is not None]
        for default_node in all_defaults:
            if isinstance(default_node, (ast.List, ast.Dict, ast.Set)):
                kind = type(default_node).__name__.lower()
                add_fn(
                    "MutableDefault",
                    getattr(default_node, "lineno", fn_node.lineno),
                    "warning",
                    f"Function '{fn_node.name}' uses a mutable default argument ({kind}); use None instead.",
                )

        # 2. Missing return on some paths (Warning)
        if self._has_explicit_value_return(fn_node.body) and not self._always_returns(fn_node.body):
            add_fn(
                "MissingReturn",
                fn_node.lineno,
                "warning",
                f"Function '{fn_node.name}' returns a value on some paths but can fall off the end returning None.",
            )

        # 3. Collect parameters, global/nonlocal declarations, and local bindings
        params: Set[str] = set()
        for arg in fn_node.args.posonlyargs + fn_node.args.args + fn_node.args.kwonlyargs:
            params.add(arg.arg)
        if fn_node.args.vararg:
            params.add(fn_node.args.vararg.arg)
        if fn_node.args.kwarg:
            params.add(fn_node.args.kwarg.arg)

        globals_declared: Set[str] = set()
        local_assigned_lines: Dict[str, int] = {}
        local_loaded: Set[str] = set()

        for node in self._walk_function_scope(fn_node):
            if isinstance(node, ast.Global):
                globals_declared.update(node.names)
            elif isinstance(node, ast.Nonlocal):
                globals_declared.update(node.names)
            elif isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    local_assigned_lines.setdefault(node.id, node.lineno)
                elif isinstance(node.ctx, ast.Load):
                    local_loaded.add(node.id)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                # `x += 1` BOTH loads AND stores x!
                local_assigned_lines.setdefault(node.target.id, node.lineno)
                local_loaded.add(node.target.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not fn_node:
                local_assigned_lines.setdefault(node.name, node.lineno)

        # Track defined locals in statement order to catch UnboundLocalError & undefined names
        bound_locals: Set[str] = set(params)
        local_assigned_set: Set[str] = set(local_assigned_lines.keys()) - globals_declared

        for stmt in fn_node.body:
            # Check AugAssign targeting a variable assigned locally without prior binding -> UnboundLocalError!
            for sub in self._walk_stmt_nodes(stmt):
                if isinstance(sub, ast.AugAssign) and isinstance(sub.target, ast.Name):
                    nm = sub.target.id
                    if nm not in bound_locals and nm not in globals_declared:
                        add_fn(
                            "UnboundLocalError",
                            sub.lineno,
                            "error",
                            f"Local variable '{nm}' referenced before assignment in '{fn_node.name}()'.",
                            {"symbol": nm},
                        )
                elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                    nm = sub.id
                    if nm in bound_locals or nm in globals_declared:
                        continue
                    if nm in local_assigned_set:
                        # Assigned later in same function -> UnboundLocalError
                        if sub.lineno < local_assigned_lines.get(nm, 0):
                            add_fn(
                                "UnboundLocalError",
                                sub.lineno,
                                "error",
                                f"Local variable '{nm}' referenced before assignment in '{fn_node.name}()'.",
                                {"symbol": nm},
                            )
                    elif nm not in outer_symbols:
                        # Undefined name inside function
                        all_known = list(bound_locals | local_assigned_set | outer_symbols)
                        suggestion = self._did_you_mean(nm, all_known)
                        msg = f"Name '{nm}' is not defined."
                        if suggestion:
                            msg += f" Did you mean '{suggestion}'?"
                        add_fn(
                            "NameError",
                            sub.lineno,
                            "error",
                            msg,
                            {"symbol": nm, "suggestion": suggestion},
                        )

            bound_locals.update(self._stmt_defined_names(stmt))

        # 4. Unused local variables (Warning)
        for nm, ln in local_assigned_lines.items():
            if nm not in params and not nm.startswith("_") and nm not in local_loaded and nm not in globals_declared:
                add_fn(
                    "UnusedVariable",
                    ln,
                    "warning",
                    f"Local variable '{nm}' in '{fn_node.name}()' is assigned but never used.",
                    {"symbol": nm},
                )

    def _check_stmt_loads(
        self,
        stmt: ast.AST,
        defined_so_far: Set[str],
        module_defs: Dict[str, int],
        func_sigs: Dict,
        add_fn: Callable,
        in_function: bool = False,
    ) -> None:
        """Check variable loads in a top-level statement for undefined names or use-before-assignment."""
        # Collect comprehension loop variables to avoid false positives on `[x for x in items]`
        comp_targets: Set[str] = set()
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.comprehension):
                comp_targets.update(self._target_names(sub.target))
            elif isinstance(sub, ast.Lambda):
                for a in sub.args.args:
                    comp_targets.add(a.arg)
            elif isinstance(sub, ast.ExceptHandler) and sub.name:
                comp_targets.add(sub.name)
            elif isinstance(sub, ast.For):
                comp_targets.update(self._target_names(sub.target))
            elif isinstance(sub, ast.With):
                for it in sub.items:
                    if it.optional_vars:
                        comp_targets.update(self._target_names(it.optional_vars))

        # Collect names assigned INSIDE an `if`/`for`/`while`/`try` block so lines inside the block can see them
        block_defined: Set[str] = set()
        if isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    block_defined.add(sub.id)

        known_now = defined_so_far | comp_targets | block_defined
        all_candidates = list(known_now | set(module_defs.keys()))

        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                nm = sub.id
                if nm in known_now:
                    continue
                if nm in module_defs and module_defs[nm] > sub.lineno:
                    add_fn(
                        "NameError",
                        sub.lineno,
                        "error",
                        f"Name '{nm}' is used before it is assigned on line {module_defs[nm]}.",
                        {"symbol": nm},
                    )
                elif nm not in module_defs:
                    suggestion = self._did_you_mean(nm, all_candidates)
                    msg = f"Name '{nm}' is not defined."
                    if suggestion:
                        msg += f" Did you mean '{suggestion}'?"
                    add_fn(
                        "NameError",
                        sub.lineno,
                        "error",
                        msg,
                        {"symbol": nm, "suggestion": suggestion},
                    )

    @staticmethod
    def _walk_function_scope(fn_node: ast.AST):
        """Walk AST nodes inside a function without descending into nested defs/classes."""
        stack = list(fn_node.body)
        while stack:
            node = stack.pop()
            yield node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            stack.extend(ast.iter_child_nodes(node))

    @staticmethod
    def _walk_stmt_nodes(stmt: ast.AST):
        """Walk expression/statement nodes without descending into nested defs or comprehensions."""
        comp_vars: Set[str] = set()
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.comprehension):
                comp_vars.update(StaticASTScanner._target_names(sub.target))
            elif isinstance(sub, ast.For):
                comp_vars.update(StaticASTScanner._target_names(sub.target))
            elif isinstance(sub, ast.ExceptHandler) and sub.name:
                comp_vars.add(sub.name)

        stack = [stmt]
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Name) and node.id in comp_vars:
                continue
            yield node
            stack.extend(ast.iter_child_nodes(node))

    @staticmethod
    def _has_explicit_value_return(body: List[ast.stmt]) -> bool:
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if isinstance(node, ast.Return) and node.value is not None:
                    return True
        return False

    @classmethod
    def _always_returns(cls, body: List[ast.stmt]) -> bool:
        for stmt in body:
            if isinstance(stmt, (ast.Return, ast.Raise)):
                return True
            if isinstance(stmt, ast.If):
                if stmt.orelse and cls._always_returns(stmt.body) and cls._always_returns(stmt.orelse):
                    return True
            if isinstance(stmt, ast.Try):
                if cls._always_returns(stmt.body) and all(cls._always_returns(h.body) for h in stmt.handlers):
                    return True
        return False

    @staticmethod
    def _literal_type(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return "str"
            if isinstance(node.value, bool):
                return "bool"
            if isinstance(node.value, int):
                return "int"
            if isinstance(node.value, float):
                return "float"
        if isinstance(node, ast.JoinedStr):
            return "str"
        return None

    @staticmethod
    def _target_names(node: ast.AST) -> Set[str]:
        names: Set[str] = set()
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                names.update(StaticASTScanner._target_names(elt))
        elif isinstance(node, ast.Starred):
            names.update(StaticASTScanner._target_names(node.value))
        return names

    @classmethod
    def _stmt_defined_names(cls, stmt: ast.AST) -> Set[str]:
        names: Set[str] = set()
        for node in ast.walk(stmt):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    names.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name != "*":
                        names.add(a.asname or a.name)
        return names

    @staticmethod
    def _did_you_mean(name: str, candidates: List[str]) -> Optional[str]:
        pool = list(set(c for c in candidates if c != name))
        matches = difflib.get_close_matches(name, pool, n=1, cutoff=0.68)
        return matches[0] if matches else None

    @staticmethod
    def _line_at(lines: List[str], lineno: int) -> str:
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1]
        return ""


class RepairLoop:
    """4-Pass Multi-Error Detection & Repair Engine."""

    def __init__(self, use_ai: bool = True, ollama_client: Optional[Any] = None):
        self.error_capture = ErrorCapture(timeout_seconds=config.TOTAL_SANDBOX_TIMEOUT)
        self.ast_extractor = ASTContextExtractor()
        self.static_scanner = StaticASTScanner(self.ast_extractor)
        self.validator = CodeSecurityValidator()
        self.aai_guard = AAISecurityGuard()
        self.use_ai = use_ai
        if ollama_client is not None:
            self.ollama_client = ollama_client
        elif use_ai and OllamaClient is not None:
            try:
                self.ollama_client = OllamaClient()
            except Exception:
                self.ollama_client = None
        else:
            self.ollama_client = None

    # ─────────────────────────────────────────────────────────────
    # Main Entry Point
    # ─────────────────────────────────────────────────────────────
    def analyze_all(
        self,
        code: str,
        mode: str = "direct",
        stdin_data: str = "",
        fix_warnings: bool = False,
        progress_callback: Optional[Callable[[int, int, int, str], None]] = None,
    ) -> Dict[str, Any]:
        """Run the complete 4-pass repair pipeline on `code`."""
        original_code = code or ""
        if not original_code.strip():
            return {
                "blocked": False,
                "issues": [],
                "fixed_code": original_code,
                "diff": "",
                "rounds_used": 0,
                "final_run": {"status": "Idle", "output": ""},
                "error_count": 0,
                "warning_count": 0,
                "cascade_count": 0,
                "verified": True,
                "llm_max_context_lines": 0,
            }

        # ── STAGE 0: SECURITY GATE (Fail-closed, no repair loop if blocked) ──
        gate_block = self._check_security_gate(original_code)
        if gate_block is not None:
            return gate_block

        working_code = original_code
        all_issues: List[Dict[str, Any]] = []
        llm_max_context_lines = 0
        rounds_used = 0
        llm_available = bool(
            self.use_ai
            and self.ollama_client is not None
            and getattr(self.ollama_client, "is_available", lambda: True)()
        )

        # ── PASS 1: STATIC SCAN (Iterative syntax repair + single-sweep AST) ──
        working_code, syntax_issues, parsed_tree, syn_ctx = self._pass1_syntax_repair(
            working_code, llm_available=llm_available
        )
        llm_max_context_lines = max(llm_max_context_lines, syn_ctx)
        all_issues.extend(syntax_issues)

        static_warnings: List[Dict[str, Any]] = []
        static_errors: List[Dict[str, Any]] = []
        if parsed_tree is not None:
            static_raw = self.static_scanner.scan(working_code, parsed_tree)
            for item in static_raw:
                if item["severity"] == "warning":
                    static_warnings.append(self._make_issue_record(item, status="warning"))
                else:
                    static_errors.append(self._make_issue_record(item, status="open"))

        # ── PASS 2: RESILIENT DYNAMIC RUN (Inside existing sandbox subprocess) ──
        dynamic_issues: List[Dict[str, Any]] = []
        pass2_res = {"blocked": False, "status": "Success", "issues": [], "stdout": "", "stderr": ""}
        if parsed_tree is not None:
            pass2_res = self.error_capture.execute_resilient(
                working_code,
                stdin_data=stdin_data,
                total_timeout=config.TOTAL_SANDBOX_TIMEOUT,
                per_stmt_timeout=config.PER_STATEMENT_TIMEOUT,
            )
            if pass2_res.get("blocked"):
                return {
                    "blocked": True,
                    "block_reason": pass2_res.get("block_reason", "Blocked by sandbox security gate."),
                    "risk_level": "CRITICAL",
                    "risk_score": 90.0,
                    "attack_category": "security_policy",
                    "issues": [],
                    "fixed_code": original_code,
                    "diff": "",
                    "rounds_used": 0,
                    "final_run": {"status": "Blocked", "output": pass2_res.get("block_reason", "")},
                    "error_count": 0,
                    "warning_count": 0,
                    "cascade_count": 0,
                    "verified": False,
                    "llm_max_context_lines": llm_max_context_lines,
                }
            for dyn in pass2_res.get("issues", []):
                dynamic_issues.append(self._make_dynamic_issue_record(dyn))

        # Merge Pass 1 static errors + Pass 2 dynamic errors (avoiding duplicates on same line)
        merged_errors = self._merge_static_and_dynamic(static_errors, dynamic_issues)
        all_issues.extend(merged_errors)
        all_issues.extend(static_warnings)

        # Enforce MAX_ISSUES cap
        max_issues = getattr(config, "MAX_ISSUES", 30)
        if len(all_issues) > max_issues:
            all_issues = all_issues[:max_issues]

        # Assign clean sequential 1-based IDs & remap cascade_of references
        self._assign_issue_ids(all_issues)

        # ── FAST PATH: Clean program (0 errors and not fixing warnings) ──
        open_errors = [
            i for i in all_issues
            if i["severity"] == "error" and i["cascade_of"] is None and i["status"] not in ("fixed", "verified")
        ]
        open_warnings = [i for i in all_issues if i["severity"] == "warning"]

        if not open_errors and not syntax_issues and (not fix_warnings or not open_warnings):
            return self._build_final_report(
                original_code=original_code,
                fixed_code=working_code,
                issues=all_issues,
                rounds_used=0,
                final_run={"status": "Success", "output": pass2_res.get("stdout", "")},
                verified=True,
                llm_max_context_lines=llm_max_context_lines,
                mode=mode,
                llm_available=llm_available,
            )

        # ── PASS 3: ITERATIVE FIX LOOP (Small context, 1 issue at a time) ──
        max_rounds = getattr(config, "MAX_ROUNDS", 15)
        targets = [
            i for i in all_issues
            if i["cascade_of"] is None
            and i["status"] not in ("fixed", "verified", "manual")
            and (i["severity"] == "error" or (fix_warnings and i["severity"] == "warning"))
        ]
        targets.sort(key=lambda x: (x["line"] or 0, 0 if x["severity"] == "error" else 1))

        # Track loop protection
        prev_sig: Optional[Tuple[str, int, str]] = None
        no_progress_rounds = 0
        processed_sigs: Set[Tuple[str, int, str]] = set()
        queue: List[Dict[str, Any]] = list(targets)
        fixed_count_this_loop = 0

        while queue and rounds_used < max_rounds:
            issue = queue.pop(0)
            sig = (issue["type"], issue["line"], issue["message"])
            if sig in processed_sigs:
                continue

            rounds_used += 1
            total_target = max(len(targets), fixed_count_this_loop + len(queue) + 1)
            if progress_callback:
                progress_callback(
                    min(fixed_count_this_loop + 1, total_target),
                    total_target,
                    rounds_used,
                    f"Fixing issue {min(fixed_count_this_loop + 1, total_target)} of {total_target} (round {rounds_used})",
                )

            # Loop protection 1: same issue twice in a row
            if prev_sig == sig:
                issue["status"] = "manual"
                processed_sigs.add(sig)
                prev_sig = None
                continue
            prev_sig = sig

            # Build SMALL context (~30 lines / enclosing def or class) — NEVER the full file!
            ctx_snippet, sym_summary = self._build_small_context(working_code, issue["line"])
            llm_max_context_lines = max(llm_max_context_lines, len(ctx_snippet.splitlines()))

            # Check baseline error count in Pass 2 before patching
            pre_errors = self._count_non_cascade_errors(working_code, stdin_data)

            patched_code, patch_info, engine_used = self._generate_and_apply_issue_patch(
                working_code=working_code,
                original_code=original_code,
                issue=issue,
                ctx_snippet=ctx_snippet,
                sym_summary=sym_summary,
                llm_available=llm_available,
            )

            # Re-verify via Pass 2 in sandbox (rejects patches that introduce a new error on the same line!)
            accepted, post_res = self._verify_patch_in_sandbox(
                working_code=working_code,
                patched_code=patched_code,
                issue=issue,
                pre_errors=pre_errors,
                stdin_data=stdin_data,
            )

            # If LLM patch failed sandbox verification (e.g. small-model hallucination like `'z' in vars`),
            # immediately fall back to deterministic rule-based AST patch and verify it!
            if not accepted and not str(engine_used).startswith("Rule-based"):
                rb_code, rb_info = self._rule_based_patch_issue(working_code, issue)
                if rb_code and self._passes_security_egress(rb_code, original_code):
                    rb_ok, rb_post = self._verify_patch_in_sandbox(
                        working_code=working_code,
                        patched_code=rb_code,
                        issue=issue,
                        pre_errors=pre_errors,
                        stdin_data=stdin_data,
                    )
                    if rb_ok:
                        patched_code = rb_code
                        patch_info = rb_info
                        engine_used = "Rule-based"
                        accepted = True
                        post_res = rb_post

            if accepted and patched_code is not None:
                line_delta = len(patched_code.splitlines()) - len(working_code.splitlines())
                patched_at_line = issue.get("line") or 0
                working_code = patched_code
                if line_delta != 0:
                    # Shift downstream queued/remaining issue line numbers to stay aligned
                    for q_iss in queue:
                        if (q_iss.get("line") or 0) > patched_at_line:
                            q_iss["line"] += line_delta
                issue["patch"] = {"old": patch_info.get("old", ""), "new": patch_info.get("new", "")}
                if patch_info.get("explanation"):
                    issue["explanation"] = patch_info["explanation"]
                if patch_info.get("hint"):
                    issue["hint"] = patch_info["hint"]
                issue["engine"] = engine_used
                issue["status"] = "fixed"
                fixed_count_this_loop += 1
                no_progress_rounds = 0
                processed_sigs.add(sig)

                # Check if Pass 2 uncovered any NEW runtime errors previously hidden behind a fixed bug
                # (including root-cause errors on lines that previously only showed a cascade error!)
                if post_res is not None:
                    for dyn in post_res.get("issues", []):
                        if dyn.get("cascade_of") is not None:
                            continue
                        d_sig = (dyn.get("type"), dyn.get("line"), dyn.get("message", ""))
                        already_known = any(
                            x.get("cascade_of") is None
                            and (x["type"], x["line"], x.get("message", "")) == d_sig
                            for x in all_issues
                        )
                        if not already_known and d_sig not in processed_sigs and len(all_issues) < max_issues:
                            new_rec = self._make_dynamic_issue_record(dyn)
                            new_rec["_dyn_id"] = None
                            new_rec["_orig_cascade_dyn_id"] = None
                            new_rec["id"] = len(all_issues) + 1
                            all_issues.append(new_rec)
                            queue.append(new_rec)
                            queue.sort(key=lambda x: (x["line"] or 0, 0 if x["severity"] == "error" else 1))
            else:
                no_progress_rounds += 1
                issue["status"] = "manual"
                processed_sigs.add(sig)
                # Loop protection 2: no progress in 2 consecutive rounds -> stop trying stuck errors
                if no_progress_rounds >= 2 and not queue:
                    break

        # ── FINAL SELF-HEALING VERIFICATION ON FULL FIXED PROGRAM ──
        final_success, final_err = self.error_capture.execute_code(working_code, stdin_data=stdin_data)
        final_stdout = ""
        if final_success:
            # Capture stdout cleanly via resilient run (which succeeded with 0 issues)
            clean_res = self.error_capture.execute_resilient(
                working_code,
                stdin_data=stdin_data,
                total_timeout=config.TOTAL_SANDBOX_TIMEOUT,
                per_stmt_timeout=config.PER_STATEMENT_TIMEOUT,
            )
            final_stdout = clean_res.get("stdout", "")
            for iss in all_issues:
                if iss["status"] == "fixed":
                    iss["status"] = "verified"
                elif iss["cascade_of"] is not None:
                    iss["status"] = "verified"
            final_run = {"status": "Success", "output": final_stdout}
            verified = True
        else:
            err_desc = ""
            if final_err:
                err_desc = f"{final_err.get('error_type', 'Error')} at line {final_err.get('line_number')}: {final_err.get('message', '')}"
            final_run = {"status": final_err.get("error_type", "Errors") if final_err else "Errors", "output": err_desc}
            verified = False

        # Re-sort all issues cleanly by line number
        all_issues.sort(key=lambda x: (x["line"] or 0, 0 if x["severity"] == "error" else 1))
        self._assign_issue_ids(all_issues)

        # ── PASS 4: FINAL REPORT ──
        return self._build_final_report(
            original_code=original_code,
            fixed_code=working_code,
            issues=all_issues,
            rounds_used=rounds_used,
            final_run=final_run,
            verified=verified,
            llm_max_context_lines=llm_max_context_lines,
            mode=mode,
            llm_available=llm_available,
        )

    # ─────────────────────────────────────────────────────────────
    # Stage 0: Security Gate
    # ─────────────────────────────────────────────────────────────
    def _check_security_gate(self, code: str) -> Optional[Dict[str, Any]]:
        """Run AAISecurityGuard and CodeSecurityValidator before any pass."""
        line_count = len(code.splitlines())
        if line_count > 5000 or len(code) > 500000:
            reason = f"Code exceeds safety limit ({line_count} lines / {len(code)} chars; max 5,000 lines)."
            return {
                "blocked": True,
                "block_reason": reason,
                "risk_level": "HIGH",
                "risk_score": 75.0,
                "attack_category": "resource_dos",
                "issues": [],
                "fixed_code": code,
                "diff": "",
                "rounds_used": 0,
                "final_run": {"status": "Blocked", "output": reason},
                "error_count": 0,
                "warning_count": 0,
                "cascade_count": 0,
                "verified": False,
                "llm_max_context_lines": 0,
            }

        assessment = self.aai_guard.assess_input(code, target_type="code")
        if not assessment.is_safe:
            reason = f"Blocked by Agentic AI Security Guard ({assessment.primary_category.value}, risk {assessment.risk_score:.0f}/100)."
            return {
                "blocked": True,
                "block_reason": reason,
                "risk_level": assessment.risk_level.value,
                "risk_score": assessment.risk_score,
                "attack_category": assessment.primary_category.value,
                "issues": [],
                "fixed_code": code,
                "diff": "",
                "rounds_used": 0,
                "final_run": {"status": "Blocked", "output": reason},
                "error_count": 0,
                "warning_count": 0,
                "cascade_count": 0,
                "verified": False,
                "llm_max_context_lines": 0,
            }

        is_safe_ast, warnings = self.validator.validate(code)
        if not is_safe_ast:
            blocked_msgs = [w.message for w in warnings if getattr(w, "level", "") == "BLOCKED"]
            reason = "; ".join(blocked_msgs) or "Blocked by AST Security Validator."
            return {
                "blocked": True,
                "block_reason": reason,
                "risk_level": "CRITICAL",
                "risk_score": 90.0,
                "attack_category": "dangerous_operation",
                "issues": [],
                "fixed_code": code,
                "diff": "",
                "rounds_used": 0,
                "final_run": {"status": "Blocked", "output": reason},
                "error_count": 0,
                "warning_count": 0,
                "cascade_count": 0,
                "verified": False,
                "llm_max_context_lines": 0,
            }

        return None

    # ─────────────────────────────────────────────────────────────
    # Pass 1: Iterative Syntax Repair
    # ─────────────────────────────────────────────────────────────
    def _pass1_syntax_repair(
        self, code: str, llm_available: bool
    ) -> Tuple[str, List[Dict[str, Any]], Optional[ast.AST], int]:
        """Repeatedly ast.parse and fix syntax errors up to MAX_SYNTAX_ROUNDS (10)."""
        working = code
        syntax_issues: List[Dict[str, Any]] = []
        max_syn = getattr(config, "MAX_SYNTAX_ROUNDS", 10)
        max_ctx_lines = 0

        for _ in range(max_syn):
            try:
                tree = ast.parse(working)
                return working, syntax_issues, tree, max_ctx_lines
            except SyntaxError as syn_e:
                ln = syn_e.lineno or 1
                msg = str(syn_e.msg) if syn_e.msg else str(syn_e)
                lines = working.splitlines()
                old_line = lines[ln - 1] if 1 <= ln <= len(lines) else ""

                patched, patch_old, patch_new, expl, engine_used, ctx_len = self._fix_syntax_error(
                    working, ln, msg, llm_available=llm_available
                )
                max_ctx_lines = max(max_ctx_lines, ctx_len)

                issue_rec = {
                    "id": len(syntax_issues) + 1,
                    "type": "SyntaxError",
                    "line": ln,
                    "severity": "error",
                    "message": msg,
                    "explanation": expl or f"Syntax error on line {ln}: {msg}.",
                    "hint": f"Check Python syntax punctuation (colons, brackets, quotes, or operators) near line {ln}.",
                    "hints": self._default_socratic_hints("SyntaxError", msg, ln),
                    "vague_description": f"Python could not parse the grammar near line {ln}.",
                    "patch": {"old": patch_old, "new": patch_new},
                    "status": "fixed" if (patched and patched != working) else "manual",
                    "cascade_of": None,
                    "engine": engine_used,
                }
                syntax_issues.append(issue_rec)

                if patched and patched != working:
                    working = patched
                else:
                    return working, syntax_issues, None, max_ctx_lines

        try:
            tree = ast.parse(working)
            return working, syntax_issues, tree, max_ctx_lines
        except SyntaxError:
            return working, syntax_issues, None, max_ctx_lines

    def _fix_syntax_error(
        self, code: str, lineno: int, msg: str, llm_available: bool
    ) -> Tuple[Optional[str], str, str, str, str, int]:
        """Try deterministic syntax repair first, then small-window LLM fallback."""
        lines = code.split("\n")
        idx = max(0, min(lineno - 1, len(lines) - 1))

        # Check target line AND previous line (Python often reports missing ')' on the NEXT line!)
        candidate_indices = [idx]
        if idx > 0:
            candidate_indices.append(idx - 1)

        for ci in candidate_indices:
            target = lines[ci]
            code_part, sep, comment_part = target.partition("#")
            stripped = code_part.rstrip()
            suffix = f"  #{comment_part}" if sep else ""

            # 1. Missing colon on compound statement header
            if re.search(r"^\s*(def|if|elif|else|for|while|class|try|except|finally|with)\b.*[^:]\s*$", stripped):
                # Make sure parentheses are balanced first
                if stripped.count("(") == stripped.count(")"):
                    fixed = stripped + ":" + suffix
                    new_lines = list(lines)
                    new_lines[ci] = fixed
                    if self._syntax_progress(code, "\n".join(new_lines), lineno):
                        return (
                            "\n".join(new_lines),
                            target,
                            fixed,
                            f"Added missing colon ':' at the end of the compound statement on line {ci + 1}.",
                            "Rule-based AST",
                            0,
                        )

            # 2. Single '=' inside if/elif/while condition -> '=='
            if re.search(r"^\s*(if|elif|while)\b.*(?<![=!<>:])=(?!=)", stripped):
                fixed_code = re.sub(r"(?<![=!<>:])=(?!=)", "==", stripped, count=1)
                if not fixed_code.endswith(":"):
                    fixed_code += ":"
                fixed = fixed_code + suffix
                new_lines = list(lines)
                new_lines[ci] = fixed
                if self._syntax_progress(code, "\n".join(new_lines), lineno):
                    return (
                        "\n".join(new_lines),
                        target,
                        fixed,
                        f"Replaced assignment '=' with equality comparison '==' in condition on line {ci + 1}.",
                        "Rule-based AST",
                        0,
                    )

            # 3. Unclosed parenthesis / bracket / brace (respecting multi-line structures!)
            for open_ch, close_ch in [("(", ")"), ("[", "]"), ("{", "}")]:
                # Never add a closing delimiter if the whole file is already balanced for that delimiter
                if code.count(open_ch) <= code.count(close_ch):
                    continue
                if stripped.count(open_ch) > stripped.count(close_ch):
                    missing = min(code.count(open_ch) - code.count(close_ch), stripped.count(open_ch) - stripped.count(close_ch))
                    # 3a. Try closing on a later line first if this opens a multi-line expression (e.g. `df = pd.DataFrame({\n...\n}`)
                    for close_i in range(ci + 1, min(len(lines), ci + 15)):
                        cl_part, cl_sep, cl_comm = lines[close_i].partition("#")
                        cl_stripped = cl_part.rstrip()
                        if not cl_stripped:
                            continue
                        cl_suf = f"  #{cl_comm}" if cl_sep else ""
                        cand_line = cl_stripped + (close_ch * missing) + cl_suf
                        new_lines = list(lines)
                        new_lines[close_i] = cand_line
                        if self._syntax_progress(code, "\n".join(new_lines), close_i + 1):
                            return (
                                "\n".join(new_lines),
                                lines[close_i],
                                cand_line,
                                f"Closed unclosed '{open_ch}' opened on line {ci + 1} by adding '{close_ch * missing}' on line {close_i + 1}.",
                                "Rule-based AST",
                                0,
                            )
                    # 3b. Single-line unclosed delimiter (e.g. `print("hi"` -> `print("hi")`)
                    fixed = stripped + (close_ch * missing) + suffix
                    new_lines = list(lines)
                    new_lines[ci] = fixed
                    if self._syntax_progress(code, "\n".join(new_lines), lineno):
                        return (
                            "\n".join(new_lines),
                            target,
                            fixed,
                            f"Closed {missing} unclosed '{open_ch}' delimiter(s) on line {ci + 1}.",
                            "Rule-based AST",
                            0,
                        )

            # 4. Extra unmatched closing parenthesis / bracket
            for open_ch, close_ch in [("(", ")"), ("[", "]")]:
                if stripped.count(close_ch) > stripped.count(open_ch):
                    diff = stripped.count(close_ch) - stripped.count(open_ch)
                    fixed_code = stripped
                    for _ in range(diff):
                        pos = fixed_code.rfind(close_ch)
                        if pos != -1:
                            fixed_code = fixed_code[:pos] + fixed_code[pos + 1:]
                    fixed = fixed_code + suffix
                    new_lines = list(lines)
                    new_lines[ci] = fixed
                    if self._syntax_progress(code, "\n".join(new_lines), lineno):
                        return (
                            "\n".join(new_lines),
                            target,
                            fixed,
                            f"Removed extra unmatched '{close_ch}' on line {ci + 1}.",
                            "Rule-based AST",
                            0,
                        )

            # 5. Unterminated string literal on line
            if "unterminated string" in msg.lower() or "eol while scanning" in msg.lower():
                for q in ('"', "'"):
                    if stripped.count(q) % 2 == 1:
                        fixed = stripped + q + suffix
                        new_lines = list(lines)
                        new_lines[ci] = fixed
                        if self._syntax_progress(code, "\n".join(new_lines), lineno):
                            return (
                                "\n".join(new_lines),
                                target,
                                fixed,
                                f"Closed unterminated string literal with {q} on line {ci + 1}.",
                                "Rule-based AST",
                                0,
                            )

            # 6. Python 2 print statement: print "hello" -> print("hello")
            m_print = re.match(r"^(\s*)print\s+([^(].*)$", stripped)
            if m_print:
                fixed = f"{m_print.group(1)}print({m_print.group(2).strip()}){suffix}"
                new_lines = list(lines)
                new_lines[ci] = fixed
                if self._syntax_progress(code, "\n".join(new_lines), lineno):
                    return (
                        "\n".join(new_lines),
                        target,
                        fixed,
                        f"Converted Python 2 print statement into print(...) function call on line {ci + 1}.",
                        "Rule-based AST",
                        0,
                    )

        # 7. Small-context LLM fallback for unusual syntax errors
        if llm_available and self.ollama_client and hasattr(self.ollama_client, "generate_minimal_patch"):
            ctx_snippet, _ = self._build_small_context(code, lineno)
            ctx_len = len(ctx_snippet.splitlines())
            patch = self.ollama_client.generate_minimal_patch(
                error_type="SyntaxError",
                error_message=msg,
                line_number=lineno,
                context_snippet=ctx_snippet,
            )
            if patch and patch.get("new"):
                applied, err_reason = self._apply_patch_strict(
                    code, patch, require_parse=False, original_code=code
                )
                if applied and self._syntax_progress(code, applied, lineno):
                    return (
                        applied,
                        patch.get("old", ""),
                        patch.get("new", ""),
                        patch.get("explanation", f"Fixed syntax error at line {lineno}."),
                        self._format_engine_tag(patch),
                        ctx_len,
                    )
            return None, lines[idx] if idx < len(lines) else "", "", "", "Rule-based", ctx_len

        return None, lines[idx] if idx < len(lines) else "", "", "", "Rule-based", 0

    @staticmethod
    def _syntax_progress(old_code: str, new_code: str, old_lineno: int) -> bool:
        """Returns True if new_code parses cleanly OR advances SyntaxError past old_lineno."""
        try:
            ast.parse(new_code)
            return True
        except SyntaxError as e:
            return (e.lineno or 0) > old_lineno

    # ─────────────────────────────────────────────────────────────
    # Pass 3: Context Building, Patch Validation, & Rule Engine
    # ─────────────────────────────────────────────────────────────
    def _build_small_context(self, code: str, line_number: Optional[int]) -> Tuple[str, str]:
        """
        Build a SMALL context (~30 lines or enclosing function/class) + symbol table entries.
        NEVER returns the entire file for large programs.
        """
        lines = code.splitlines()
        max_ctx = getattr(config, "LLM_CONTEXT_LINES", 30)
        target = max(1, min(line_number or 1, max(1, len(lines))))

        start_ln = max(1, target - (max_ctx // 2))
        end_ln = min(len(lines), start_ln + max_ctx - 1)

        # Prefer enclosing function/class if it fits inside max_ctx lines
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    n_start = getattr(node, "lineno", 1)
                    n_end = getattr(node, "end_lineno", n_start)
                    if n_start <= target <= n_end and (n_end - n_start + 1) <= max_ctx:
                        start_ln = n_start
                        end_ln = n_end
                        break
        except SyntaxError:
            pass

        numbered = [f"{ln}: {lines[ln - 1]}" for ln in range(start_ln, end_ln + 1)]
        snippet = "\n".join(numbered)

        # Extract symbol table summary via existing ASTContextExtractor
        symbols_summary = ""
        try:
            self.ast_extractor.parse(code)
            ctx_info = self.ast_extractor.get_context_at_line(target)
            vars_in_scope = ctx_info.get("variables_in_scope") or []
            enclosing_fn = ctx_info.get("enclosing_function")
            parts = []
            if enclosing_fn:
                parts.append(f"function={enclosing_fn}")
            if vars_in_scope:
                parts.append("vars=" + ", ".join(vars_in_scope[:20]))
            symbols_summary = "; ".join(parts)
        except Exception:
            pass

        return snippet, symbols_summary

    @staticmethod
    def _format_engine_tag(patch: Dict[str, Any]) -> str:
        """Map provider metadata to clean UI engine tag: Gemini, Local LLM (Ollama), or Rule-based."""
        prov_id = str(patch.get("_provider_id") or "").lower()
        prov = str(patch.get("_provider") or "")
        if prov_id == "gemini" or "gemini" in prov.lower():
            return "Gemini"
        if prov_id == "rules" or "rule" in prov.lower():
            return "Rule-based"
        return "Local LLM (Ollama)"

    def _is_trivial_typo_issue(self, working_code: str, issue: Dict[str, Any]) -> bool:
        """
        Return True when the AST rule engine has a high-confidence exact 'did you mean'
        typo match so we avoid unnecessary cloud Gemini calls.
        """
        etype = issue.get("type", "")
        msg = issue.get("message", "")
        ln = issue.get("line") or 1
        if etype == "NameError":
            m = re.search(r"name '(\w+)' is not defined", msg, re.IGNORECASE)
            bad = m.group(1) if m else issue.get("symbol")
            if bad and len(bad) >= 3:
                pool = self._collect_available_names(working_code, ln)
                user_vars = [n for n in pool if n not in BUILTIN_NAMES and n != bad]
                if difflib.get_close_matches(bad, user_vars, n=1, cutoff=0.72):
                    return True
                if difflib.get_close_matches(bad, [n for n in pool if n != bad], n=1, cutoff=0.75):
                    return True
        elif etype == "AttributeError":
            m = re.search(r"has no attribute '(\w+)'", msg)
            if m:
                bad_attr = m.group(1)
                lower_map = {cm.lower(): cm for cm in COMMON_METHODS}
                if bad_attr.lower() in lower_map:
                    return True
                if difflib.get_close_matches(bad_attr, COMMON_METHODS, n=1, cutoff=0.75):
                    return True
        return False

    def _generate_and_apply_issue_patch(
        self,
        working_code: str,
        original_code: str,
        issue: Dict[str, Any],
        ctx_snippet: str,
        sym_summary: str,
        llm_available: bool,
    ) -> Tuple[Optional[str], Dict[str, str], str]:
        """Try LLM minimal patch (Tier 1 Gemini -> Tier 2 Ollama -> Tier 3 Rules), with rule-based fast-path for trivial typos."""
        # Avoid unnecessary cloud calls for warnings, huge stress files (>500 lines),
        # or high-confidence single-token typos with exact 'did you mean' matches.
        prefer_rules_first = (
            issue["severity"] == "warning"
            or len(working_code.splitlines()) > 500
            or self._is_trivial_typo_issue(working_code, issue)
        )

        if prefer_rules_first:
            rb_code, rb_info = self._rule_based_patch_issue(working_code, issue)
            if rb_code and self._passes_security_egress(rb_code, original_code):
                return rb_code, rb_info, "Rule-based"

        if llm_available and self.ollama_client and hasattr(self.ollama_client, "generate_minimal_patch"):
            rejection_reason = ""
            for _attempt in range(2):
                patch = self.ollama_client.generate_minimal_patch(
                    error_type=issue["type"],
                    error_message=issue["message"],
                    line_number=issue["line"],
                    context_snippet=ctx_snippet,
                    symbols_summary=sym_summary,
                    rejection_reason=rejection_reason,
                )
                if not patch:
                    break
                patched, err_reason = self._apply_patch_strict(
                    working_code, patch, require_parse=True, original_code=original_code
                )
                if patched:
                    return patched, patch, self._format_engine_tag(patch)
                rejection_reason = err_reason

        # Tier 3: Rule-based AST fallback
        rb_code, rb_info = self._rule_based_patch_issue(working_code, issue)
        if rb_code and self._passes_security_egress(rb_code, original_code):
            return rb_code, rb_info, "Rule-based"

        return None, {}, "Rule-based"

    def _apply_patch_strict(
        self,
        code: str,
        patch: Dict[str, Any],
        require_parse: bool,
        original_code: str,
    ) -> Tuple[Optional[str], str]:
        """
        Apply a minimal JSON patch deterministically in Python and validate:
        1. Does not delete failing statement without replacement.
        2. Changes <= MAX_PATCH_LINES (default 3) lines.
        3. Passes ast.parse (when require_parse=True).
        4. Passes anti-trojan audit & import egress check.
        """
        old_str = str(patch.get("old") or "")
        new_str = str(patch.get("new") or "")
        target_line = int(patch.get("line") or 1)
        max_patch_lines = getattr(config, "MAX_PATCH_LINES", 3)

        # Reject deleting the failing statement without replacement
        if old_str.strip() and not new_str.strip():
            return None, "Patch deleted the failing statement without replacement"
        if not new_str.strip():
            return None, "Patch produced empty replacement"

        # Strip accidental line-number prefixes like "12: code" from small LLM output
        old_clean = re.sub(r"^\s*\d+:\s?", "", old_str)
        new_clean = re.sub(r"^\s*\d+:\s?", "", new_str)

        lines = code.split("\n")
        idx = max(0, min(target_line - 1, len(lines) - 1))

        new_code: Optional[str] = None
        if old_clean and old_clean in code:
            # Prefer replacing the occurrence nearest target_line
            if old_clean in lines[idx]:
                new_lines = list(lines)
                new_lines[idx] = lines[idx].replace(old_clean, new_clean, 1)
                new_code = "\n".join(new_lines)
            elif old_clean.strip() and old_clean.strip() in lines[idx]:
                indent = re.match(r"^(\s*)", lines[idx]).group(1)
                rep = new_clean if new_clean.startswith((" ", "\t")) else indent + new_clean.lstrip()
                new_lines = list(lines)
                new_lines[idx] = rep
                new_code = "\n".join(new_lines)
            else:
                new_code = code.replace(old_clean, new_clean, 1)
        elif 0 <= idx < len(lines):
            # Fallback: replace target_line preserving indentation
            indent = re.match(r"^(\s*)", lines[idx]).group(1)
            rep_lines = new_clean.splitlines()
            if len(rep_lines) <= max_patch_lines:
                formatted = [
                    (rl if rl.startswith((" ", "\t")) else indent + rl.lstrip())
                    for rl in rep_lines
                ]
                new_lines = lines[:idx] + formatted + lines[idx + 1:]
                new_code = "\n".join(new_lines)

        if not new_code or new_code == code:
            return None, "Patch did not modify target code"

        # Verify line-change budget (<= MAX_PATCH_LINES)
        changed_lines = self._count_changed_lines(code, new_code)
        if changed_lines > max_patch_lines:
            return None, f"Patch modified {changed_lines} lines (max {max_patch_lines})"

        # Verify ast.parse
        if require_parse:
            try:
                ast.parse(new_code)
            except SyntaxError as e:
                return None, f"Patched code failed ast.parse: {e.msg}"

        # Anti-trojan & import egress security audit
        if not self._passes_security_egress(new_code, original_code):
            return None, "Patch rejected by anti-trojan / import egress security guard"

        return new_code, ""

    def _passes_security_egress(self, candidate_code: str, original_code: str) -> bool:
        """Run anti-trojan audit and import egress check on every candidate patch."""
        try:
            audit = self.aai_guard.audit_healed_code(candidate_code, original_code=original_code)
            if not audit.is_safe:
                return False
        except Exception:
            pass

        is_safe_ast, _ = self.validator.validate(candidate_code)
        if not is_safe_ast:
            return False

        # Import egress check: disallow introducing unauthorized new modules
        try:
            cand_tree = ast.parse(candidate_code)
        except SyntaxError:
            return False

        orig_imports: Set[str] = set()
        try:
            orig_tree = ast.parse(original_code)
            for node in ast.walk(orig_tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        orig_imports.add(a.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    orig_imports.add(node.module.split(".")[0])
        except SyntaxError:
            # Original code had a SyntaxError (fixed in Pass 1) -> preserve user's existing imports via regex
            for imp_m in re.finditer(r"^[ \t]*import[ \t]+([\w., \t]+)", original_code, re.MULTILINE):
                for part in imp_m.group(1).split(","):
                    tokens = part.strip().split()
                    if tokens:
                        orig_imports.add(tokens[0].split(".")[0])
            for from_m in re.finditer(r"^[ \t]*from[ \t]+([\w.]+)[ \t]+import\b", original_code, re.MULTILINE):
                mod = from_m.group(1).split(".")[0]
                if mod:
                    orig_imports.add(mod)

        for node in ast.walk(cand_tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    root = a.name.split(".")[0]
                    if root not in orig_imports and root not in SAFE_PERMITTED_NEW_MODULES:
                        return False
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root not in orig_imports and root not in SAFE_PERMITTED_NEW_MODULES:
                    return False

        return True

    def _rule_based_patch_issue(
        self, code: str, issue: Dict[str, Any]
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """Deterministic rule-based AST patcher for errors and warnings."""
        lines = code.split("\n")
        ln = issue.get("line") or 1
        if not (1 <= ln <= len(lines)):
            return None, {}

        idx = ln - 1
        target = lines[idx]
        code_part, sep, comment_part = target.partition("#")
        suffix = f"#{comment_part}" if sep else ""
        err_type = issue.get("type", "")
        msg = issue.get("message", "")

        try:
            # 1. TypeError (str + int/float, uncalled builtin, arg count)
            if err_type == "TypeError":
                if "builtin_function_or_method" in msg or "function" in msg:
                    fixed = re.sub(r"\babs\s*(\+|\-|\*|\/)", r"abs(-5) \1", code_part)
                    fixed = re.sub(r"\blen\s*(\+|\-|\*|\/)", r"len([1, 2]) \1", fixed)
                    if fixed != code_part:
                        return self._replace_line(lines, idx, fixed + suffix, f"Called builtin function before arithmetic on line {ln}.")

                if "+" in code_part:
                    # Case A: "text" + expr  OR  expr + "text"
                    fixed = self._fix_str_concat_line(code_part)
                    if fixed != code_part:
                        return self._replace_line(
                            lines,
                            idx,
                            fixed + suffix,
                            f"Converted non-string operand with str() before string concatenation on line {ln}.",
                        )

            # 2. KeyError -> safe .get(key, default)
            elif err_type == "KeyError":
                # Choose sensible default based on line usage (arithmetic -> 0, string concat -> "", else None)
                default_val = "0" if re.search(r"(\+=|\-=|\*=|\+|\-|\*|/)", code_part) else '""'
                if re.search(r"['\"].*['\"]\s*\+", code_part) or re.search(r"\+\s*['\"]", code_part):
                    default_val = '""'
                # Extract exact missing key if present in message
                fixed = re.sub(
                    r"(\b[a-zA-Z_]\w*)\[\s*([^\]]+)\s*\]",
                    rf"\1.get(\2, {default_val})",
                    code_part,
                    count=1,
                )
                if fixed != code_part:
                    return self._replace_line(
                        lines,
                        idx,
                        fixed + suffix,
                        f"Used dict.get() with a safe default value to prevent KeyError on line {ln}.",
                    )

            # 3. IndexError -> fix range(len(x) + 1) off-by-one loop OR out-of-range literal index
            elif err_type == "IndexError":
                # Check enclosing `for ... in range(len(...) + 1):` up to 8 lines above!
                for back in range(0, min(9, idx + 1)):
                    check_i = idx - back
                    check_line = lines[check_i]
                    c_part, c_sep, c_comm = check_line.partition("#")
                    c_suf = f"#{c_comm}" if c_sep else ""
                    if re.search(r"range\s*\(.+\+\s*1\s*\)", c_part):
                        fixed_loop = re.sub(r"(range\s*\(.+?)\s*\+\s*1(\s*\))", r"\1\2", c_part, count=1)
                        if fixed_loop != c_part:
                            return self._replace_line(
                                lines,
                                check_i,
                                fixed_loop + c_suf,
                                f"Removed '+ 1' off-by-one bound in range() on line {check_i + 1} so index stays within list bounds.",
                            )
                # Literal out-of-range index like items[10] -> items[0]
                fixed = re.sub(r"\[\s*-?\d+\s*\]", "[0]", code_part, count=1)
                if fixed != code_part:
                    return self._replace_line(
                        lines,
                        idx,
                        fixed + suffix,
                        f"Adjusted out-of-bounds index on line {ln} to valid index [0].",
                    )

            # 4. UnboundLocalError -> insert `global var` if global exists, else initialize `var = 0`
            elif err_type == "UnboundLocalError":
                m = re.search(r"local variable '(\w+)'", msg)
                var_name = m.group(1) if m else issue.get("symbol")
                if var_name:
                    fn_info = self._find_enclosing_function(code, ln)
                    if fn_info is not None:
                        fn_node, body_start_idx, body_indent = fn_info
                        is_module_var = self._is_defined_at_module_level(code, var_name)
                        insert_stmt = f"{body_indent}global {var_name}" if is_module_var else f"{body_indent}{var_name} = 0"
                        new_lines = list(lines)
                        new_lines.insert(body_start_idx, insert_stmt)
                        patched = "\n".join(new_lines)
                        ast.parse(patched)
                        expl = (
                            f"Declared 'global {var_name}' inside '{fn_node.name}()' so Python modifies the module-level variable."
                            if is_module_var
                            else f"Initialized local variable '{var_name} = 0' before use inside '{fn_node.name}()'."
                        )
                        return patched, {
                            "old": lines[body_start_idx] if body_start_idx < len(lines) else target,
                            "new": insert_stmt,
                            "explanation": expl,
                            "hint": f"In Python, assigning to '{var_name}' inside a function makes it local unless declared global or initialized first.",
                        }

            # 5. AttributeError -> fix misspelled method/attribute (e.g. .titel -> .title, .arra -> .array, .dataframe -> .DataFrame)
            elif err_type == "AttributeError":
                m = re.search(r"has no attribute '(\w+)'", msg)
                if m:
                    bad_attr = m.group(1)
                    lower_map = {cm.lower(): cm for cm in COMMON_METHODS}
                    best = lower_map.get(bad_attr.lower())
                    if not best:
                        matches = difflib.get_close_matches(bad_attr, COMMON_METHODS, n=1, cutoff=0.6)
                        if not matches:
                            l_matches = difflib.get_close_matches(bad_attr.lower(), list(lower_map.keys()), n=1, cutoff=0.6)
                            best = lower_map[l_matches[0]] if l_matches else None
                        else:
                            best = matches[0]
                    if best and best != bad_attr:
                        fixed = re.sub(r"\." + re.escape(bad_attr) + r"\b", "." + best, code_part)
                        if fixed != code_part:
                            return self._replace_line(
                                lines,
                                idx,
                                fixed + suffix,
                                f"Corrected misspelled attribute '.{bad_attr}' to '.{best}' on line {ln}.",
                            )

            # 6. ZeroDivisionError -> handle literal / 0, sum(x)/len(x), or variable divisor
            elif err_type == "ZeroDivisionError":
                # 6a. Literal / 0 -> / 2
                fixed = re.sub(r"(//|/|%)\s*0(?![.\d])", r"\1 2", code_part)
                # 6b. / len(expr) -> / (len(expr) or 1)
                if fixed == code_part and re.search(r"(//|/|%)\s*len\s*\([^)]+\)", code_part):
                    fixed = re.sub(r"(//|/|%)\s*(len\s*\([^)]+\))", r"\1 (\2 or 1)", code_part, count=1)
                # 6c. / var_name -> / (var_name or 1)
                if fixed == code_part:
                    fixed = re.sub(r"(//|/|%)\s*([a-zA-Z_]\w*)", r"\1 (\2 or 1)", code_part, count=1)
                if fixed != code_part:
                    return self._replace_line(
                        lines,
                        idx,
                        fixed + suffix,
                        f"Guarded against division by zero on line {ln}.",
                    )

            # 7. NameError -> reorder later def, typo match (totl -> total, prnt -> print), or initialize
            elif err_type == "NameError":
                m = re.search(r"name '(\w+)' is not defined", msg, re.IGNORECASE)
                bad_name = m.group(1) if m else issue.get("symbol")
                if bad_name:
                    # 7a. Check if defined on a later line at same indentation
                    target_indent = re.match(r"^(\s*)", target).group(1)
                    for later_i in range(idx + 1, len(lines)):
                        if re.match(r"^" + re.escape(target_indent) + re.escape(bad_name) + r"\s*=", lines[later_i]):
                            new_lines = list(lines)
                            def_line = new_lines.pop(later_i)
                            new_lines.insert(idx, def_line)
                            patched = "\n".join(new_lines)
                            ast.parse(patched)
                            return patched, {
                                "old": target,
                                "new": def_line + "\n" + target,
                                "explanation": f"Moved assignment of '{bad_name}' above its first usage on line {ln}.",
                                "hint": f"'{bad_name}' must be defined before line {ln}.",
                            }

                    # 7b. Typo match against all defined variables in scope + module + builtins
                    scope_pool = self._collect_available_names(code, ln)
                    # Filter builtins that don't make sense when not called
                    if "(" not in code_part:
                        candidates = [n for n in scope_pool if n not in ("print", "len", "range", "open", "sum", "min", "max")]
                    else:
                        candidates = list(scope_pool)
                    # Prefer user-defined identifiers over builtins first!
                    user_vars = [n for n in candidates if n not in BUILTIN_NAMES and n != bad_name]
                    matches = difflib.get_close_matches(bad_name, user_vars, n=1, cutoff=0.65)
                    if not matches:
                        matches = difflib.get_close_matches(bad_name, [n for n in candidates if n != bad_name], n=1, cutoff=0.68)

                    if matches:
                        best = matches[0]
                        fixed = re.sub(r"\b" + re.escape(bad_name) + r"\b", best, code_part)
                        if fixed != code_part:
                            return self._replace_line(
                                lines,
                                idx,
                                fixed + suffix,
                                f"Corrected undefined name '{bad_name}' to '{best}' on line {ln}.",
                            )

                    # 7c. Truly undefined variable -> initialize before failing line
                    new_lines = list(lines)
                    # If used as a dictionary key (e.g. `{b: "j"}`), initialize as a string key
                    if re.search(r"[\{,]\s*" + re.escape(bad_name) + r"\s*:", code_part):
                        init_line = f'{target_indent}{bad_name} = "{bad_name}"  # Initialized key variable'
                    else:
                        init_line = f"{target_indent}{bad_name} = 0  # Initialized variable"
                    new_lines.insert(idx, init_line)
                    patched = "\n".join(new_lines)
                    ast.parse(patched)
                    return patched, {
                        "old": target,
                        "new": init_line + "\n" + target,
                        "explanation": f"Initialized undefined variable '{bad_name}' before line {ln}.",
                        "hint": f"Define '{bad_name}' before referencing it.",
                    }

            # 7.5 ModuleNotFoundError / ImportError -> common alias mistakes (import np -> import numpy as np)
            elif err_type in ("ModuleNotFoundError", "ImportError"):
                m_mod = re.search(r"No module named '([^']+)'", msg)
                bad_mod = m_mod.group(1).split(".")[0] if m_mod else ""
                alias_map = {
                    "np": ("numpy", "np"),
                    "pd": ("pandas", "pd"),
                    "plt": ("matplotlib.pyplot", "plt"),
                    "sns": ("seaborn", "sns"),
                    "sp": ("scipy", "sp"),
                    "tf": ("tensorflow", "tf"),
                    "nx": ("networkx", "nx"),
                    "sk": ("sklearn", "sk"),
                }
                indent = re.match(r"^(\s*)", target).group(1)
                if bad_mod in alias_map:
                    real_mod, alias = alias_map[bad_mod]
                    fixed = f"{indent}import {real_mod} as {alias}{suffix}"
                    return self._replace_line(
                        lines,
                        idx,
                        fixed,
                        f"Replaced invalid 'import {bad_mod}' with standard 'import {real_mod} as {alias}' on line {ln}.",
                    )
                if bad_mod:
                    safe_known = sorted(SAFE_PERMITTED_NEW_MODULES)
                    m_close = difflib.get_close_matches(bad_mod.lower(), safe_known, n=1, cutoff=0.65)
                    if m_close:
                        real_mod = m_close[0]
                        fixed = re.sub(r"\b" + re.escape(bad_mod) + r"\b", real_mod, code_part, count=1)
                        if fixed != code_part:
                            return self._replace_line(
                                lines,
                                idx,
                                fixed + suffix,
                                f"Corrected misspelled module '{bad_mod}' to '{real_mod}' on line {ln}.",
                            )

            # 7.6 ValueError -> Pandas scalar DataFrame missing index
            elif err_type == "ValueError":
                if "If using all scalar values, you must pass an index" in msg and "DataFrame(" in code_part:
                    close_pos = code_part.rfind(")")
                    if close_pos != -1:
                        fixed = code_part[:close_pos] + ", index=[0]" + code_part[close_pos:]
                        return self._replace_line(
                            lines,
                            idx,
                            fixed + suffix,
                            f"Added 'index=[0]' to pd.DataFrame() with scalar dictionary values on line {ln}.",
                        )

            # 8. TimeoutError -> convert infinite while True loop to bounded loop
            elif err_type == "TimeoutError":
                for check_i in range(idx, max(-1, idx - 5), -1):
                    if re.match(r"^\s*while\s+True\s*:", lines[check_i]):
                        indent = re.match(r"^(\s*)", lines[check_i]).group(1)
                        fixed_header = f"{indent}for _ in range(5):  # Bounded loop"
                        return self._replace_line(
                            lines,
                            check_i,
                            fixed_header,
                            f"Replaced infinite 'while True:' loop at line {check_i + 1} with a bounded loop.",
                        )
                # Check unincremented `while var < N:`
                for check_i in range(idx, max(-1, idx - 5), -1):
                    m_w = re.match(r"^(\s*)while\s+([a-zA-Z_]\w*)\s*<\s*.+:", lines[check_i])
                    if m_w:
                        indent = m_w.group(1)
                        var_nm = m_w.group(2)
                        new_lines = list(lines)
                        new_lines.insert(check_i + 1, f"{indent}    {var_nm} += 1")
                        patched = "\n".join(new_lines)
                        ast.parse(patched)
                        return patched, {
                            "old": lines[check_i],
                            "new": lines[check_i] + f"\n{indent}    {var_nm} += 1",
                            "explanation": f"Added loop counter increment '{var_nm} += 1' so the while loop terminates.",
                            "hint": f"Ensure '{var_nm}' progresses toward the loop exit condition.",
                        }

            # 9. Warnings (only invoked when fix_warnings=True)
            elif err_type == "UnusedImport":
                fixed = f"# Removed unused import: {target.strip()}"
                return self._replace_line(lines, idx, fixed, f"Removed unused import on line {ln}.")

            elif err_type == "UnusedVariable":
                fixed = f"# Unused: {target.strip()}"
                return self._replace_line(lines, idx, fixed, f"Commented out unused variable assignment on line {ln}.")

            elif err_type == "BareExcept":
                fixed = re.sub(r"except\s*:", "except Exception:", code_part)
                if fixed != code_part:
                    return self._replace_line(lines, idx, fixed + suffix, f"Narrowed bare 'except:' to 'except Exception:' on line {ln}.")

            elif err_type == "MutableDefault":
                m_def = re.search(r"(\w+)\s*=\s*(\[\]|\{\}|set\(\))", code_part)
                if m_def:
                    p_name, p_lit = m_def.group(1), m_def.group(2)
                    fixed_sig = code_part.replace(m_def.group(0), f"{p_name}=None", 1) + suffix
                    fn_info = self._find_enclosing_function(code, ln)
                    new_lines = list(lines)
                    new_lines[idx] = fixed_sig
                    if fn_info is not None:
                        _, body_start, body_indent = fn_info
                        new_lines.insert(body_start, f"{body_indent}if {p_name} is None: {p_name} = {p_lit}")
                    patched = "\n".join(new_lines)
                    ast.parse(patched)
                    return patched, {
                        "old": target,
                        "new": fixed_sig,
                        "explanation": f"Replaced mutable default '{p_name}={p_lit}' with None and initialized inside the function.",
                        "hint": "Default arguments are evaluated once at function definition time.",
                    }

            elif err_type == "MissingReturn":
                fn_info = self._find_enclosing_function(code, ln)
                if fn_info is not None:
                    fn_node, _, body_indent = fn_info
                    end_ln = getattr(fn_node, "end_lineno", ln)
                    new_lines = list(lines)
                    new_lines.insert(end_ln, f"{body_indent}return None")
                    patched = "\n".join(new_lines)
                    ast.parse(patched)
                    return patched, {
                        "old": lines[end_ln - 1],
                        "new": lines[end_ln - 1] + f"\n{body_indent}return None",
                        "explanation": f"Added explicit fallback 'return None' at the end of '{fn_node.name}()'.",
                        "hint": "Ensure every execution path through the function has an explicit return.",
                    }

        except Exception:
            pass

        return None, {}

    @staticmethod
    def _replace_line(lines: List[str], idx: int, new_line: str, explanation: str) -> Tuple[Optional[str], Dict[str, str]]:
        old_line = lines[idx]
        new_lines = list(lines)
        new_lines[idx] = new_line
        patched = "\n".join(new_lines)
        ast.parse(patched)
        return patched, {
            "old": old_line,
            "new": new_line,
            "explanation": explanation,
        }

    @staticmethod
    def _fix_str_concat_line(code_part: str) -> str:
        """Safely wrap non-string operands in str(...) for string concatenation."""
        # Case 1: "..." + expr  (e.g. "Total: " + price  or  "Val: " + str_needed)
        if re.search(r"['\"]\s*\+", code_part):
            fixed = re.sub(
                r"(\+\s*)(?!str\()([a-zA-Z_]\w*(?:\([^)]*\)|\[[^\]]*\])?|\d+(?:\.\d+)?)",
                r"\1str(\2)",
                code_part,
            )
            if fixed != code_part:
                return fixed
        # Case 2: expr + "..."
        if re.search(r"\+\s*['\"]", code_part):
            fixed = re.sub(
                r"(?<!str\()(\b[a-zA-Z_]\w*(?:\([^)]*\)|\[[^\]]*\])?|\b\d+(?:\.\d+)?)(\s*\+\s*['\"])",
                r"str(\1)\2",
                code_part,
                count=1,
            )
            if fixed != code_part:
                return fixed
        # Case 3: variable + variable (e.g. label + amount) -> str(a) + str(b) on RHS of '=' or inside print()
        fixed = re.sub(r"(\+\s*)(?!str\()([a-zA-Z_]\w*)", r"\1str(\2)", code_part, count=1)
        return fixed

    @staticmethod
    def _find_enclosing_function(code: str, lineno: int) -> Optional[Tuple[ast.AST, int, str]]:
        """Return (fn_node, body_start_0based_idx, body_indent_str) for function containing lineno."""
        try:
            tree = ast.parse(code)
            lines = code.split("\n")
            best = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    s = getattr(node, "lineno", 1)
                    e = getattr(node, "end_lineno", s)
                    if s <= lineno <= e:
                        best = node
            if best and best.body:
                first_body_idx = best.body[0].lineno - 1
                body_indent = re.match(r"^(\s*)", lines[first_body_idx]).group(1)
                return best, first_body_idx, body_indent
        except Exception:
            pass
        return None

    @staticmethod
    def _is_defined_at_module_level(code: str, var_name: str) -> bool:
        try:
            tree = ast.parse(code)
            for stmt in tree.body:
                if isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if var_name in StaticASTScanner._target_names(t):
                            return True
                elif isinstance(stmt, ast.AnnAssign):
                    if var_name in StaticASTScanner._target_names(stmt.target):
                        return True
        except Exception:
            pass
        return False

    @staticmethod
    def _collect_available_names(code: str, lineno: int) -> Set[str]:
        names: Set[str] = set(BUILTIN_NAMES)
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    names.add(node.id)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(node.name)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        s = getattr(node, "lineno", 1)
                        e = getattr(node, "end_lineno", s)
                        if s <= lineno <= e:
                            for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                                names.add(a.arg)
        except Exception:
            pass
        return names

    def _count_non_cascade_errors(self, code: str, stdin_data: str) -> int:
        res = self.error_capture.execute_resilient(
            code,
            stdin_data=stdin_data,
            total_timeout=config.TOTAL_SANDBOX_TIMEOUT,
            per_stmt_timeout=config.PER_STATEMENT_TIMEOUT,
        )
        return sum(1 for x in res.get("issues", []) if x.get("cascade_of") is None)

    def _verify_patch_in_sandbox(
        self,
        working_code: str,
        patched_code: Optional[str],
        issue: Dict[str, Any],
        pre_errors: int,
        stdin_data: str,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Verify a candidate patch in the sandbox via Pass 2.
        Rejects any patch that leaves the target line failing (even with a different
        error type such as NameError -> TypeError) or increases non-cascade errors.
        """
        if not patched_code or patched_code == working_code:
            return False, None

        post_res = self.error_capture.execute_resilient(
            patched_code,
            stdin_data=stdin_data,
            total_timeout=config.TOTAL_SANDBOX_TIMEOUT,
            per_stmt_timeout=config.PER_STATEMENT_TIMEOUT,
        )
        if post_res.get("blocked"):
            return False, post_res

        post_non_cascade = [x for x in post_res.get("issues", []) if x.get("cascade_of") is None]
        if issue.get("severity") == "warning":
            return len(post_non_cascade) <= pre_errors, post_res

        line_delta = len(patched_code.splitlines()) - len(working_code.splitlines())
        target_ln = issue.get("line") or 1
        target_lines = {target_ln, target_ln + line_delta}
        same_issue_still_present = any(
            x.get("type") == issue.get("type") and x.get("line") in target_lines
            for x in post_non_cascade
        )
        # Allow spelling/definition/import fixes to reveal genuine downstream argument/value errors
        # on the same line (e.g. pd.dataframe -> pd.DataFrame revealing ValueError, or defining `b` in
        # pd.DataFrame({b:"j"}) revealing scalar-index ValueError), while still blocking hallucinated
        # regressions (such as NameError -> TypeError from `'z' in vars`).
        same_line_errs = [x for x in post_non_cascade if x.get("line") in target_lines]
        if issue.get("type") in ("AttributeError", "NameError", "ModuleNotFoundError", "ImportError"):
            same_line_regression = any(
                x.get("type") in ("AttributeError", "SyntaxError", "NameError", "ModuleNotFoundError", "ImportError", "TypeError")
                for x in same_line_errs
            )
        else:
            same_line_regression = bool(same_line_errs)

        # Fixing an import/module error can unblock previously-cascaded downstream lines so their
        # genuine errors become visible; allow that as long as the target line itself is now clean.
        unblocks_downstream = issue.get("type") in ("ModuleNotFoundError", "ImportError")
        count_ok = (len(post_non_cascade) <= max(pre_errors, 1)) or (
            unblocks_downstream and all((x.get("line") or 0) > target_ln + line_delta for x in post_non_cascade)
        )

        if not same_line_regression and not same_issue_still_present and count_ok:
            return True, post_res
        return False, post_res

    @staticmethod
    def _count_changed_lines(old_code: str, new_code: str) -> int:
        old_l = old_code.splitlines()
        new_l = new_code.splitlines()
        sm = difflib.SequenceMatcher(None, old_l, new_l)
        changed = 0
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != "equal":
                changed += max(i2 - i1, j2 - j1)
        return changed

    # ─────────────────────────────────────────────────────────────
    # Helpers: Record Construction, Merging, Socratic Hints, Diff
    # ─────────────────────────────────────────────────────────────
    def _make_issue_record(self, raw: Dict[str, Any], status: str) -> Dict[str, Any]:
        etype = raw.get("type", "Error")
        ln = raw.get("line", 1)
        msg = raw.get("message", "")
        return {
            "id": 0,
            "type": etype,
            "line": ln,
            "severity": raw.get("severity", "error"),
            "message": msg,
            "explanation": self._default_explanation(etype, msg, ln),
            "hint": self._default_socratic_hints(etype, msg, ln)[0],
            "hints": self._default_socratic_hints(etype, msg, ln),
            "vague_description": self._vague_description(etype, ln),
            "patch": {"old": "", "new": ""},
            "status": status,
            "cascade_of": None,
            "engine": "Rule-based AST",
            "symbol": raw.get("symbol"),
        }

    def _make_dynamic_issue_record(self, dyn: Dict[str, Any]) -> Dict[str, Any]:
        etype = dyn.get("type", "RuntimeError")
        ln = dyn.get("line", 1)
        msg = dyn.get("message", "")
        cascade_of = dyn.get("cascade_of")
        return {
            "id": dyn.get("id", 0),
            "type": etype,
            "line": ln,
            "severity": "error",
            "message": msg,
            "explanation": (
                f"Cascade error caused by issue #{cascade_of}: a variable needed on line {ln} was never created because the earlier statement failed."
                if cascade_of is not None
                else self._default_explanation(etype, msg, ln)
            ),
            "hint": self._default_socratic_hints(etype, msg, ln)[0],
            "hints": self._default_socratic_hints(etype, msg, ln),
            "vague_description": self._vague_description(etype, ln),
            "patch": {"old": "", "new": ""},
            "status": "cascade" if cascade_of is not None else "open",
            "cascade_of": cascade_of,
            "engine": "Rule-based AST",
            "_dyn_id": dyn.get("id"),
            "_orig_cascade_dyn_id": cascade_of,
        }

    @staticmethod
    def _merge_static_and_dynamic(
        static_errors: List[Dict[str, Any]],
        dynamic_issues: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Combine static errors and dynamic runtime errors without duplicates on the same line."""
        merged = list(dynamic_issues)
        dyn_lines = {(d["line"], d["type"]) for d in dynamic_issues}
        dyn_any_line = {d["line"] for d in dynamic_issues}

        for st_err in static_errors:
            # Skip static NameError/UnboundLocalError if dynamic run already caught an exception on the same line
            if (st_err["line"], st_err["type"]) in dyn_lines or st_err["line"] in dyn_any_line:
                continue
            merged.append(st_err)

        merged.sort(key=lambda x: (x["line"] or 0, 0 if x["cascade_of"] is None else 1))
        return merged

    @staticmethod
    def _assign_issue_ids(issues: List[Dict[str, Any]]) -> None:
        """Assign clean sequential 1..N IDs and remap cascade_of references idempotently."""
        dyn_to_new: Dict[Any, int] = {}
        for idx, iss in enumerate(issues, 1):
            if "_dyn_id" in iss and iss["_dyn_id"] is not None:
                dyn_to_new.setdefault(iss["_dyn_id"], idx)
            iss["id"] = idx
        for iss in issues:
            orig_c = iss.get("_orig_cascade_dyn_id")
            if orig_c is None:
                orig_c = iss.get("cascade_of")
            if orig_c is not None and orig_c in dyn_to_new:
                new_parent = dyn_to_new[orig_c]
                iss["cascade_of"] = new_parent
                ln = iss.get("line", 1)
                iss["explanation"] = (
                    f"Cascade error caused by issue #{new_parent}: "
                    f"a variable needed on line {ln} was never created because the earlier statement failed."
                )

    def _build_final_report(
        self,
        original_code: str,
        fixed_code: str,
        issues: List[Dict[str, Any]],
        rounds_used: int,
        final_run: Dict[str, Any],
        verified: bool,
        llm_max_context_lines: int,
        mode: str,
        llm_available: bool,
    ) -> Dict[str, Any]:
        """Pass 4: Assemble structured report, unified diff, and Socratic hints."""
        # Enrich Socratic hints via diagnosis-only LLM call when in socratic mode (capped to avoid slowness)
        if mode == "socratic" and llm_available and self.ollama_client and hasattr(self.ollama_client, "generate_socratic_hint_for_issue"):
            for iss in issues[:5]:
                if iss["severity"] == "error" and iss["cascade_of"] is None:
                    ctx_s, _ = self._build_small_context(original_code, iss["line"])
                    llm_max_context_lines = max(llm_max_context_lines, len(ctx_s.splitlines()))
                    soc = self.ollama_client.generate_socratic_hint_for_issue(
                        error_type=iss["type"],
                        error_message=iss["message"],
                        line_number=iss["line"],
                        context_snippet=ctx_s,
                    )
                    if soc and soc.get("hints"):
                        iss["hints"] = soc["hints"]
                        iss["hint"] = soc["hints"][0]
                        if soc.get("vague_description"):
                            iss["vague_description"] = soc["vague_description"]

        diff_lines = list(
            difflib.unified_diff(
                original_code.splitlines(keepends=True),
                fixed_code.splitlines(keepends=True),
                fromfile="original.py",
                tofile="fixed.py",
                n=2,
            )
        )
        unified_diff = "".join(diff_lines)

        # Clean internal keys before returning
        clean_issues = []
        for iss in issues:
            clean_item = {k: v for k, v in iss.items() if not k.startswith("_") and k != "symbol"}
            clean_issues.append(clean_item)

        error_count = sum(1 for i in clean_issues if i["severity"] == "error" and i["cascade_of"] is None)
        warning_count = sum(1 for i in clean_issues if i["severity"] == "warning")
        cascade_count = sum(1 for i in clean_issues if i["cascade_of"] is not None)

        return {
            "blocked": False,
            "issues": clean_issues,
            "fixed_code": fixed_code,
            "diff": unified_diff,
            "rounds_used": rounds_used,
            "final_run": final_run,
            "error_count": error_count,
            "warning_count": warning_count,
            "cascade_count": cascade_count,
            "verified": verified,
            "llm_max_context_lines": llm_max_context_lines,
        }

    @staticmethod
    def _vague_description(error_type: str, line: int) -> str:
        templates = {
            "TypeError": f"An operation near line {line} combines incompatible data types or wrong arguments.",
            "KeyError": f"A dictionary lookup near line {line} could not find the requested key.",
            "IndexError": f"A sequence access near line {line} stepped outside valid index bounds.",
            "UnboundLocalError": f"A variable scope issue occurred inside a function near line {line}.",
            "AttributeError": f"An object near line {line} does not support the referenced method or attribute.",
            "ZeroDivisionError": f"An arithmetic division near line {line} encountered a zero denominator.",
            "NameError": f"An unrecognized identifier was referenced near line {line}.",
            "SyntaxError": f"The Python grammar near line {line} could not be parsed.",
            "TimeoutError": f"Execution stalled near line {line} without reaching a stop condition.",
            "UnusedImport": f"An imported module on line {line} is not used.",
            "UnusedVariable": f"A variable assigned on line {line} is never read.",
            "MissingReturn": f"A function starting at line {line} may exit without returning a value.",
            "MutableDefault": f"A function header at line {line} uses a mutable default argument.",
            "BareExcept": f"An exception handler at line {line} catches every exception unconditionally.",
        }
        return templates.get(error_type, f"An issue ({error_type}) was detected near line {line}.")

    @staticmethod
    def _default_explanation(error_type: str, message: str, line: int) -> str:
        return f"{error_type} at line {line}: {message}"

    @staticmethod
    def _default_socratic_hints(error_type: str, message: str, line: int) -> List[str]:
        by_type = {
            "TypeError": [
                f"Inspect the data types of every value used on line {line}.",
                "Python does not implicitly convert numbers to strings during '+' concatenation.",
                "Explicitly convert the non-string value before combining it with text.",
            ],
            "KeyError": [
                f"Look closely at which dictionary key is being accessed on line {line}.",
                "Indexing with dict[key] raises KeyError whenever that key is absent.",
                "Consider checking membership first or using the dictionary .get() method with a default.",
            ],
            "IndexError": [
                f"Compare the loop or index bounds around line {line} with the length of the collection.",
                "Valid Python indices run from 0 through len(seq) - 1.",
                "Check whether a range() call or hardcoded index goes past the last element.",
            ],
            "UnboundLocalError": [
                f"Check where the variable on line {line} is assigned inside the function.",
                "Assigning to a name anywhere inside a function marks it as local throughout that function.",
                "Either initialize the local variable before reading it, or declare it global if modifying a module variable.",
            ],
            "AttributeError": [
                f"Check the spelling of the method or attribute called on line {line}.",
                "Verify what type of object is on the left side of the dot operator.",
                "Match the attribute name against the standard Python methods for that type.",
            ],
            "ZeroDivisionError": [
                f"Check the denominator expression on line {line}.",
                "What happens if the list is empty or the divisor variable evaluates to 0?",
                "Guard the division so it handles a zero denominator safely.",
            ],
            "NameError": [
                f"Check the spelling and definition order of every identifier on line {line}.",
                "Variables and functions must be defined before they are referenced.",
                "Compare the failing identifier against previously defined variable names in scope.",
            ],
            "TimeoutError": [
                f"Inspect the loop or recursion near line {line}.",
                "Determine whether the exit condition can ever become False.",
                "Add a termination condition or counter update so the loop finishes.",
            ],
        }
        return by_type.get(error_type, [
            f"Inspect the code around line {line} carefully.",
            f"Read the error symptom: {error_type}.",
            "Verify the inputs, types, and control flow on that line.",
        ])


def analyze_all(
    code: str,
    mode: str = "direct",
    stdin_data: str = "",
    fix_warnings: bool = False,
    use_ai: bool = True,
    progress_callback: Optional[Callable[[int, int, int, str], None]] = None,
    ollama_client: Optional[Any] = None,
) -> Dict[str, Any]:
    """Convenience entry point for the 4-pass multi-error repair loop."""
    loop = RepairLoop(use_ai=use_ai, ollama_client=ollama_client)
    return loop.analyze_all(
        code=code,
        mode=mode,
        stdin_data=stdin_data,
        fix_warnings=fix_warnings,
        progress_callback=progress_callback,
    )
