import os
import re
import ast
from typing import Optional, Dict, List
from dataclasses import dataclass, field

try:
    from .error_capture import ErrorCapture
    from .ast_parser import ASTContextExtractor
    from .gemini_client import GeminiErrorExplainer
    from .fallback import FallbackExplainer
    from .model import ErrorExplainerModel
    from .code_analyzer import CodeHealthAnalyzer, CodeHealthReport
    from .security import SecurityWarning
    from .aai_security_guard import AAISecurityGuard, ThreatCategory, RiskLevel
except ImportError:
    from error_capture import ErrorCapture
    from ast_parser import ASTContextExtractor
    from gemini_client import GeminiErrorExplainer
    from fallback import FallbackExplainer
    try:
        from model import ErrorExplainerModel
    except ImportError:
        ErrorExplainerModel = None
    try:
        from code_analyzer import CodeHealthAnalyzer, CodeHealthReport
    except ImportError:
        CodeHealthAnalyzer = None
        CodeHealthReport = None
    try:
        from security import SecurityWarning
        from aai_security_guard import AAISecurityGuard, ThreatCategory, RiskLevel
    except ImportError:
        SecurityWarning = None
        AAISecurityGuard = None

try:
    from .multi_agent_system import CompilerOrchestratorAgent, CompilerPhase, BaseCompilerAgent
except ImportError:
    try:
        from multi_agent_system import CompilerOrchestratorAgent, CompilerPhase, BaseCompilerAgent
    except ImportError:
        CompilerOrchestratorAgent = None
        CompilerPhase = None
        BaseCompilerAgent = None


@dataclass
class ExplanationResult:
    """Result from the error explanation pipeline."""
    success: bool
    error_type: Optional[str]
    raw_error: Optional[str]
    friendly_explanation: Optional[str]
    suggested_fix: Optional[str]
    code_context: Optional[str]
    line_number: Optional[int]
    similar_names: list
    security_warnings: list
    ai_used: bool = False
    engine_used: str = "gemini"  # "gemini", "t5_local", "fallback", "security_gate", "execution_success", "aai_security_guard"
    health_report: Optional[object] = None
    concept: Optional[str] = None
    corrected_code: Optional[str] = None
    prevention_tip: Optional[str] = None
    hint_mode: bool = False
    socratic_question: Optional[str] = None
    progressive_hints: list = field(default_factory=list)
    fix_verified: bool = False
    fix_verification_attempts: int = 0
    risk_level: Optional[str] = None
    risk_score: float = 0.0
    attack_category: Optional[str] = None
    compiler_phase: Optional[str] = None
    agent_name: Optional[str] = None


class AIErrorTutor:
    """Main pipeline for AI-powered error explanations with multi-tier fallback."""

    def __init__(self, model_path: Optional[str] = None, use_ai: bool = True, use_t5_bridge: bool = True):
        """
        Initialize the AI Error Tutor.

        Args:
            model_path: Optional path to local fine-tuned T5 model
            use_ai: Whether to attempt Gemini first
            use_t5_bridge: Whether to use local T5 model as fallback when Gemini is unavailable
        """
        self.error_capture = ErrorCapture()
        self.ast_extractor = ASTContextExtractor()
        self.fallback = FallbackExplainer()
        self.health_analyzer = CodeHealthAnalyzer() if CodeHealthAnalyzer else None

        self.use_ai = use_ai
        self.use_t5_bridge = use_t5_bridge
        self.gemini_model = None
        self.t5_model = None
        self.aai_guard = AAISecurityGuard() if AAISecurityGuard else None
        self.orchestrator = CompilerOrchestratorAgent() if CompilerOrchestratorAgent else None
        self.t5_path = model_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "models",
            "error_tutor_model"
        )

        # Initialize Tier 1: Gemini AI
        if use_ai:
            try:
                self.gemini_model = GeminiErrorExplainer()
                print("[OK] Gemini AI configured successfully")
            except Exception as e:
                print(f"[INFO] Gemini API not active: {e}")
                self.gemini_model = None

    def _get_or_load_t5_model(self) -> Optional[object]:
        """Lazy load the local T5 model if available."""
        if self.t5_model is not None:
            return self.t5_model

        if not self.use_t5_bridge or ErrorExplainerModel is None:
            return None

        try:
            load_target = self.t5_path if os.path.exists(self.t5_path) else "t5-small"
            print(f"Loading local T5 model bridge from: {load_target}...")
            self.t5_model = ErrorExplainerModel(load_target)
            print("[OK] Local T5 Model Bridge initialized successfully")
            return self.t5_model
        except Exception as e:
            print(f"[WARN] Local T5 model could not be loaded: {e}")
            return None

    def analyze_code(self, code: str, mode: str = "direct", **kwargs) -> ExplanationResult:
        """
        Analyze code and provide friendly error explanations.

        Args:
            code: Python code to analyze
            mode: "direct" or "socratic"

        Returns:
            ExplanationResult with error details and friendly explanation
        """
        # Step -0.5: Enforce strict input size limits
        if len(code) > 10000:
            return ExplanationResult(
                success=False,
                error_type="SecurityError",
                raw_error="Input payload exceeds 10,000 character limit.",
                friendly_explanation="The submitted code exceeds the safety limit of 10,000 characters. Please submit a smaller snippet.",
                suggested_fix="Reduce the size of your code snippet to under 10,000 characters.",
                code_context=code[:120] if code else "",
                line_number=1,
                similar_names=[],
                security_warnings=[],
                ai_used=False,
                engine_used="security_gate",
                health_report=None,
                concept="Resource Limiting",
                prevention_tip="Keep learning snippets concise and focused on single functions or logic units.",
                risk_level="HIGH",
                risk_score=75.0,
                attack_category="resource_dos"
            )

        # Step 0: Ingress Agentic AI Security Inspection (Prompt Injection, Policy Bypass, Exploits)
        if self.aai_guard:
            ingress_assessment = self.aai_guard.assess_input(code, target_type="code")
            if not ingress_assessment.is_safe:
                sec_warnings = [
                    SecurityWarning(
                        level='BLOCKED',
                        category=f.category.value if hasattr(f.category, 'value') else str(f.category),
                        message=f"[{f.severity.value if hasattr(f.severity, 'value') else str(f.severity)}] {f.description} (Pattern: {f.matched_snippet})",
                        line_number=1,
                        code_snippet=f.matched_snippet
                    )
                    for f in ingress_assessment.findings
                ]
                health_report = self.health_analyzer.analyze(code, sec_warnings) if self.health_analyzer else None
                return ExplanationResult(
                    success=False,
                    error_type="AttackBlocked",
                    raw_error=f"AAI Security Guard Quarantined Request: {ingress_assessment.primary_category.value}",
                    friendly_explanation=(
                        f"SECURITY ALERT [{ingress_assessment.risk_level.value} - Threat Score: {ingress_assessment.risk_score:.1f}/100]: "
                        f"A {ingress_assessment.primary_category.value.replace('_', ' ').title()} attack was intercepted. "
                        f"The Agentic AI security layer has quarantined this request and blocked execution to prevent policy evasion or privilege escalation."
                    ),
                    suggested_fix="Remove prompt injection directives, policy bypass commands, and exfiltration routines.",
                    code_context=code[:120] if code else "",
                    line_number=1,
                    similar_names=[],
                    security_warnings=sec_warnings,
                    ai_used=False,
                    engine_used="aai_security_guard",
                    health_report=health_report,
                    concept=f"Threat Defense: {ingress_assessment.primary_category.value.replace('_', ' ').title()}",
                    prevention_tip="Never inject policy override instructions into agentic prompts or execution environments.",
                    risk_level=ingress_assessment.risk_level.value,
                    risk_score=ingress_assessment.risk_score,
                    attack_category=ingress_assessment.primary_category.value
                )

        # Step 1: Execute and capture errors (security check happens inside)
        success, error_info = self.error_capture.execute_code(code)

        # Collect any security warnings
        sec_warnings = []
        if error_info and 'security_warnings' in error_info:
            sec_warnings = error_info['security_warnings']

        # Compute Code Health Report (Security + Optimality)
        health_report = None
        if self.health_analyzer:
            health_report = self.health_analyzer.analyze(code, sec_warnings)

        if success:
            return ExplanationResult(
                success=True,
                error_type=None,
                raw_error=None,
                friendly_explanation="Your code ran successfully with zero execution errors!",
                suggested_fix=None,
                code_context=None,
                line_number=None,
                similar_names=[],
                security_warnings=sec_warnings,
                ai_used=False,
                engine_used="execution_success",
                health_report=health_report,
                concept="Clean Execution",
                prevention_tip="Maintain modular functions, clear naming conventions, and consistent type hints."
            )

        # Step 1.5: Handle security blocks separately
        if error_info.get('error_type') == 'SecurityError':
            return ExplanationResult(
                success=False,
                error_type='SecurityError',
                raw_error=error_info['message'],
                friendly_explanation=(
                    "Your code was blocked because it contains potentially "
                    "dangerous operations (e.g. system shell access or dangerous file deletion). "
                    "In a sandbox learning environment, these calls are restricted for safety."
                ),
                suggested_fix=(
                    "Remove the restricted OS or system commands and focus on pure Python algorithms."
                ),
                code_context=error_info.get('code_context', ''),
                line_number=error_info.get('line_number'),
                similar_names=[],
                security_warnings=sec_warnings,
                ai_used=False,
                engine_used="security_gate",
                health_report=health_report,
                concept="Security Sandbox Policy",
                prevention_tip="Avoid executing shell commands from untrusted inputs in production environments."
            )

        # Step 2: Extract AST context & Route to Specialized Compiler Phase Agent
        ast_context = self.ast_extractor.analyze_error_context(error_info)
        specialist_agent = None
        specialist_diagnosis = None
        if self.orchestrator and error_info.get('error_type'):
            specialist_agent = self.orchestrator.route_to_specialist(error_info['error_type'])
            if hasattr(specialist_agent, "diagnose"):
                specialist_diagnosis = specialist_agent.diagnose(error_info, code, mode=mode)

        # Step 3: Multi-tier explanation generation
        result = None

        # Tier 1: Gemini API
        if self.use_ai and self.gemini_model:
            try:
                result = self._generate_gemini_explanation(error_info, ast_context, sec_warnings, full_code=code, mode=mode)
            except Exception as e:
                print(f"Gemini generation failed: {e}. Falling back to Tier 2 (T5 Model)...")

        # Tier 2: Local T5 Model Bridge
        if result is None:
            t5_engine = self._get_or_load_t5_model()
            if t5_engine:
                try:
                    result = self._generate_t5_explanation(error_info, ast_context, sec_warnings, full_code=code, mode=mode)
                except Exception as e:
                    print(f"Local T5 generation failed: {e}. Falling back to Tier 3 (Rules)...")

        # Tier 3: Rule-based fallback
        if result is None:
            result = self._generate_fallback_explanation(error_info, ast_context, full_code=code, mode=mode)
            result.security_warnings = sec_warnings

        # Attach Compiler Phase & Specialist Agent details
        if result:
            if specialist_agent:
                result.compiler_phase = specialist_agent.phase.value
                result.agent_name = specialist_agent.name
            if specialist_diagnosis:
                if not result.concept:
                    result.concept = specialist_diagnosis.concept
                if not result.corrected_code:
                    result.corrected_code = specialist_diagnosis.proposed_code
                if mode == "socratic" and not result.socratic_question:
                    result.socratic_question = specialist_diagnosis.socratic_question
                    result.progressive_hints = specialist_diagnosis.progressive_hints

        # Step 4: Automated Verification & Refinement of Recommended Fix (Max 3 attempts)
        if result and result.corrected_code:
            verified_code, is_verified, attempts = self._verify_and_refine_fix(
                initial_code=result.corrected_code,
                original_code=code,
                original_error=error_info,
                mode=mode,
                max_attempts=3
            )
            result.corrected_code = verified_code
            result.fix_verified = is_verified
            result.fix_verification_attempts = attempts

        result.health_report = health_report
        result.hint_mode = (mode == "socratic")
        return result

    def _get_clean_code_context(self, error_info: Dict) -> str:
        """Extract clean code context without debug markers or line numbers."""
        full_code = error_info.get('full_code', '')
        line_number = error_info.get('line_number')

        if not line_number or not full_code:
            return error_info.get('code_context', '')

        lines = full_code.split('\n')
        start = max(0, line_number - 2)
        end = min(len(lines), line_number + 2)
        return '\n'.join(lines[start:end]).strip()

    def _generate_gemini_explanation(self, error_info: Dict,
                                     ast_context: Dict,
                                     sec_warnings: list,
                                     full_code: str = "",
                                     mode: str = "direct") -> ExplanationResult:
        """Generate explanation using Tier 1: Gemini Structured JSON Engine."""
        clean_context = self._get_clean_code_context(error_info)

        data = self.gemini_model.generate_explanation_json(
            error_type=error_info['error_type'],
            error_message=error_info['message'],
            code_context=clean_context,
            full_code=full_code,
            mode=mode
        )

        concept = data.get("concept", self._get_default_concept(error_info['error_type']))
        explanation = data.get("explanation", "An error occurred during execution.")
        fix = data.get("suggested_fix", self._generate_basic_fix(error_info, ast_context))
        corrected_code = data.get("corrected_code") or self._synthesize_fixed_code(full_code, error_info, ast_context)
        prevention_tip = data.get("prevention_tip", self._get_default_prevention_tip(error_info['error_type']))
        socratic_q = data.get("socratic_question")
        prog_hints = data.get("progressive_hints", [])

        if mode == "socratic" and not socratic_q:
            socratic_q, prog_hints = self._get_socratic_materials(error_info, ast_context)

        return ExplanationResult(
            success=False,
            error_type=error_info['error_type'],
            raw_error=error_info['message'],
            friendly_explanation=explanation,
            suggested_fix=fix,
            code_context=error_info['code_context'],
            line_number=error_info['line_number'],
            similar_names=ast_context.get('similar_names', []),
            security_warnings=sec_warnings,
            ai_used=True,
            engine_used="gemini",
            concept=concept,
            corrected_code=corrected_code,
            prevention_tip=prevention_tip,
            hint_mode=(mode == "socratic"),
            socratic_question=socratic_q,
            progressive_hints=prog_hints
        )

    def _generate_t5_explanation(self, error_info: Dict,
                                 ast_context: Dict,
                                 sec_warnings: list,
                                 full_code: str = "",
                                 mode: str = "direct") -> ExplanationResult:
        """Generate explanation using Tier 2: Local T5 Transformer Model Bridge."""
        clean_context = self._get_clean_code_context(error_info)
        raw_output = self.t5_model.generate_explanation(
            error_type=error_info['error_type'],
            error_message=error_info['message'],
            code_context=clean_context
        )

        error_type = error_info['error_type']
        concept = self._get_default_concept(error_type)
        prevention_tip = self._get_default_prevention_tip(error_type)
        corrected_code = self._synthesize_fixed_code(full_code, error_info, ast_context)

        if error_type == 'TimeoutError':
            explanation = "Your code exceeded the execution limit (2.0s watchdog). This indicates an infinite loop or non-terminating recursion."
            fix = "Add a termination condition or 'break' statement inside your loop, or ensure your recursion has a reachable base case."
        elif 'FIX:' in raw_output:
            parts = raw_output.split('FIX:', 1)
            explanation = parts[0].replace('EXPLANATION:', '').strip()
            fix = parts[1].strip() or None
        else:
            explanation = raw_output.strip()
            fix = self._generate_basic_fix(error_info, ast_context)

        socratic_q, prog_hints = (None, [])
        if mode == "socratic":
            socratic_q, prog_hints = self._get_socratic_materials(error_info, ast_context)

        return ExplanationResult(
            success=False,
            error_type=error_type,
            raw_error=error_info['message'],
            friendly_explanation=explanation,
            suggested_fix=fix,
            code_context=error_info['code_context'],
            line_number=error_info['line_number'],
            similar_names=ast_context.get('similar_names', []),
            security_warnings=sec_warnings,
            ai_used=True,
            engine_used="t5_local",
            concept=concept,
            corrected_code=corrected_code,
            prevention_tip=prevention_tip,
            hint_mode=(mode == "socratic"),
            socratic_question=socratic_q,
            progressive_hints=prog_hints
        )

    def _generate_fallback_explanation(self, error_info: Dict,
                                       ast_context: Dict,
                                       full_code: str = "",
                                       mode: str = "direct") -> ExplanationResult:
        """Generate explanation using Tier 3: Rule-based fallback."""
        explanation = self.fallback.explain(
            error_info['error_type'],
            error_info['message']
        )

        similar = ast_context.get('similar_names', [])
        if similar:
            explanation += f" Did you mean: {', '.join(similar)}?"

        fix = self._generate_basic_fix(error_info, ast_context)
        concept = self._get_default_concept(error_info['error_type'])
        prevention_tip = self._get_default_prevention_tip(error_info['error_type'])
        corrected_code = self._synthesize_fixed_code(full_code, error_info, ast_context)

        socratic_q, prog_hints = (None, [])
        if mode == "socratic":
            socratic_q, prog_hints = self._get_socratic_materials(error_info, ast_context)

        return ExplanationResult(
            success=False,
            error_type=error_info['error_type'],
            raw_error=error_info['message'],
            friendly_explanation=explanation,
            suggested_fix=fix,
            code_context=error_info['code_context'],
            line_number=error_info['line_number'],
            similar_names=similar,
            security_warnings=[],
            ai_used=False,
            engine_used="fallback",
            concept=concept,
            corrected_code=corrected_code,
            prevention_tip=prevention_tip,
            hint_mode=(mode == "socratic"),
            socratic_question=socratic_q,
            progressive_hints=prog_hints
        )

    def _get_default_concept(self, error_type: str) -> str:
        """Map error types to their core Python concepts."""
        concepts = {
            'NameError': 'Variable Scope & Symbol Definition',
            'TypeError': 'Data Type Compatibility & Operations',
            'SyntaxError': 'Python Syntax Grammar & Structure',
            'IndexError': 'Sequence Bounds & 0-Based Indexing',
            'KeyError': 'Dictionary Key Existence & Mapping',
            'ZeroDivisionError': 'Mathematical Constraints & Arithmetic',
            'TimeoutError': 'Loop Termination & Algorithm Complexity',
            'AttributeError': 'Object Methods & Attributes',
            'ValueError': 'Argument Value Validity',
            'IndentationError': 'Code Block Indentation & Formatting',
        }
        return concepts.get(error_type, 'Python Runtime Execution')

    def _get_default_prevention_tip(self, error_type: str) -> str:
        """Map error types to practical prevention tips."""
        tips = {
            'NameError': 'Define variables before invoking them and use IDE autocomplete to avoid typos.',
            'TypeError': 'Use explicit type conversions (e.g. str(), int()) or modern f-strings for string interpolation.',
            'SyntaxError': 'Ensure all function, if, and loop headers end with a colon (:), and brackets/quotes are paired.',
            'IndexError': 'Check sequence lengths with len() or iterate directly with `for item in sequence:` instead of raw indexing.',
            'KeyError': 'Use the `.get(key, default)` method to look up dictionary keys safely without raising exceptions.',
            'ZeroDivisionError': 'Always validate divisors with a guard condition `if divisor != 0:` before performing division.',
            'TimeoutError': 'Ensure loop counters increment and `while` conditions can evaluate to False, or place a `break` condition.',
            'AttributeError': 'Use `dir(object)` or `hasattr(object, name)` to verify available attributes before access.',
        }
        return tips.get(error_type, 'Review code structure and write unit tests for edge cases.')

    def _get_socratic_materials(self, error_info: Dict, ast_context: Dict) -> tuple:
        """Produce thought-provoking Socratic questions and progressive hints."""
        err = error_info.get('error_type', '')
        line = error_info.get('line_number', '?')
        similar = ast_context.get('similar_names', [])

        if err == 'NameError':
            q = f"Look at line {line}: What variable or function name is being referenced, and where was it defined?"
            hints = [
                f"Check the spelling of the name at line {line}.",
                f"Did you mean: {', '.join(similar)}?" if similar else "Verify whether this name is a built-in function or declared earlier in the file.",
                "Ensure all functions and variables are declared before being called."
            ]
        elif err == 'TypeError':
            msg = error_info.get('message', '')
            if 'builtin_function_or_method' in msg or 'function' in msg:
                q = f"Look at line {line}: Are you referencing a function (like 'abs' or 'len') without parentheses () to call it?"
                hints = [
                    "In Python, writing a function name without () refers to the function object itself, not its computed result.",
                    "You cannot use arithmetic operators like '+' directly between a function object and an integer.",
                    "Call the function with an argument using parentheses, e.g. abs(-5) + 2 or len(list) + 2."
                ]
            else:
                q = f"Look at line {line}: What are the data types of the values being combined or operated on?"
                hints = [
                    "Python does not automatically convert numbers or other objects into strings when using the '+' operator.",
                    "Inspect each operand on the line and check their runtime types using type().",
                    "Try wrapping the non-string value with `str()` or format it using an f-string."
                ]
        elif err == 'SyntaxError':
            q = f"Inspect line {line}: Is there a missing punctuation mark or unmatched delimiter?"
            hints = [
                "Look closely at the very end of the line.",
                "In Python, compound statements (def, if, for, while, class) must end with a colon ':'.",
                "Add the missing colon or check that all parentheses `()` and quotes `''` are closed."
            ]
        elif err == 'IndexError':
            q = f"Look at line {line}: What is the length of the list, and what index are you requesting?"
            hints = [
                "Remember that Python uses 0-based indexing: the first item is index 0.",
                "If a list has 3 items, the maximum valid index is 2.",
                "Check `len(list_name)` before accessing elements, or iterate directly."
            ]
        elif err == 'ZeroDivisionError':
            q = f"Look at line {line}: What is the denominator value in the division operation?"
            hints = [
                "Division by zero is undefined in mathematics and raises ZeroDivisionError in Python.",
                "Check the variable or expression on the right side of `/` or `//`.",
                "Add an `if denominator != 0:` guard check before performing the calculation."
            ]
        elif err == 'TimeoutError':
            q = "Does your loop have a condition that will guaranteed become False or trigger a break?"
            hints = [
                "The code ran for more than 2.0 seconds and was halted by the execution watchdog.",
                "Check if loop counters are properly incremented inside the loop body.",
                "Add a maximum iteration counter or a `break` statement to exit the loop."
            ]
        else:
            q = f"Examine line {line}: What operation failed and what assumptions did it make about the data?"
            hints = [
                f"Read the exception message: {error_info.get('message', '')}",
                "Check the variables and expression types involved on this line.",
                "Verify inputs and add defensive checks or error handling."
            ]

        return q, hints

    def _synthesize_fixed_code(self, full_code: str, error_info: Dict, ast_context: Dict) -> Optional[str]:
        """Synthesize a complete corrected code snippet for 1-click apply fix."""
        if not full_code:
            return None

        err = error_info.get('error_type')
        line_num = error_info.get('line_number')
        lines = full_code.split('\n')

        try:
            if err == 'NameError':
                msg = error_info.get('message', '')
                match = re.search(r"name '(\w+)' is not defined", msg)
                if match and line_num and 1 <= line_num <= len(lines):
                    bad_name = match.group(1)
                    target_line = lines[line_num - 1]
                    similar = ast_context.get('similar_names', [])

                    # 1. Check if defined on a later line (used before definition)
                    later_def_idx = None
                    for idx, line in enumerate(lines):
                        if idx > line_num - 1 and re.match(r'^\s*' + re.escape(bad_name) + r'\s*=', line):
                            later_def_idx = idx
                            break
                    if later_def_idx is not None:
                        def_line = lines.pop(later_def_idx)
                        lines.insert(line_num - 1, def_line)
                        return '\n'.join(lines)

                    # 2. Check for typo in function call or variable (e.g. prnt -> print or itms -> items)
                    if similar:
                        # Avoid replacing variable in arithmetic with built-in functions like print/len
                        candidates = [s for s in similar if not (s in ('print', 'len', 'range', 'open') and not '(' in target_line)]
                        if candidates:
                            best_candidate = candidates[0]
                            lines[line_num - 1] = re.sub(r'\b' + re.escape(bad_name) + r'\b', best_candidate, target_line)
                            return '\n'.join(lines)

                    # 3. Simple undefined variable -> prepend declaration
                    return f"{bad_name} = 10  # Initialized variable\n" + full_code

            elif err == 'SyntaxError':
                if line_num and 1 <= line_num <= len(lines):
                    target_line = lines[line_num - 1]
                    # Missing colon fix for def, if, for, while, class, elif, else
                    if re.search(r'^\s*(def|if|for|while|class|elif|else)\b.*[^:]\s*$', target_line):
                        lines[line_num - 1] = target_line.rstrip() + ":"
                        return '\n'.join(lines)

            elif err == 'TypeError':
                if line_num and 1 <= line_num <= len(lines):
                    target_line = lines[line_num - 1]
                    msg = error_info.get('message', '')

                    # 1. Uncalled built-in function used in arithmetic (e.g. abs + 2 or len + 1)
                    if 'builtin_function_or_method' in msg or 'function' in msg:
                        # Fix common builtins like abs, len, max, min, sum
                        fixed_line = re.sub(r'\babs\s*(\+|\-|\*|\/)', r'abs(-5) \1', target_line)
                        fixed_line = re.sub(r'\blen\s*(\+|\-|\*|\/)', r'len([1, 2]) \1', fixed_line)
                        lines[line_num - 1] = fixed_line
                        return '\n'.join(lines)

                    # 2. String and non-string concatenation (e.g. "+ age" -> "+ str(age)")
                    if '+' in target_line:
                        fixed_line = re.sub(r'\+\s*([a-zA-Z_]\w*)', r'+ str(\1)', target_line)
                        lines[line_num - 1] = fixed_line
                        return '\n'.join(lines)

            elif err == 'IndexError':
                if line_num and 1 <= line_num <= len(lines):
                    target_line = lines[line_num - 1]
                    # Fix large index like [10] to [0] or [len-1]
                    fixed_line = re.sub(r'\[\d+\]', '[0]', target_line)
                    lines[line_num - 1] = fixed_line
                    return '\n'.join(lines)

            elif err == 'ZeroDivisionError':
                if line_num and 1 <= line_num <= len(lines):
                    target_line = lines[line_num - 1]
                    fixed_line = re.sub(r'/\s*0', r'/ 2', target_line)
                    lines[line_num - 1] = fixed_line
                    return '\n'.join(lines)

            elif err == 'TimeoutError':
                # Replace while True: with a bounded loop
                fixed_code = re.sub(
                    r'while\s+True\s*:\s*\n(\s*)(.*)',
                    r'for _ in range(5):\n\1\2',
                    full_code
                )
                return fixed_code

        except Exception:
            pass

        return None

    def _generate_basic_fix(self, error_info: Dict, ast_context: Dict) -> str:
        """Generate basic fix suggestions."""
        error_type = error_info['error_type']
        suggestions = ast_context.get('suggestions', [])

        if suggestions:
            return suggestions[0]

        fix_templates = {
            'SyntaxError': "Check for missing colons (:), parentheses, or quotation marks.",
            'NameError': "Verify the variable or function name is spelled correctly and defined before use.",
            'TypeError': "Convert data types explicitly using str(), int(), or format strings.",
            'IndexError': "Verify the index is within the valid sequence range [0, len - 1].",
            'KeyError': "Use the .get() method or verify the dictionary key exists.",
            'ZeroDivisionError': "Ensure the denominator is non-zero before dividing.",
            'TimeoutError': "Inspect loop conditions and recursion base cases to ensure execution terminates."
        }

        return fix_templates.get(error_type, "Review the code at the indicated line")

    def _is_healed_code_safe_to_verify(self, candidate_code: str, original_code: str) -> bool:
        """
        Verify that healed code does not introduce new unauthorized imports or risky modules.
        """
        if not candidate_code:
            return False

        SAFE_PERMITTED_NEW_MODULES = {
            'math', 'random', 're', 'datetime', 'collections',
            'itertools', 'functools', 'string'
        }

        try:
            cand_tree = ast.parse(candidate_code)
        except SyntaxError:
            return False

        orig_imports = set()
        try:
            orig_tree = ast.parse(original_code)
            for node in ast.walk(orig_tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        orig_imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    orig_imports.add(node.module.split('.')[0])
        except SyntaxError:
            pass

        # Check candidate imports
        for node in ast.walk(cand_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split('.')[0]
                    if root not in orig_imports and root not in SAFE_PERMITTED_NEW_MODULES:
                        return False
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split('.')[0]
                if root not in orig_imports and root not in SAFE_PERMITTED_NEW_MODULES:
                    return False

        return True

    def _verify_and_refine_fix(
        self,
        initial_code: str,
        original_code: str,
        original_error: Dict,
        mode: str = "direct",
        max_attempts: int = 3
    ) -> tuple:
        """
        Verifies candidate corrected code by executing it in the sandbox.
        If the candidate code throws an error, iteratively refines and re-tests it up to max_attempts (3).

        Returns:
            (best_code, is_verified, attempts_count)
        """
        current_candidate = initial_code
        attempts = 0

        while attempts < max_attempts:
            attempts += 1
            if not current_candidate or not current_candidate.strip():
                # Synthesize fallback from AST
                ast_ctx = self.ast_extractor.analyze_error_context(original_error)
                current_candidate = self._synthesize_fixed_code(original_code, original_error, ast_ctx)
                if not current_candidate:
                    return None, False, attempts

            # Egress Guard: Audit candidate healed code for hidden agendas / trojan insertions
            if hasattr(self, 'aai_guard') and self.aai_guard:
                healed_assessment = self.aai_guard.audit_healed_code(current_candidate, original_code=original_code)
                if not healed_assessment.is_safe:
                    # Candidate code contains trojan/hidden agenda - block from verification sandbox and discard!
                    current_candidate = None
                    continue

            # Import Egress Gate: Prevent candidate code from introducing unapproved external imports
            if not self._is_healed_code_safe_to_verify(current_candidate, original_code):
                current_candidate = None
                continue

            # Test execution in sandbox
            success, test_error = self.error_capture.execute_code(current_candidate)

            if success:
                # Execution succeeded without any runtime or syntax errors!
                return current_candidate, True, attempts

            # If error occurred and we have remaining attempts, refine:
            if attempts < max_attempts:
                refined = None
                # Tier 1: Try Gemini refinement if active
                if self.use_ai and self.gemini_model and hasattr(self.gemini_model, 'refine_fix'):
                    try:
                        refined = self.gemini_model.refine_fix(
                            original_code=original_code,
                            failed_fix_code=current_candidate,
                            error_type=test_error.get('error_type', 'Error'),
                            error_message=test_error.get('message', '')
                        )
                    except Exception:
                        refined = None

                # Tier 2/3: Try AST synthesis on the new error
                if not refined or not refined.strip():
                    new_ast_ctx = self.ast_extractor.analyze_error_context(test_error)
                    refined = self._synthesize_fixed_code(current_candidate, test_error, new_ast_ctx)

                if refined and refined.strip() and refined.strip() != current_candidate.strip():
                    current_candidate = refined.strip()
                else:
                    # Could not produce a distinct alternative fix
                    break

        return current_candidate, False, attempts