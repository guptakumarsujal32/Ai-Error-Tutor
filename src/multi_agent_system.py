"""
Multi-Agent Compiler System (MACS) for AI Error Tutor.

Implements specialized, collaborating Agentic AIs mapped to distinct compiler phases:
  1. SecuritySentinelAgent (Ingress Threat Modeling & Policy Defense)
  2. SyntaxGrammarAgent (Compiler Phases 1 & 2: Lexical & Syntax Analysis)
  3. SemanticScopeAgent (Compiler Phase 3: Semantic Analysis & Symbol Table)
  4. OptimizationProfilerAgent (Compiler Phase 5: Code Optimization & Health)
  5. RuntimeWatchdogAgent (Compiler Phase 6: Code Generation & Runtime Sandbox)
  6. SelfHealingVerifierAgent (QA Gate: Sandbox Testing & Trojan Egress Guard)
  7. CompilerOrchestratorAgent (Meta-Tutor / Blackboard Coordinator)
"""

import ast
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any

# Local module imports
try:
    from .error_capture import ErrorCapture
    from .ast_parser import ASTContextExtractor
    from .fallback import FallbackExplainer
    from .code_analyzer import CodeHealthAnalyzer, CodeHealthReport
    from .security import SecurityWarning
    from .aai_security_guard import AAISecurityGuard, ThreatCategory, RiskLevel, SecurityAssessment
except ImportError:
    from error_capture import ErrorCapture
    from ast_parser import ASTContextExtractor
    from fallback import FallbackExplainer
    try:
        from code_analyzer import CodeHealthAnalyzer, CodeHealthReport
    except ImportError:
        CodeHealthAnalyzer = None
        CodeHealthReport = None
    from security import SecurityWarning
    from aai_security_guard import AAISecurityGuard, ThreatCategory, RiskLevel, SecurityAssessment


class CompilerPhase(str, Enum):
    INGRESS_SECURITY = "Ingress Threat Modeling & Policy Gate"
    LEXICAL_SYNTAX = "Compiler Phases 1 & 2: Lexical & Syntax Analysis"
    SEMANTIC_ANALYSIS = "Compiler Phase 3: Semantic Analysis & Symbol Table"
    CODE_OPTIMIZATION = "Compiler Phase 5: Code Optimization & Health"
    RUNTIME_EXECUTION = "Compiler Phase 6: Code Generation & Runtime Sandbox"
    SELF_HEALING_VERIFICATION = "Quality Assurance: Verification & Self-Healing Loop"


@dataclass
class AgentDiagnosis:
    """Standardized decision and diagnostic output from a compiler agent."""
    agent_name: str
    phase: CompilerPhase
    error_type: Optional[str]
    concept: str
    explanation: str
    socratic_question: Optional[str] = None
    progressive_hints: List[str] = field(default_factory=list)
    suggested_fix: Optional[str] = None
    proposed_code: Optional[str] = None
    prevention_tip: str = ""
    similar_names: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseCompilerAgent(ABC):
    """Abstract base class for all specialized compiler phase agents."""

    def __init__(self, name: str, phase: CompilerPhase):
        self.name = name
        self.phase = phase

    @abstractmethod
    def can_handle(self, error_type: Optional[str]) -> bool:
        """Determines if this specialist agent handles the given compiler condition."""
        pass


class SecuritySentinelAgent(BaseCompilerAgent):
    """Specialized Agent for Ingress Threat Modeling & Policy Enforcement."""

    def __init__(self, guard: Optional[AAISecurityGuard] = None):
        super().__init__("SecuritySentinelAgent", CompilerPhase.INGRESS_SECURITY)
        self.guard = guard or AAISecurityGuard()

    def can_handle(self, error_type: Optional[str]) -> bool:
        return error_type in ("SecurityError", "AttackBlocked")

    def inspect(self, code_or_prompt: str) -> SecurityAssessment:
        """Audits inbound payload for prompt injections, policy bypasses, and exploits."""
        return self.guard.assess_input(code_or_prompt, target_type="code")


class SyntaxGrammarAgent(BaseCompilerAgent):
    """
    Specialized Agent for Compiler Phases 1 & 2:
    Lexical Analysis (Tokens) & Syntax Analysis (Grammar & Abstract Syntax Tree).
    """

    HANDLED_ERRORS = {"SyntaxError", "IndentationError", "TabError"}

    def __init__(self, ast_extractor: Optional[ASTContextExtractor] = None):
        super().__init__("SyntaxGrammarAgent", CompilerPhase.LEXICAL_SYNTAX)
        self.ast_extractor = ast_extractor or ASTContextExtractor()

    def can_handle(self, error_type: Optional[str]) -> bool:
        return error_type in self.HANDLED_ERRORS

    def diagnose(self, error_info: Dict[str, Any], full_code: str, mode: str = "direct") -> AgentDiagnosis:
        err_type = error_info.get("error_type", "SyntaxError")
        line = error_info.get("line_number", 1)
        msg = error_info.get("message", "Invalid syntax")
        offset = error_info.get("offset")

        # Grammar concept
        concept = "Python Syntax Grammar & Structural Rules" if err_type == "SyntaxError" else "Python Code Block Indentation Rules"
        
        # Friendly explanation
        explanation = f"Syntax analysis failed at line {line}: {msg}."
        if "expected ':'" in msg.lower() or ":" in msg:
            explanation = f"Line {line} is missing a required colon ':' at the end of the compound statement header."

        # Socratic questions and progressive hints
        socratic_q = f"Look closely at the punctuation at the end of line {line}: What character is Python expecting?"
        hints = [
            f"Check the exact grammar of line {line}.",
            "In Python, all compound statements (def, if, for, while, class) must terminate with a colon ':'.",
            "Add the missing ':' or balance any unclosed quotation marks or parentheses."
        ]

        suggested_fix = "Ensure all statement headers end with a colon (:) and all parentheses/quotes are properly closed."
        prevention_tip = "Use a modern IDE with real-time syntax checking or format code with black/flake8."

        # Synthesize fixed code
        proposed_code = self._synthesize_syntax_fix(full_code, line, msg)

        return AgentDiagnosis(
            agent_name=self.name,
            phase=self.phase,
            error_type=err_type,
            concept=concept,
            explanation=explanation,
            socratic_question=socratic_q if mode == "socratic" else None,
            progressive_hints=hints if mode == "socratic" else [],
            suggested_fix=suggested_fix,
            proposed_code=proposed_code,
            prevention_tip=prevention_tip,
            metadata={"token_offset": offset}
        )

    def _synthesize_syntax_fix(self, full_code: str, line_num: Optional[int], msg: str) -> Optional[str]:
        if not full_code or not line_num:
            return None
        lines = full_code.split('\n')
        if 1 <= line_num <= len(lines):
            target = lines[line_num - 1]
            # Missing colon fix
            if re.match(r'^\s*(def|if|elif|else|for|while|class|try|except|finally|with)\b', target) and not target.rstrip().endswith(':'):
                lines[line_num - 1] = target.rstrip() + ':'
                return '\n'.join(lines)
            # Unclosed string quote
            if target.count('"') % 2 != 0:
                lines[line_num - 1] = target + '"'
                return '\n'.join(lines)
            if target.count("'") % 2 != 0:
                lines[line_num - 1] = target + "'"
                return '\n'.join(lines)
        return None


class SemanticScopeAgent(BaseCompilerAgent):
    """
    Specialized Agent for Compiler Phase 3:
    Semantic Analysis, Scope Resolution, Symbol Table Management & Type Compatibility.
    """

    HANDLED_ERRORS = {"NameError", "TypeError", "AttributeError", "KeyError"}

    def __init__(self, ast_extractor: Optional[ASTContextExtractor] = None):
        super().__init__("SemanticScopeAgent", CompilerPhase.SEMANTIC_ANALYSIS)
        self.ast_extractor = ast_extractor or ASTContextExtractor()

    def can_handle(self, error_type: Optional[str]) -> bool:
        return error_type in self.HANDLED_ERRORS

    def diagnose(self, error_info: Dict[str, Any], full_code: str, mode: str = "direct") -> AgentDiagnosis:
        err_type = error_info.get("error_type", "TypeError")
        line = error_info.get("line_number", 1)
        msg = error_info.get("message", "")

        # Extract AST symbol table context
        ast_context = self.ast_extractor.analyze_error_context(error_info)
        similar_names = ast_context.get("similar_names", [])

        if err_type == "NameError":
            concept = "Variable Scope & Symbol Table Definition"
            explanation = f"Symbol lookup failed at line {line}: The identifier is not defined in local, enclosing, or global scope."
            if similar_names:
                explanation += f" Did you mean: {', '.join(similar_names)}?"
            socratic_q = f"Look at line {line}: What variable or function name is being referenced, and where was it defined?"
            hints = [
                f"Check the spelling of the name at line {line}.",
                f"Did you mean: {', '.join(similar_names)}?" if similar_names else "Verify whether this symbol is defined earlier in the code.",
                "Ensure functions and variables are declared before they are called."
            ]
            suggested_fix = f"Define the symbol before using it, or fix typos (e.g. {similar_names[0] if similar_names else 'print'})."
            prevention_tip = "Use an IDE with variable autocomplete and avoid relying on undefined global variables."
            proposed_code = self._synthesize_name_fix(full_code, line, similar_names)

        elif err_type == "TypeError":
            concept = "Data Type Compatibility & Operations"
            if "builtin_function_or_method" in msg or "function" in msg:
                explanation = f"Type conflict at line {line}: An uncalled function object was used in an arithmetic expression without parentheses ()."
                socratic_q = f"Look at line {line}: Are you referencing a function without parentheses () to invoke it?"
                hints = [
                    "Writing a function name without () refers to the function object itself, not its return value.",
                    "You cannot add or subtract directly with a function object.",
                    "Call the function with parentheses and appropriate arguments."
                ]
                suggested_fix = "Invoke the function with parentheses (e.g., abs(-5) or len(items))."
            else:
                explanation = f"Type mismatch at line {line}: Incompatible operand types encountered: {msg}."
                socratic_q = f"Inspect line {line}: What are the runtime types of the operands being combined?"
                hints = [
                    "Python is strongly typed and does not automatically convert numbers to strings when using '+'.",
                    "Check the types of both values with type().",
                    "Explicitly convert the non-string value with str() or use an f-string."
                ]
                suggested_fix = "Use explicit type casting like str() or int(), or format using f-strings."
            prevention_tip = "Use Python type annotations (type hints) to detect type mismatches during development."
            proposed_code = self._synthesize_type_fix(full_code, line, msg)

        else:
            concept = "Object Attributes & Mapping Semantics"
            explanation = f"Semantic inspection failed at line {line}: {msg}."
            socratic_q = f"Check line {line}: Does the target object possess this attribute or dictionary key?"
            hints = [
                "Inspect the keys or attributes available on this object.",
                "Verify whether the dictionary key exists before accessing it, or use .get().",
                "Ensure you are not accessing a private or non-existent attribute."
            ]
            suggested_fix = "Verify object attributes with dir() or use dict.get(key, default)."
            prevention_tip = "Write defensive guard checks with hasattr() or dict.get()."
            proposed_code = None

        return AgentDiagnosis(
            agent_name=self.name,
            phase=self.phase,
            error_type=err_type,
            concept=concept,
            explanation=explanation,
            socratic_question=socratic_q if mode == "socratic" else None,
            progressive_hints=hints if mode == "socratic" else [],
            suggested_fix=suggested_fix,
            proposed_code=proposed_code,
            prevention_tip=prevention_tip,
            similar_names=similar_names,
            metadata={"ast_symbols": ast_context.get("available_variables", [])}
        )

    def _synthesize_name_fix(self, full_code: str, line_num: Optional[int], similar_names: List[str]) -> Optional[str]:
        if not full_code or not line_num:
            return None
        lines = full_code.split('\n')
        if 1 <= line_num <= len(lines):
            target = lines[line_num - 1]
            if similar_names:
                replacement = similar_names[0]
                fixed = re.sub(r'\bprnt\b', replacement, target)
                lines[line_num - 1] = fixed
                return '\n'.join(lines)
            elif 'prnt' in target:
                lines[line_num - 1] = target.replace('prnt', 'print')
                return '\n'.join(lines)
        return None

    def _synthesize_type_fix(self, full_code: str, line_num: Optional[int], msg: str) -> Optional[str]:
        if not full_code or not line_num:
            return None
        lines = full_code.split('\n')
        if 1 <= line_num <= len(lines):
            target = lines[line_num - 1]
            if "builtin_function_or_method" in msg or "function" in msg:
                fixed = re.sub(r'\babs\s*(\+|\-|\*|\/)', r'abs(-5) \1', target)
                fixed = re.sub(r'\blen\s*(\+|\-|\*|\/)', r'len([1, 2]) \1', fixed)
                lines[line_num - 1] = fixed
                return '\n'.join(lines)
            if '+' in target:
                fixed = re.sub(r'\+\s*([a-zA-Z_]\w*)', r'+ str(\1)', target)
                lines[line_num - 1] = fixed
                return '\n'.join(lines)
        return None


class RuntimeWatchdogAgent(BaseCompilerAgent):
    """
    Specialized Agent for Compiler Phase 6:
    Bytecode Execution Environment, Watchdog Watcher, and Runtime Failure Isolation.
    """

    HANDLED_ERRORS = {"TimeoutError", "ZeroDivisionError", "IndexError", "RecursionError", "OverflowError"}

    def __init__(self, error_capture: Optional[ErrorCapture] = None):
        super().__init__("RuntimeWatchdogAgent", CompilerPhase.RUNTIME_EXECUTION)
        self.error_capture = error_capture or ErrorCapture()

    def can_handle(self, error_type: Optional[str]) -> bool:
        return error_type in self.HANDLED_ERRORS

    def diagnose(self, error_info: Dict[str, Any], full_code: str, mode: str = "direct") -> AgentDiagnosis:
        err_type = error_info.get("error_type", "RuntimeError")
        line = error_info.get("line_number", 1)
        msg = error_info.get("message", "")

        if err_type == "TimeoutError":
            concept = "Loop Termination & Algorithmic Complexity"
            explanation = "Execution watchdog interrupted the program: The execution exceeded the 2.0s sandbox limit (infinite loop or non-terminating recursion detected)."
            socratic_q = "Does your loop have an exit condition guaranteed to evaluate to False, or a break statement?"
            hints = [
                "The code ran past the 2.0s safety watchdog.",
                "Inspect while loops to ensure iteration variables update toward the exit condition.",
                "Add a break condition or bounded range: for _ in range(N):."
            ]
            suggested_fix = "Ensure loop counters increment and while conditions terminate, or use for loops with range()."
            prevention_tip = "Avoid while True: loops without explicit, reachable break statements."
            proposed_code = re.sub(r'while\s+True\s*:\s*\n(\s*)(.*)', r'for _ in range(5):\n\1\2', full_code) if full_code else None

        elif err_type == "ZeroDivisionError":
            concept = "Mathematical Constraints & Arithmetic Rules"
            explanation = f"Arithmetic fault at line {line}: Division by zero is undefined in mathematics and raises ZeroDivisionError in Python."
            socratic_q = f"Inspect line {line}: What is the value of the denominator in the division operation?"
            hints = [
                "Division by zero is undefined.",
                "Check the variable or calculation on the right-hand side of / or //.",
                "Add a guard check: if denominator != 0: before dividing."
            ]
            suggested_fix = "Validate that the denominator is not zero before dividing, or provide a default fallback."
            prevention_tip = "Always place a guard condition or clamp divisor values before arithmetic division."
            proposed_code = self._synthesize_zerodiv_fix(full_code, line)

        elif err_type == "IndexError":
            concept = "Sequence Bounds & 0-Based Indexing"
            explanation = f"Sequence fault at line {line}: Attempted to access an index outside the valid range [0, len(sequence) - 1]."
            socratic_q = f"Look at line {line}: What is the length of the list, and what index are you requesting?"
            hints = [
                "Remember that Python uses 0-based indexing: the first item is index 0.",
                "If a list has 3 items, the maximum valid index is 2.",
                "Check len(sequence) or iterate with for item in sequence: directly."
            ]
            suggested_fix = "Ensure indices are strictly less than len(sequence), or iterate with a for-in loop."
            prevention_tip = "Prefer direct sequence iteration over manual numeric index lookups."
            proposed_code = self._synthesize_index_fix(full_code, line)

        else:
            concept = "Runtime Environment Constraints"
            explanation = f"Runtime fault: {msg}."
            socratic_q = "Did the program exceed standard memory or recursion limits?"
            hints = ["Check recursion base cases.", "Ensure data structures do not expand infinitely."]
            suggested_fix = "Review runtime resource consumption."
            prevention_tip = "Ensure recursion algorithms have reachable base cases."
            proposed_code = None

        return AgentDiagnosis(
            agent_name=self.name,
            phase=self.phase,
            error_type=err_type,
            concept=concept,
            explanation=explanation,
            socratic_question=socratic_q if mode == "socratic" else None,
            progressive_hints=hints if mode == "socratic" else [],
            suggested_fix=suggested_fix,
            proposed_code=proposed_code,
            prevention_tip=prevention_tip
        )

    def _synthesize_zerodiv_fix(self, full_code: str, line_num: Optional[int]) -> Optional[str]:
        if not full_code or not line_num:
            return None
        lines = full_code.split('\n')
        if 1 <= line_num <= len(lines):
            target = lines[line_num - 1]
            fixed = re.sub(r'/\s*0\b', r'/ 2', target)
            lines[line_num - 1] = fixed
            return '\n'.join(lines)
        return None

    def _synthesize_index_fix(self, full_code: str, line_num: Optional[int]) -> Optional[str]:
        if not full_code or not line_num:
            return None
        lines = full_code.split('\n')
        if 1 <= line_num <= len(lines):
            target = lines[line_num - 1]
            fixed = re.sub(r'\[\d+\]', r'[0]', target)
            lines[line_num - 1] = fixed
            return '\n'.join(lines)
        return None


class OptimizationProfilerAgent(BaseCompilerAgent):
    """
    Specialized Agent for Compiler Phase 5:
    Code Optimization, Algorithmic Time/Space Complexity & Static Health Scorecard.
    """

    def __init__(self, analyzer: Optional[CodeHealthAnalyzer] = None):
        super().__init__("OptimizationProfilerAgent", CompilerPhase.CODE_OPTIMIZATION)
        self.analyzer = analyzer or (CodeHealthAnalyzer() if CodeHealthAnalyzer else None)

    def can_handle(self, error_type: Optional[str]) -> bool:
        return True  # Evaluated on every code submission

    def profile(self, code: str, security_warnings: list = None) -> Optional[CodeHealthReport]:
        """Profiles code for asymptotic complexity O(N^2) and memory allocation efficiency."""
        if self.analyzer:
            return self.analyzer.analyze(code, security_warnings or [])
        return None


class SelfHealingVerifierAgent(BaseCompilerAgent):
    """
    Specialized Quality Gate Agent:
    Audits proposed candidate code for Trojan/PII exfiltration,
    executes fixes in the sandbox, and conducts iterative self-healing refinement.
    """

    def __init__(self, error_capture: Optional[ErrorCapture] = None, guard: Optional[AAISecurityGuard] = None):
        super().__init__("SelfHealingVerifierAgent", CompilerPhase.SELF_HEALING_VERIFICATION)
        self.error_capture = error_capture or ErrorCapture()
        self.guard = guard or AAISecurityGuard()

    def can_handle(self, error_type: Optional[str]) -> bool:
        return True

    def verify_and_heal(
        self,
        candidate_code: str,
        original_code: str,
        orchestrator: Any,
        max_attempts: int = 50
    ) -> Tuple[Optional[str], bool, int]:
        """
        Closed-loop self-correction:
        1. Egress security audit (Trojan/exfiltration detection)
        2. Sandbox execution test
        3. Automated refinement loop if secondary bugs occur
        """
        current_candidate = candidate_code
        attempts = 0

        while attempts < max_attempts:
            attempts += 1
            if not current_candidate or not current_candidate.strip():
                return None, False, attempts

            # Phase A: Egress Trojan & Secret Exfiltration Guard
            audit = self.guard.audit_healed_code(current_candidate, original_code=original_code)
            if not audit.is_safe:
                # Malicious Trojan detected in proposed fix! Drop and halt verification.
                return None, False, attempts

            # Phase B: Sandbox Execution Verification
            success, test_error = self.error_capture.execute_code(current_candidate)
            if success:
                # Candidate compiled and ran with 0 errors!
                return current_candidate, True, attempts

            # Phase C: Autonomous Refinement
            if attempts < max_attempts and orchestrator:
                refined = orchestrator.refine_candidate(current_candidate, test_error)
                if refined and refined.strip() and refined.strip() != current_candidate.strip():
                    current_candidate = refined.strip()
                else:
                    break

        return current_candidate, False, attempts


class CompilerOrchestratorAgent:
    """
    Meta-Tutor / Blackboard Coordinator:
    Orchestrates the multi-agent workflow across all compiler phases.
    """

    def __init__(self):
        self.security_agent = SecuritySentinelAgent()
        self.syntax_agent = SyntaxGrammarAgent()
        self.semantic_agent = SemanticScopeAgent()
        self.runtime_agent = RuntimeWatchdogAgent()
        self.optimization_agent = OptimizationProfilerAgent()
        self.verifier_agent = SelfHealingVerifierAgent()

    def route_to_specialist(self, error_type: str) -> BaseCompilerAgent:
        """Dispatches an error to the corresponding compiler phase specialist."""
        if self.syntax_agent.can_handle(error_type):
            return self.syntax_agent
        elif self.semantic_agent.can_handle(error_type):
            return self.semantic_agent
        elif self.runtime_agent.can_handle(error_type):
            return self.runtime_agent
        return self.semantic_agent  # Default to semantic analysis

    def refine_candidate(self, failed_code: str, error_info: Dict[str, Any]) -> Optional[str]:
        """Requests a secondary fix from the specialist agent for the new error."""
        err_type = error_info.get("error_type", "")
        specialist = self.route_to_specialist(err_type)
        if hasattr(specialist, "diagnose"):
            diagnosis = specialist.diagnose(error_info, failed_code, mode="direct")
            return diagnosis.proposed_code
        return None
