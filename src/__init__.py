"""
AI Error Tutor - A friendly Python error message rewriter using AI

This package provides tools to capture Python errors and transform
cryptic compiler messages into human-friendly explanations.
"""

from .error_capture import ErrorCapture, capture_error
from .ast_parser import ASTContextExtractor
from .fallback import FallbackExplainer
from .gemini_client import GeminiErrorExplainer
from .pipeline import AIErrorTutor, ExplanationResult
from .security import CodeSecurityValidator, SecurityWarning
from .aai_security_guard import AAISecurityGuard, SecurityAssessment, ThreatCategory, RiskLevel
from .multi_agent_system import (
    CompilerOrchestratorAgent,
    CompilerPhase,
    BaseCompilerAgent,
    SecuritySentinelAgent,
    SyntaxGrammarAgent,
    SemanticScopeAgent,
    RuntimeWatchdogAgent,
    OptimizationProfilerAgent,
    SelfHealingVerifierAgent
)

ErrorExplainerModel = GeminiErrorExplainer

__version__ = "1.0.0"
__author__ = "Sai Charan Kumar"

__all__ = [
    # Error Capture
    "ErrorCapture",
    "capture_error",

    # AST Parser
    "ASTContextExtractor",

    # Model
    "ErrorExplainerModel",
    "GeminiErrorExplainer",
    "FallbackExplainer",

    # Pipeline
    "AIErrorTutor",
    "ExplanationResult",

    # Security
    "CodeSecurityValidator",
    "SecurityWarning",
    "AAISecurityGuard",
    "SecurityAssessment",
    "ThreatCategory",
    "RiskLevel",

    # Multi-Agent Compiler System
    "CompilerOrchestratorAgent",
    "CompilerPhase",
    "BaseCompilerAgent",
    "SecuritySentinelAgent",
    "SyntaxGrammarAgent",
    "SemanticScopeAgent",
    "RuntimeWatchdogAgent",
    "OptimizationProfilerAgent",
    "SelfHealingVerifierAgent"
]