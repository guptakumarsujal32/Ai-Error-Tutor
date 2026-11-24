"""Configuration file for AI Error Tutor.

All model parameters, provider chain order, circuit-breaker limits, and
endpoints are centralized here. No model, URL, or secret should be hardcoded
outside this file.
"""

import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# ─────────────────────────────────────────────
# Multi-Tier LLM Provider Chain
# Tier 1 = Gemini (Cloud), Tier 2 = Local LLM (Ollama), Tier 3 = AST Rule-Based
# ─────────────────────────────────────────────
PROVIDER_ORDER = ["gemini", "ollama", "rules"]

# Tier 1: Gemini API Configuration (API key read ONLY from env / .env, never hardcoded)
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")  # Change to any current Google AI Studio model if needed
GEMINI_TIMEOUT = int(os.getenv("GEMINI_TIMEOUT", "30"))

# Per-role Gemini model mapping
GEMINI_MODELS = {
    "fixer": os.getenv("GEMINI_MODEL_FIXER", GEMINI_MODEL),
    "diagnostician": os.getenv("GEMINI_MODEL_DIAGNOSTICIAN", GEMINI_MODEL),
    "tutor": os.getenv("GEMINI_MODEL_TUTOR", GEMINI_MODEL),
    "critic": os.getenv("GEMINI_MODEL_CRITIC", GEMINI_MODEL),
    # Note: Attacker agent is strictly locked to local Ollama and never uses Gemini.
}

# Tier 2: Ollama Local LLM Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")

# Per-role Ollama model mapping (kept as MODELS for backward compatibility)
MODELS = {
    "fixer": os.getenv("OLLAMA_MODEL_FIXER", OLLAMA_MODEL),
    "diagnostician": os.getenv("OLLAMA_MODEL_DIAGNOSTICIAN", OLLAMA_MODEL),
    "tutor": os.getenv("OLLAMA_MODEL_TUTOR", OLLAMA_MODEL),
    "critic": os.getenv("OLLAMA_MODEL_CRITIC", OLLAMA_MODEL),
    "attacker": os.getenv("OLLAMA_MODEL_ATTACKER", OLLAMA_MODEL),
}

# Unified per-provider role model map
PROVIDER_MODELS = {
    "gemini": GEMINI_MODELS,
    "ollama": MODELS,
}

FALLBACK_MODEL = os.getenv("OLLAMA_FALLBACK_MODEL", OLLAMA_MODEL)

OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "90"))
TEMPERATURE = float(os.getenv("TEMPERATURE", "0"))
NUM_CTX = int(os.getenv("NUM_CTX", "4096"))

# Circuit Breaker & Rate Limit Configuration
CIRCUIT_BREAKER_FAILURES = int(os.getenv("CIRCUIT_BREAKER_FAILURES", "3"))
CIRCUIT_BREAKER_COOLDOWN = int(os.getenv("CIRCUIT_BREAKER_COOLDOWN", "60"))
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "15"))

# Multi-Pass Repair Loop Limits
MAX_ROUNDS = int(os.getenv("REPAIR_MAX_ROUNDS", "15"))
MAX_SYNTAX_ROUNDS = int(os.getenv("REPAIR_MAX_SYNTAX_ROUNDS", "10"))
MAX_ISSUES = int(os.getenv("REPAIR_MAX_ISSUES", "30"))
TOTAL_SANDBOX_TIMEOUT = float(os.getenv("TOTAL_SANDBOX_TIMEOUT", "2.0"))
PER_STATEMENT_TIMEOUT = float(os.getenv("PER_STATEMENT_TIMEOUT", "0.6"))
MAX_PATCH_LINES = int(os.getenv("MAX_PATCH_LINES", "3"))
LLM_CONTEXT_LINES = int(os.getenv("LLM_CONTEXT_LINES", "30"))

# AST Visualizer Display Thresholds (no hard-coded limits elsewhere)
AST_GRAPH_MAX_NODES = int(os.getenv("AST_GRAPH_MAX_NODES", "150"))
AST_GRAPH_MAX_LINES = int(os.getenv("AST_GRAPH_MAX_LINES", "60"))
AST_TEXT_MAX_ROWS = int(os.getenv("AST_TEXT_MAX_ROWS", "3000"))
AST_DEFAULT_MAX_DEPTH = int(os.getenv("AST_DEFAULT_MAX_DEPTH", "6"))

# Target Python Errors to Handle
TARGET_ERRORS = [
    "SyntaxError",
    "IndentationError",
    "NameError",
    "TypeError",
    "ValueError",
    "IndexError",
    "KeyError",
    "AttributeError",
    "ImportError",
    "ModuleNotFoundError",
    "ZeroDivisionError",
    "FileNotFoundError",
    "UnboundLocalError",
    "RecursionError",
    "StopIteration"
]
