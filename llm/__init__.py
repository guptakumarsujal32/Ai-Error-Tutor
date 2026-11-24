"""Ollama Local LLM Integration Package for AI Error Tutor."""

from .ollama_client import (
    ask_llm,
    check_ollama_health,
    LLMError,
    wrap_code,
    wrap_error,
    OllamaClient
)

__all__ = [
    "ask_llm",
    "check_ollama_health",
    "LLMError",
    "wrap_code",
    "wrap_error",
    "OllamaClient"
]
