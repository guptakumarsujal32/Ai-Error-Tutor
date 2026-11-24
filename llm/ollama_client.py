"""LLM Client Facade for AI Error Tutor.

Delegates inference to the 3-tier provider chain in llm/providers.py:
  Tier 1 (Primary):   Gemini API (google-genai SDK)
  Tier 2 (Secondary): Local LLM via Ollama (qwen2.5-coder:3b)
  Tier 3 (Fallback):  Deterministic Rule-based AST engine

Keeps the exact public API (ask_llm, OllamaClient, check_ollama_health,
wrap_code, wrap_error, LLMError) intact so all callers work seamlessly.
"""

import re
from typing import Dict, Any, Optional, List
import requests

import config
from llm.providers import (
    LLMError,
    ask_llm,
    get_router,
    get_gemini_api_key,
    parse_json_safely as _parse_json_safely,
    strip_markdown_fences as _strip_markdown_fences,
    redact_secrets,
    sanitize_log_message,
)


def wrap_code(code: str) -> str:
    """Enclose student code in untrusted data tags."""
    sanitized = _sanitize_tags(code)
    return f"<code>\n{sanitized}\n</code>"


def wrap_error(error_text: str) -> str:
    """Enclose error messages in untrusted data tags."""
    sanitized = _sanitize_tags(error_text)
    return f"<error>\n{sanitized}\n</error>"


def _sanitize_tags(text: str) -> str:
    """Strip attempts to forge internal tags."""
    if not text:
        return ""
    return re.sub(r'<\s*/?\s*(?:code|error|system|admin|instruction)\s*>', '', str(text), flags=re.IGNORECASE)


def check_ollama_health(timeout: float = 3.0) -> Dict[str, Any]:
    """
    Check if Ollama is running and whether required models are present.
    Calls GET {OLLAMA_URL}/api/tags.

    Returns:
        dict with keys: 'running', 'models', 'missing_models', 'message'
    """
    target_models = list(dict.fromkeys(list(config.MODELS.values()) + [config.FALLBACK_MODEL]))
    try:
        url = f"{config.OLLAMA_URL.rstrip('/')}/api/tags"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return {
                "running": False,
                "models": [],
                "missing_models": target_models,
                "message": "Ollama is not running. Start it with: ollama serve"
            }

        data = resp.json()
        available = [m.get("name", "") for m in data.get("models", [])]

        missing = []
        for req in target_models:
            req_base = req.split(":")[0]
            matched = any(
                req == a or a.startswith(f"{req}:") or a.startswith(f"{req_base}:")
                for a in available
            )
            if not matched:
                missing.append(req)

        if missing:
            return {
                "running": True,
                "models": available,
                "missing_models": missing,
                "message": f"Model missing. Run: ollama pull {missing[0]}"
            }

        return {
            "running": True,
            "models": available,
            "missing_models": [],
            "message": "Ollama is running with all models ready."
        }

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, Exception):
        return {
            "running": False,
            "models": [],
            "missing_models": target_models,
            "message": "Ollama is not running. Start it with: ollama serve"
        }


class OllamaClient:
    """High-level LLM client coordinating diagnostic, fixing, and Socratic roles across Tier 1/2/3."""

    def __init__(self):
        self.health = check_ollama_health(timeout=1.5)

    def is_available(self) -> bool:
        """Returns True if either Tier 1 (Gemini) or Tier 2 (Ollama) is available."""
        router = get_router()
        if (
            router.cloud_enabled
            and not router.offline_mode
            and get_gemini_api_key() is not None
            and not router.circuit_breaker.is_open()
        ):
            return True
        health = check_ollama_health(timeout=1.5)
        return health.get("running", False)

    def generate_direct_solution(self, error_type: str, error_message: str,
                                 code_context: str, full_code: str = "") -> Dict[str, Any]:
        """
        Generate Direct Solution using the diagnostician role.
        Sends only compact context (never huge files) wrapped in <code>/<error> tags.
        """
        # Keep cloud/local payloads bounded (~30 lines context for large files)
        if full_code and len(full_code.splitlines()) <= getattr(config, "LLM_CONTEXT_LINES", 30) * 2:
            raw_code = full_code
        else:
            raw_code = code_context or full_code
        wrapped_c = wrap_code(raw_code)
        wrapped_e = wrap_error(f"{error_type}: {error_message}")

        system_prompt = """You are an expert Python programming diagnostician and tutor.
Analyze the Python error and code.
CRITICAL INSTRUCTIONS:
- Be concise, accurate, and direct.
- Strict Zero-Analogies Policy: Do NOT use metaphors or analogies (no 'boxes', 'jars', 'traffic lights'). Explain the actual Python mechanics clearly.
- Provide the working corrected code in 'corrected_code'.
- Output MUST be valid JSON conforming to the example schema.

One-line JSON Schema Example:
{"concept": "Variable Scope", "explanation": "Variable 'x' is referenced before it was assigned a value.", "suggested_fix": "Define 'x' before calling it.", "corrected_code": "x = 10\\nprint(x)", "prevention_tip": "Always initialize variables before reading them."}
""".strip()

        user_content = f"Error details:\n{wrapped_e}\n\nStudent code to diagnose:\n{wrapped_c}"

        return ask_llm(
            role="diagnostician",
            system_prompt=system_prompt,
            user_content=user_content,
            expected_keys=["explanation"],
        )

    def _validate_and_sanitize_hints(self, hints: List[str], corrected_code: Optional[str],
                                     original_code: str, error_type: str) -> List[str]:
        """
        Check that progressive hints do not leak the exact corrected code line.
        If a hint contains the corrected line, regenerate or sanitize it.
        """
        if not hints or not corrected_code:
            return hints

        orig_lines = {l.strip() for l in original_code.splitlines() if l.strip()}
        fixed_lines = [l.strip() for l in corrected_code.splitlines() if l.strip() and len(l.strip()) > 3]
        changed_lines = [l for l in fixed_lines if l not in orig_lines]

        sanitized_hints = []
        for i, hint in enumerate(hints):
            has_leak = False
            for chg in changed_lines:
                if chg in hint or (len(chg) > 8 and chg.replace(" ", "") in hint.replace(" ", "")):
                    has_leak = True
                    break

            if has_leak:
                try:
                    regen_prompt = f"""You are a Python programming tutor.
A hint unintentionally spoiled the solution by including the exact code replacement.
Regenerate hint Level {i+1} as a purely conceptual clue without giving away any code syntax or function names.
Output MUST be valid JSON: {{"hint": "conceptual hint text"}}"""
                    regen_res = ask_llm(
                        role="tutor",
                        system_prompt=regen_prompt,
                        user_content=f"Error: {error_type}. Provide a subtle conceptual hint without mentioning code.",
                        expected_keys=["hint"],
                    )
                    new_hint = regen_res.get("hint", f"Think carefully about how Python evaluates expressions in {error_type}.")
                    sanitized_hints.append(new_hint)
                except Exception:
                    sanitized_hints.append(f"Examine the variables and operations involved in this {error_type} step-by-step.")
            else:
                sanitized_hints.append(hint)

        return sanitized_hints

    def generate_socratic_tutoring(self, error_type: str, error_message: str,
                                   code_context: str, full_code: str = "") -> Dict[str, Any]:
        """
        Generate Socratic Hint Mode materials.
        SECURITY & PEDAGOGY RULE: The tutor receives ONLY the diagnosis and error, NEVER the fixed code.
        Also validates that progressive hints do not leak the corrected code.
        """
        wrapped_e = wrap_error(f"{error_type}: {error_message}")
        wrapped_c = wrap_code(code_context)

        system_prompt = """You are an expert, patient Python programming tutor in Socratic Hint Mode.
Analyze the Python error and code context.
CRITICAL INSTRUCTIONS:
- You receive ONLY the error diagnosis and code context. You do NOT have the final answer.
- Strict Zero-Analogies Policy: Do NOT use metaphors or analogies.
- Formulate a thought-provoking Socratic question and exactly 3 progressive hints that lead the student to discover the fix.
- Do NOT output the corrected code line directly in the explanation or hints.
- Output MUST be valid JSON conforming to the example schema.

One-line JSON Schema Example:
{"concept": "String Concatenation", "explanation": "The '+' operator between str and int is not supported.", "socratic_question": "What type is the value you are adding to the string on line 2?", "progressive_hints": ["Check the data types being combined with '+'.", "Remember that numbers must be converted before string concatenation.", "Consider using str() or an f-string."], "suggested_fix": "Convert numeric variables to strings before concatenating.", "prevention_tip": "Use formatted string literals (f-strings) for combining text and variables."}
""".strip()

        user_content = f"Error details:\n{wrapped_e}\n\nContext:\n{wrapped_c}"

        socratic_result = ask_llm(
            role="tutor",
            system_prompt=system_prompt,
            user_content=user_content,
            expected_keys=["explanation"],
        )

        # Background fixer call so 1-Click Apply Fix is available only if student later requests answer
        fixer_prompt = """You are an expert Python code repair engine.
Fix the Python code to resolve the error. Provide the complete corrected working code.
Output MUST be valid JSON conforming to the example schema.

One-line JSON Schema Example:
{"corrected_code": "name = 'Alice'\\nprint('Hello ' + name)"}
""".strip()

        raw_code = (
            full_code
            if (full_code and len(full_code.splitlines()) <= getattr(config, "LLM_CONTEXT_LINES", 30) * 2)
            else code_context
        )
        fixer_content = f"Error:\n{wrapped_e}\n\nCode to fix:\n{wrap_code(raw_code)}"
        try:
            fix_res = ask_llm(
                role="fixer",
                system_prompt=fixer_prompt,
                user_content=fixer_content,
                expected_keys=["corrected_code"],
            )
            socratic_result["corrected_code"] = fix_res.get("corrected_code", "")
        except Exception:
            socratic_result["corrected_code"] = None

        hints = socratic_result.get("progressive_hints", [])
        socratic_result["progressive_hints"] = self._validate_and_sanitize_hints(
            hints=hints,
            corrected_code=socratic_result.get("corrected_code"),
            original_code=raw_code,
            error_type=error_type
        )

        return socratic_result

    def refine_fix(self, original_code: str, failed_fix_code: str,
                   error_type: str, error_message: str) -> Optional[str]:
        """Refine a proposed fix that failed verification in the execution sandbox."""
        wrapped_orig = wrap_code(original_code)
        wrapped_failed = wrap_code(failed_fix_code)
        wrapped_e = wrap_error(f"{error_type}: {error_message}")

        system_prompt = """You are an expert Python automated repair engine.
A previous code fix failed sandbox verification. Produce the revised, fully working Python code.
Output MUST be valid JSON conforming to the example schema.

One-line JSON Schema Example:
{"corrected_code": "def solve():\\n    return 42\\nprint(solve())"}
""".strip()

        user_content = (
            f"Original code:\n{wrapped_orig}\n\n"
            f"Failed attempt:\n{wrapped_failed}\n\n"
            f"Sandbox Error:\n{wrapped_e}\n\n"
            "Produce the corrected code in the 'corrected_code' JSON property."
        )

        try:
            res = ask_llm(
                role="fixer",
                system_prompt=system_prompt,
                user_content=user_content,
                expected_keys=["corrected_code"],
            )
            code = res.get("corrected_code", "")
            return _strip_markdown_fences(code) if code else None
        except Exception:
            return None

    def generate_minimal_patch(
        self,
        error_type: str,
        error_message: str,
        line_number: int,
        context_snippet: str,
        symbols_summary: str = "",
        rejection_reason: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Ask the active LLM provider (Tier 1 Gemini -> Tier 2 Ollama -> Tier 3 Rules)
        for a minimal <=3 line JSON patch using ONLY a small ~30-line context window.
        """
        wrapped_ctx = wrap_code(context_snippet)
        wrapped_err = wrap_error(f"Line {line_number}: {error_type}: {error_message}")

        system_prompt = (
            "You are a precise Python bug-fixing engine. "
            "Fix ONLY the reported error with the smallest possible change (at most 3 lines). "
            "Do NOT delete the failing statement without a replacement. "
            "Keep explanations concise and factual with zero analogies. "
            "Respond ONLY with valid JSON matching this example:\n"
            '{"line": 12, "old": "msg = \\"Age: \\" + age", "new": "msg = \\"Age: \\" + str(age)", '
            '"explanation": "Cannot add str and int without conversion.", '
            '"hint": "Check the data types on both sides of the + operator."}'
        )

        extra = f"\nSymbols in scope: {symbols_summary}" if symbols_summary else ""
        retry_note = f"\nPrevious patch rejected because: {rejection_reason}. Fix that issue." if rejection_reason else ""
        user_content = (
            f"Error:\n{wrapped_err}{extra}{retry_note}\n\n"
            f"Local code context (with line numbers):\n{wrapped_ctx}"
        )

        try:
            res = ask_llm(
                role="fixer",
                system_prompt=system_prompt,
                user_content=user_content,
                expected_keys=["line", "old", "new"],
                use_cache=not bool(rejection_reason),
            )
            if not isinstance(res, dict):
                return None
            # If Tier 3 Rule-based answered with an empty patch, let RepairLoop's AST rule engine patch it directly
            if res.get("_provider_id") == "rules" and not str(res.get("new") or "").strip():
                return None
            return {
                "line": int(res.get("line") or line_number),
                "old": str(res.get("old") or ""),
                "new": str(res.get("new") or ""),
                "explanation": str(res.get("explanation") or ""),
                "hint": str(res.get("hint") or ""),
                "_provider": res.get("_provider", "Local LLM (Ollama)"),
                "_provider_id": res.get("_provider_id", "ollama"),
                "_model_used": res.get("_model_used", config.MODELS.get("fixer", "qwen2.5-coder:3b")),
            }
        except Exception:
            return None

    def generate_socratic_hint_for_issue(
        self,
        error_type: str,
        error_message: str,
        line_number: int,
        context_snippet: str
    ) -> Optional[Dict[str, Any]]:
        """
        Ask the active LLM provider (role='tutor') for progressive Socratic hints (Levels 1-3)
        given ONLY the diagnosis—never the fix or patched code.
        """
        wrapped_ctx = wrap_code(context_snippet)
        wrapped_err = wrap_error(f"Line {line_number}: {error_type}: {error_message}")

        system_prompt = (
            "You are a Socratic Python tutor. NEVER reveal the fixed code or exact code replacement. "
            "Give a vague symptom summary and 3 progressive hints (from conceptual to specific direction). "
            "Respond ONLY with valid JSON matching this example:\n"
            '{"vague_description": "There is a data type mismatch on this line.", '
            '"hints": ["Check what types are combined in this expression.", '
            '"Python cannot combine text and numbers directly with +.", '
            '"Convert the numeric value into text before concatenating."]}'
        )

        user_content = f"Diagnosis:\n{wrapped_err}\n\nCode context:\n{wrapped_ctx}"
        try:
            res = ask_llm(
                role="tutor",
                system_prompt=system_prompt,
                user_content=user_content,
            )
            if not isinstance(res, dict):
                return None
            raw_hints = res.get("hints") or res.get("progressive_hints") or []
            if not isinstance(raw_hints, list):
                raw_hints = [str(raw_hints)]
            safe_hints = self._validate_and_sanitize_hints(
                hints=[str(h) for h in raw_hints[:3]],
                corrected_code=None,
                original_code=context_snippet,
                error_type=error_type,
            )
            return {
                "vague_description": str(res.get("vague_description") or f"Check the {error_type} near line {line_number}."),
                "hints": safe_hints,
                "_provider": res.get("_provider", "Local LLM (Ollama)"),
                "_provider_id": res.get("_provider_id", "ollama"),
                "_model_used": res.get("_model_used", config.MODELS.get("tutor", "qwen2.5-coder:3b")),
            }
        except Exception:
            return None
