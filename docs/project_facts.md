# Verified Project Facts (`docs/project_facts.md`)

Audited directly from the repository source files at `c:\codes\AI Error Tutor\AI Error Tutor\ai-error-tutor`. Only features verified in live code are listed as implemented.

---

## 1. Verified Live System Pipeline

1. **User Interface (`main.py`, `ui/layout.py`, `ui/styles.css`, `ui/execution_engine.py`)**
   - CodeChef-style two-pane Streamlit IDE (`st.set_page_config(layout="wide")`), Light/Dark theme toggle, demo snippet selector, multi-tab code editor (`main.py`, `+`, `×`, isolated per-tab widget keys, disabled browser spellcheck, pixel-aligned error-line highlights, Clear Editor, Download Code), custom `stdin` input, and live output terminal (`SafeExecutionEngine`, temp-file execution avoiding Windows 32 KB `WinError 206`).
   - Eight bottom tabs: **Diagnostics**, **Tutor & Fix**, **Fixed Code**, **AST Graph**, **Security & Audit**, **Code Health**, **Session Analytics**, and **Attack Lab**.
   - **Rate Limiter:** Sliding-window `15 requests/min` (`config.RATE_LIMIT_RPM = 15`), counting both run submissions and Gemini cloud calls.
   - **Carbon Tracker:** `codecarbon.EmissionsTracker` with a `55 W` TDP × `0.475 kg CO2/kWh` fallback model on Windows (when WDAC blocks PowerShell WMI queries), plus separate Cloud CO₂ (`~0.20 mg` per Gemini call) vs. Local CO₂ accounting.

2. **Ingress Security Gate (`src/aai_security_guard.py`, `src/security.py`)**
   - Input size cap: `5,000 lines` and `500,000 characters`.
   - **`AAISecurityGuard`**: Regex + heuristic prompt-injection, policy-bypass, indirect docstring/comment injection, credential/PII exfiltration, and obfuscated execution scanner; computes `0–100` risk score (`BENIGN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`); fail-closed quarantine; logs JSONL/text audit entries to `.security_scans/security_audit.jsonl`.
   - **`CodeSecurityValidator`**: AST + regex fallback SAST blocking dangerous modules (`subprocess`, `ctypes`, `multiprocessing`, `socket`, `http`, `urllib`, `requests`, `ftplib`, `xmlrpc`, `smtplib`, `poplib`, `imaplib`, `importlib`, `code`, `codeop`, `signal`, `resource`), dangerous builtins (`exec`, `eval`, `compile`, `__import__`, `globals`, `locals`, `breakpoint`), dangerous `os`/`shutil`/`sys`/`pathlib` methods, and `open(` / `.write(`. Also runs `python -m bandit -q -f json` (fail-closed, 10 s timeout).
   - Blocked/quarantined code halts immediately and never enters the sandbox or any LLM provider.

3. **Isolated Subprocess Sandbox (`src/error_capture.py`)**
   - **`execute_code()`**: Subprocess execution with restricted builtins (`open`, `eval`, `exec`, `compile`, `breakpoint`, `exit`, `quit` raise `PermissionError`), guarded `__import__`, `sys.setrecursionlimit(500)`, `50 KB` output cap, and `2.0 s` wall-clock timeout (extended to `6.0 s` only when heavy C-extension libraries such as `pandas`/`numpy` are imported).
   - **`execute_resilient()` (Pass 2)**: Executes each top-level AST statement inside its own `try/except` sharing one namespace, records all exceptions in a single run, detects and labels cascade `NameError`s (`cascade_of`), and enforces `0.6 s` per-statement and `2.0 s` total timeouts via `sys.settrace` (excluding `ast.Import`/`ast.ImportFrom` startup from false infinite-loop triggers).

4. **AST Context Extractor & Typo Matcher (`src/ast_parser.py`)**
   - Parses code with `ast.parse`, extracts enclosing function/class, AST node type, module/function-level symbol tables (`variables_in_scope`), imports, and function calls, and suggests typo corrections using Levenshtein / edit-distance matching (`similar_names`).

5. **Three-Tier Hybrid LLM Provider Chain (`llm/providers.py`, `llm/ollama_client.py`, `config.py`)**
   - Public facade `ask_llm(role, system_prompt, user_content)` tries providers in `PROVIDER_ORDER = ["gemini", "ollama", "rules"]`:
     - **Tier 1 (`GeminiProvider`)**: Official `google-genai` SDK, `GEMINI_MODEL = "gemini-3.5-flash-lite"` (configurable via `.env`), `GEMINI_TIMEOUT = 30 s`, `TEMPERATURE = 0`, `response_mime_type = "application/json"`, 1 automatic retry on invalid JSON, and automatic fallback to `gemini-3.5-flash-lite` on `404`/`504`.
     - **Tier 2 (`OllamaProvider`)**: Local Ollama HTTP `/api/chat` (`OLLAMA_URL = "http://localhost:11434"`, `OLLAMA_MODEL = "qwen2.5-coder:3b"`, `OLLAMA_TIMEOUT = 90 s`, `NUM_CTX = 4096`, `format = "json"`), with primary + `FALLBACK_MODEL` retry.
     - **Tier 3 (`RuleBasedProvider`)**: Deterministic AST/rule fallback returning structured JSON when both Gemini and Ollama fail.
   - **Circuit Breaker:** Opens after `CIRCUIT_BREAKER_FAILURES = 3` consecutive Gemini failures for `CIRCUIT_BREAKER_COOLDOWN = 60 s`.
   - **Privacy & Security:** `GEMINI_API_KEY` read strictly from `.env`/environment, scrubbed from all logs/errors/UI (`sanitize_log_message`); `redact_secrets()` irreversibly replaces API keys, passwords, bearer tokens, emails, and long high-entropy strings before any cloud call; student code and errors fenced in `<code>...</code>` and `<error>...</error>` tags with a passive-data system directive.
   - **Efficiency:** In-session SHA-256 hash cache keyed by `(role, system_prompt, user_content, provider_order)`; rule-based fast-path for high-confidence single-token typos.

6. **Multi-Agent Roles (`src/multi_agent_system.py`, `llm/providers.py`, `agents/attacker.py`)**
   - Compiler-phase agents in `src/multi_agent_system.py`: `SecuritySentinelAgent` (Guardian), `SyntaxGrammarAgent`, `SemanticScopeAgent`, `OptimizationProfilerAgent`, `RuntimeWatchdogAgent` (Executor), `SelfHealingVerifierAgent` (Verifier), and `CompilerOrchestratorAgent`.
   - LLM roles in `config.py`: `diagnostician`, `fixer`, `tutor`, `critic`, and `attacker` (locked exclusively to local Ollama; never calls Gemini).

7. **Four-Pass Multi-Error Repair Loop & Self-Healing Verification (`engine/repair_loop.py`, `src/pipeline.py`)**
   - **Pass 1 (Static Scan):** Iterative syntax repair (`MAX_SYNTAX_ROUNDS = 10`) + `StaticASTScanner` single-sweep checks (undefined names, unused imports/variables, use-before-assignment, missing returns, wrong argument counts, literal type misuse, mutable default arguments, bare `except`).
   - **Pass 2 (Resilient Dynamic Run):** Collects all runtime exceptions + cascade references in one sandboxed run.
   - **Pass 3 (Small-Context Fix Loop):** Sorts issues by line, builds `<= 30`-line local context (`LLM_CONTEXT_LINES = 30`) + symbol table, applies `<= 3`-line JSON patches (`MAX_PATCH_LINES = 3`) deterministically, enforces anti-trojan & import-egress checks, re-runs Pass 2 to block regressions, retries/falls back to AST rules, loop protection (`MAX_ROUNDS = 15`, `MAX_ISSUES = 30`).
   - **Pass 4 (Final Report):** Full sandbox verification gates 1-click Apply (`verified = True`); warnings separated (`Fix Warnings`).

8. **Code Health Analyzer (`src/code_analyzer.py`)**
   - Static AST scoring (`0–100`, grades `A+`–`F`) for security posture and algorithmic efficiency (nested loops $O(N^2)+$, repeated loop string concatenation, manual `.append()` loops, membership checks inside loops).
   - *Note:* Formal McCabe cyclomatic complexity is **not** explicitly computed as a numeric metric in `src/code_analyzer.py` (it checks loop nesting depth and common anti-patterns). We will describe what `code_analyzer.py` actually computes and note formal cyclomatic complexity in Background Concepts / Future Scope.

9. **Pedagogical Modes (`llm/ollama_client.py`, `engine/repair_loop.py`, `ui/layout.py`)**
   - **Direct Solution Mode:** Zero-analogies explanations, unified diff, gated 1-click Apply.
   - **Socratic Hint Mode:** Tutor receives only error diagnosis (never fixed code); 3 progressive hint levels (`Need another hint`), post-generation hint-leak validator (`_validate_and_sanitize_hints`), locked fix reveal, and solved-issue tracking across re-runs.

10. **Adaptive AST Visualiser (`src/ast_visualizer.py`, `ui/layout.py`)**
    - Pure `ast.parse()` only (never executes code; catches `SyntaxError`, `RecursionError`, `MemoryError`, `ValueError`).
    - Size rule (`config.py`): `AST_GRAPH_MAX_NODES = 150` AND `AST_GRAPH_MAX_LINES = 60` → **Graph mode** (`st.graphviz_chart`, DOT string, category colors, error/warning highlights + tooltips, Simplified/Full, TB/LR, Download DOT); otherwise **Text mode** (collapsible `st.expander` per function/class/top-level block, search filter, `Max depth` default `6`, `3,000`-row cap with truncation banner, Download `.txt`). Includes `"Your code"` and `"After fixes"` sub-tabs and `@st.cache_data` hash caching.

11. **Defensive Red-Team Attack Lab (`agents/attacker.py`, `attack_runner.py`, `attacks/seed_attacks.json`)**
    - 33 curated seed attacks across 11 categories (3 seeds each), optional local-Ollama-only mutations (clamped 1–3), `CanaryManager` (ephemeral temp file + env token + watchdog breach check), verdicts (`BLOCKED_BY_GUARDIAN`, `CONTAINED_BY_SANDBOX`, `ESCAPED`), regression saving to `tests/attacks/escaped_attacks.json`, and human-review remediation text.

---

## 2. Unconfirmed / Missing / Legacy Items (Explicitly Tracked)

* **Legacy T5 artifacts on disk:** `models/error_tutor_model/` and `data/error_dataset.csv` exist from an earlier prototype (`notebooks/train_model.ipynb`), but the live pipeline in `src/pipeline.py`, `engine/repair_loop.py`, and `llm/providers.py` does **not** load T5; it uses the 3-tier Gemini / Ollama / AST chain.
* **No `tests/buggy_programs` directory:** The repository contains `test_5000_lines_buggy.py` plus 14 test files in `tests/` (`test_repair_loop.py`, `test_providers.py`, `test_ast_visualizer.py`, `test_attack_lab.py`, `test_security_hardening.py`, `test_fix_verification.py`, `test_ollama_pipeline.py`, `test_comprehensive_matrix.py`, etc.), not a subfolder named `tests/buggy_programs`.
* **No `docs/screenshots/` folder yet:** No application screenshot PNGs exist in `docs/screenshots/`; we will create clearly marked placeholders with exact filenames and log them in `docs/todo_for_me.md`.
* **No user study / BLEU / ROUGE / 800-sample dataset metrics:** None exist in the codebase or logs; we will NOT copy the template's numbers and will insert yellow `[TO BE FILLED: ...]` placeholders only where human evaluation is discussed (and list them in `docs/todo_for_me.md`).
