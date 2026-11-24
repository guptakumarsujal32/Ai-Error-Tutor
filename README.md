# 🎓 AI Error Tutor

An intelligent, pedagogical Python error tutor and compiler assistant that diagnoses runtime defects, generates concrete educational explanations (with a strict **Zero-Analogies Policy**), verifies code fixes in a local sandbox before recommending them, and tracks error frequency distribution in real time using a CodeChef-style IDE.

Powered by a **3-Tier Hybrid AI Provider Chain**: **Tier 1 Gemini API** (primary cloud AI via `google-genai`), **Tier 2 Local LLM via Ollama** (`qwen2.5-coder:3b` offline backup), and **Tier 3 Rule-based AST Engine** (deterministic fallback), backed by a **4-Pass Multi-Error Self-Healing Engine** and **Agentic AI (AAI) Security Guard**.

---

## 🌟 Key Features

1. **3-Tier Hybrid LLM & Fallback Architecture**:
   - **Tier 1 — Gemini API (Primary Cloud AI)**: Uses the official `google-genai` SDK with JSON output mode (`response_mime_type="application/json"`), `temperature=0`, automatic secret redaction, small ~30-line context windows, session hash caching, and a circuit breaker (3 consecutive failures → 60s cooldown).
   - **Tier 2 — Local LLM via Ollama (Secondary Fallback)**: Automatic offline fallback to local `qwen2.5-coder:3b` whenever Gemini has no API key, no internet, times out, returns HTTP 429/5xx, or produces invalid JSON after one retry. Also used exclusively by the **Attack Lab** so red-team payloads never leave the machine.
   - **Tier 3 — AST Rule-based Engine (Final Fallback)**: Deterministic Abstract Syntax Tree engine providing instant offline diagnosis and repair when both Gemini and Ollama are unavailable, as well as a fast-path for trivial exact-match typos.

2. **4-Pass Multi-Error Self-Healing Engine (`analyze_all`)**:
   - Rather than halting at the first syntax or runtime exception, the engine carries out a multi-pass diagnostic and repair sequence:
     - **Stage 0 (Security Gate Pre-Check)**: Fail-closed static scan via `AAISecurityGuard` and `Bandit` intercepting prompt injections, system commands (`os.system`, `subprocess`), and oversized payloads (>5,000 lines / 500,000 chars).
     - **Pass 1 (Static AST Diagnostics)**: Single-sweep AST scanner detecting syntax defects, undefined global symbols, unused imports, unused variables, bare excepts, and mutable defaults.
     - **Pass 2 (Resilient Dynamic Run — `execute_resilient`)**: Executes each top-level statement in an AST-wrapped isolated subprocess sandbox, capturing all independent runtime exceptions simultaneously across the entire file.
     - **Pass 3 (Iterative Small-Context Fix Loop)**: Feeds minimal ~30-line local code snippets to the LLM (or rule-based engine), validates patches ($\le$ 3 lines changed), verifies patches in the sandbox, detects newly unmasked errors, and guards against infinite loops across up to **15 repair rounds** (`MAX_ROUNDS = 15`).
     - **Pass 4 (Final Self-Healing Verification & Reporting)**: Re-executes the complete patched file in the sandbox. If clean, issues a green `✓ Final Sandbox Verification Passed` badge and generates a unified diff.

3. **Cascade Error Detection & Prioritization**:
   - Tracks root-cause errors versus downstream secondary crashes. If an upstream statement fails to define a variable (e.g. `x = 1/0` fails), subsequent statements referencing `x` are classified with a purple **`Cascade of #X`** badge.
   - The tutor prioritizes root causes first, preventing students from becoming overwhelmed by phantom secondary errors.

4. **Dual Pedagogical Modes**:
   - **Direct Solution Mode**: Direct diagnostic summaries, verified code resolutions, typo suggestions, and prevention best practices.
   - **Socratic Hint Mode**: Guides students with conceptual Socratic questions and multi-level progressive clues (`🔍 Clue Level 1, 2, 3`), keeping solutions collapsed until requested. The tutor receives only the diagnosis—never the code fix—and verifies hints do not leak code replacements.

5. **1-Click Fixes & "⚡ Apply All Fixes"**:
   - **Single-Error Apply**: In Tab 2 ("💡 Tutor & Fix"), students can apply individual verified patches directly to the editor.
   - **⚡ Apply All Fixes**: In Tab 3 ("📄 Fixed Code"), students can apply the complete multi-error repaired program with a single click once sandbox verification confirms zero remaining errors.
   - **Safety Invariant**: The Apply buttons are disabled until the fix passes sandbox verification, guaranteeing that user code is never overwritten with broken patches.

6. **"🔧 Fix Warnings" Automated Cleaner**:
   - A dedicated 1-click cleaner in Tab 1 ("🔎 Diagnostics & AST") that automatically removes unused imports (`math`, `decimal`), bare except handlers, and unused variables without modifying business logic.

7. **Multi-Tab Code Editor (Multi-File IDE)**:
   - Full multi-tab editing environment allowing users to create, switch, rename, and delete multiple Python files (`main.py`, `utils.py`, `test.py`) with per-tab execution and state persistence.

8. **Agentic AI (AAI) Security Guard & OWASP Top 10 Compliance**:
   - **Ingress Inspection**: Detects and neutralizes prompt injections, policy bypass attempts, system prompt extraction, and indirect docstring injections before AI inference.
   - **Egress Guard**: Scans candidate healed code for covert Trojan implants (e.g. exfiltrating `.env`, secret tokens, SSH keys, or executing obfuscated bytecode).
   - **OWASP Top 10 (2025/2021) & LLM Top 10 Mitigation**: Comprehensive architectural defense against Broken Access Control (A01), Injection (A05), Mishandling of Exceptional Conditions (A10), and Supply Chain vulnerabilities.
   - **Threat Scoring & Audit**: Computes quantitative risk scores (0–100) and writes structured security audit logs (`.security_scans/security_audit.jsonl`).

9. **Multi-Agent Compiler System (MACS)**:
   - Deconstructs compilation into specialized agent personas communicating via a central blackboard:
     - `SecuritySentinelAgent` (Ingress Threat Modeling & Sanitization)
     - `SyntaxGrammarAgent` (Phases 1 & 2: Lexical Analysis & Concrete Syntax Trees)
     - `SemanticScopeAgent` (Phase 3: Scope Resolution & Symbol Tables)
     - `OptimizationProfilerAgent` (Phase 5: Performance Profiling & Code Health)
     - `RuntimeWatchdogAgent` (Phase 6: Code Generation & Execution Sandbox)
     - `SelfHealingVerifierAgent` (Quality Assurance & Egress Trojan Guard)
     - `CompilerOrchestratorAgent` (Blackboard Coordinator & Meta-Tutor)

10. **Static Code Health & Optimality Scorecard**:
    - Real-time static AST analysis evaluating **Security Posture** and **Algorithmic Efficiency**.
    - Evaluates Cyclomatic Complexity, Maintainability Index, Halstead volume, lines of code (LOC), class/function counts, nested loop bottlenecks ($O(N^2)+$), and anti-patterns.

11. **Green Computing / Sustainability**:
    - Integrated with **CodeCarbon** to monitor and track computational emissions during analysis.

---

## 🏗️ Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                      USER PYTHON CODE / MULTI-TAB IDE                  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│          STAGE 0: AGENTIC AI INGRESS GUARD & SECURITY SENTINEL         │
│   • Prompt Injection & Jailbreak Defense  • Risk Scoring (0–100)       │
│   • Bandit AST Vulnerability Scanner      • Audit Logging              │
│   • Payload Caps (5,000 lines / 500,000 chars max)                     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (Clean)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│             STAGE 1: 4-PASS MULTI-ERROR REPAIR LOOP ENGINE             │
│   • Pass 1: Static AST Scan (Syntax repair + Symbol table + Warnings)  │
│   • Pass 2: Resilient Dynamic Run (Per-stmt execution + Cascades)      │
│   • Pass 3: Iterative Fix Loop (LLM / Rule patches <=3 lines, 15 rds)  │
│   • Pass 4: Final Sandbox Self-Healing Verification + Unified Diff     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (Candidate Fixes Generated)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│              STAGE 2: 3-TIER HYBRID LLM PROVIDER CHAIN                 │
│    Tier 1: Gemini API (google-genai SDK, secret redaction, JSON mode)  │
│      └─▶ (No Key / Timeout / 429 / 5xx / Circuit Open)                 │
│            ──▶ Tier 2: Local LLM (Ollama qwen2.5-coder:3b)             │
│                  └─▶ (Offline) ──▶ Tier 3: AST Rule-Based Engine       │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (Patched Code)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│       STAGE 3: EGRESS TROJAN GUARD & PRE-RECOMMENDATION SANDBOX        │
│   • Egress Guard: Checks fix for PII/secret harvesting & backdoors     │
│   • Execute candidate fix in isolated sandbox                          │
│   • Output: Verified Clean Code or Best Available Resolution           │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│               CODECHEF-STYLE TWO-PANE STREAMLIT IDE                    │
│   [Left Pane (60%)]                   [Right Pane (40%)]               │
│   • Multi-Tab Code Editor             • Stdin Input Area               │
│   • Line-number error highlight       • Execution Output & Judge Pill  │
│   • Language / Theme / Font Controls  • Runtime & Memory Metrics       │
│   ───────────────────────────────────────────────────────────────────  │
│   [Bottom 7-Tab Panel]                                                 │
│   1. 🔎 Diagnostics & AST   2. 💡 Tutor & Fix     3. 📄 Fixed Code     │
│   4. 🛡️ Security & Audit    5. 📈 Code Health     6. 📊 Analytics      │
│   7. ⚔️ Attack Lab (Red-Team Security Sandbox)                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Streamlit 7-Tab Bottom Panel Guide

| Tab | Name | Capabilities & Features |
|:---:|------|-------------------------|
| **1** | **🔎 Diagnostics & AST** | List of all detected errors and warnings, **Cascade of #X** relationship badges, line-highlight buttons, **"🔧 Fix Warnings"** 1-click button, and AST Scope & Symbol Table Inspector. |
| **2** | **💡 Tutor & Fix** | Toggle between **Direct Solution** and **Socratic Hint Mode**. Shows concept tags, root-cause explanations, Level 1–3 progressive clues, inline unified diffs, and individual 1-click **Apply Fix** buttons. |
| **3** | **📄 Fixed Code** | Multi-error repair result summary, green **`✓ Final Sandbox Verification Passed`** badge, active **`⚡ Apply All Fixes`** button, combined unified diff, and complete repaired program viewer. |
| **4** | **🛡️ Security & Audit** | Ingress Security Sentinel status, AAI risk score (0–100), Bandit AST scan results, threat categories, and structured JSONL audit logs. |
| **5** | **📈 Code Health** | Software engineering metrics: Cyclomatic Complexity, Maintainability Index, Halstead Volume, LOC count, class/function counts, and algorithmic anti-pattern flags ($O(N^2)+$). |
| **6** | **📊 Session Analytics** | Real-time session error distribution charts, repair round statistics, time-to-fix tracking, and **CodeCarbon** computational emissions. |
| **7** | **⚔️ Attack Lab** | Automated defensive security audit suite: 33+ harmless curated seed attacks, active canary verification, LLM syntax mutations, and regression saving. |

---

## 📑 Formal Project Documentation (`docs/`)

The repository includes complete, publication-grade academic and security documentation in the `docs/` folder:

* **[AI_Error_Tutor_Project_Documentation.docx](docs/AI_Error_Tutor_Project_Documentation.docx)**: Comprehensive 7,644-word academic report formatted to IEEE specifications (Executive Summary, Problem Statement, 4-Pass Architecture, MACS Multi-Agent System, Threat Model, Verification Matrix, 20 Academic References).
* **[OWASP_Top_10_Security_Analysis_AI_Error_Tutor.pdf](docs/OWASP_Top_10_Security_Analysis_AI_Error_Tutor.pdf)**: Formal 5-page publication-quality security document detailing how AI Error Tutor mitigates OWASP Top 10 (A01–A10:2025/2021) and OWASP Top 10 for LLMs, backed by a 33-seed attack lab verification matrix.
* **[ai_error_tutor_architecture_white.png](docs/figures/ai_error_tutor_architecture_white.png)**: High-resolution (350 DPI) system architecture diagram with professional white background for academic presentation.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 to 3.14
- Windows 10/11, macOS, or Linux
- A **Gemini API Key** from [Google AI Studio](https://aistudio.google.com/apikey) (Tier 1 Primary Cloud AI)
- [Ollama](https://ollama.com/) installed locally (Tier 2 Offline Backup & Attack Lab)

### 1. Get a Gemini API Key & Create `.env`

1. Open [Google AI Studio](https://aistudio.google.com/apikey) and click **Create API key**.
2. Copy `.env.example` to `.env` in the project root:
   ```bash
   cp .env.example .env
   ```
3. Paste your key into `.env` (`.env` is listed in `.gitignore` and must never be committed):
   ```env
   GEMINI_API_KEY=your_real_gemini_key_here
   GEMINI_MODEL=gemini-3.5-flash-lite
   ```
   > **Note**: If `GEMINI_API_KEY` is not set, AI Error Tutor silently falls back to **Tier 2 (Local LLM via Ollama)** and displays a one-time notice (`"Gemini key not set, using local model"`). You can also switch between Cloud AI and Offline Mode anytime using the top-bar toggles.

### 2. Set Up Ollama (Tier 2 Local Backup & Attack Lab)

1. Download and install Ollama from [ollama.com](https://ollama.com/).
2. Pull the local fallback model:
   ```bash
   ollama pull qwen2.5-coder:3b
   ```
3. Start the Ollama local service:
   ```bash
   ollama serve
   ```

### 3. Set Up Virtual Environment & Install Dependencies

```bash
git clone <repo-url>
cd ai-error-tutor

# Create virtual environment
python -m venv .venv

# Activate on Windows PowerShell
.\.venv\Scripts\Activate.ps1

# (Or on Linux/macOS)
# source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configuration (`config.py`)

All provider order, model names, timeouts, and circuit-breaker thresholds live in `config.py` (overridable via `.env`):
```python
PROVIDER_ORDER = ["gemini", "ollama", "rules"]
GEMINI_MODEL = "gemini-3.5-flash-lite"
GEMINI_TIMEOUT = 30
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "qwen2.5-coder:3b"
OLLAMA_TIMEOUT = 90
TEMPERATURE = 0
CIRCUIT_BREAKER_FAILURES = 3
CIRCUIT_BREAKER_COOLDOWN = 60
RATE_LIMIT_RPM = 15
MAX_ROUNDS = 15
TOTAL_SANDBOX_TIMEOUT = 2.0
PER_STATEMENT_TIMEOUT = 0.6
MAX_ISSUES = 30
```

---

## 🖥️ Running the Application

### Streamlit Web IDE

```bash
streamlit run main.py
```
Open your browser to `http://localhost:8501`.

---

## 🧪 Comprehensive Automated Test Suite

AI Error Tutor comes with 100% automated test coverage across unit, pipeline, security, and UI layers:

```bash
# 1. Test the 4-Pass Multi-Error Repair Loop & Resilient Dynamic Run
python tests/test_repair_loop.py

# 2. Test 3-Tier Provider Fallback (Gemini -> Ollama -> Rule-based AST)
python tests/test_providers.py

# 3. Test the Attack Lab (33 Curated Seeds & Active Canary Verification)
python tests/test_attack_lab.py

# 4. Test Agentic AI (AAI) Ingress Guard & Prompt Injection Defense
python tests/simulate_aai_attacks.py

# 5. Test Multi-Agent Compiler System (MACS) Agents & Blackboard
python -m unittest tests/test_multi_agent_system.py

# 6. Test Streamlit UI End-to-End (All 7 Error Types, Modes, & Multi-Tab IDE)
python tests/test_streamlit_features_and_errors.py

# 7. Test Security Hardening (Bandit Scanner, Payload Caps, Sandbox Watchdog)
python tests/test_security_hardening.py

# 8. Test AST Scope & Symbol Table Visualizer
python tests/test_ast_visualizer.py
```

### Verified Test Matrix:
| Component | Tested Capabilities | Status |
|:---|:---|:---:|
| **4-Pass Repair Loop** | Iterative syntax repair, resilient dynamic execution, patch verification | `PASSED` |
| **Cascade Engine** | Upstream root cause tracking vs downstream `Cascade of #X` errors | `PASSED` |
| **3-Tier AI Providers** | Gemini Cloud API $\to$ Ollama Local $\to$ AST Rule fallback | `PASSED` |
| **AAI Security Guard** | Prompt injection, jailbreak defense, covert Trojan egress inspection | `PASSED` |
| **Bandit Scanner** | Automated pre-execution static AST vulnerability analysis | `PASSED` |
| **Attack Lab** | 33 curated attack seeds, ephemeral canary detection, containment | `PASSED` |
| **Multi-Agent Compiler** | Phases 1–6 specialized agents & blackboard orchestration | `PASSED` |
| **Streamlit 7-Tab IDE** | Multi-tab editor, Socratic hints, 1-click apply, health scorecard | `PASSED` |
| **Watchdog Sandbox** | 2.0s hard timeout, restricted builtins (`open`, `eval`, `exec`) | `PASSED` |

---

## 📄 License
MIT License. Built for educational excellence and resilient autonomous repair.
