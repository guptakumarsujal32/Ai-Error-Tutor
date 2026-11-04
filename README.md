# 🎓 AI Error Tutor

An intelligent, pedagogical Python error tutor that diagnoses runtime defects, generates concrete educational explanations (with a strict **Zero-Analogies Policy**), verifies code fixes in a local sandbox before recommending them, and tracks error frequency distribution in real time.

---

## 🌟 Key Features

1. **Multi-Tier AI Fallback Architecture**:
   - **Tier 1 (Cloud AI)**: Google Gemini Flash for deep semantic error analysis.
   - **Tier 2 (Neural Bridge)**: On-device fine-tuned Hugging Face T5 Transformer (`models/error_tutor_model/`) when offline or during cloud quota limits.
   - **Tier 3 (AST Engine)**: Deterministic rule-based Abstract Syntax Tree engine providing instant offline fallback.

2. **Pre-Recommendation Auto-Fix Sandbox Verification**:
   - Every generated fix is automatically executed in an isolated local sandbox **before** being presented to the user.
   - If the recommended code still triggers an error, the tutor enters an iterative self-correction loop (up to **3 sandbox attempts**) until a verified zero-error fix is achieved.
   - Verified fixes display a green `✓ Sandbox Verified (Attempt X/3)` badge.

3. **Multi-Agent Compiler System (MACS)**:
   - Deconstructs compilation into specialized agent personas communicating via a central blackboard:
     - `SecuritySentinelAgent` (Ingress Threat Modeling & Sanitization)
     - `SyntaxGrammarAgent` (Phases 1 & 2: Lexical Analysis & Concrete Syntax Trees)
     - `SemanticScopeAgent` (Phase 3: Scope Resolution & Symbol Tables)
     - `OptimizationProfilerAgent` (Phase 5: Performance Profiling & Code Health)
     - `RuntimeWatchdogAgent` (Phase 6: Code Generation & Execution Sandbox)
     - `SelfHealingVerifierAgent` (Quality Assurance & Egress Trojan Guard)
     - `CompilerOrchestratorAgent` (Blackboard Coordinator & Meta-Tutor)

4. **Agentic AI (AAI) Security Guard**:
   - **Ingress Inspection**: Detects and neutralizes prompt injections, policy bypass attempts, system prompt extraction, and indirect docstring injections before AI inference.
   - **Egress Guard**: Scans candidate healed code for covert Trojan implants (e.g. exfiltrating `.env`, `GEMINI_API_KEY`, SSH keys, or executing obfuscated bytecode).
   - **Threat Scoring & Audit**: Computes quantitative risk scores (0–100) and writes structured security audit logs (`.security_scans/security_audit.jsonl`).

5. **Dual Pedagogical Modes**:
   - **Direct Solution Mode**: Direct diagnostic summaries, verified code resolutions, typo suggestions, and prevention best practices.
   - **Socratic Hint Mode**: Guides students with conceptual Socratic questions and multi-level progressive clues (`🔍 Clue Level 1, 2, 3`), keeping solutions collapsed until requested.

6. **1-Click "Apply Fix to Editor"**:
   - Students can apply verified fixes directly into the code editor with a single click, instantly updating the code and clearing stale errors without copy-paste hassle.

7. **Static Code Health & Optimality Scorecard**:
   - Real-time static AST analysis evaluating **Security Posture** and **Algorithmic Efficiency**.
   - Detects nested loop bottlenecks ($O(N^2)+$), bare `except:` clauses, broad exception handling, and dangerous imports.

8. **Error Frequency & Learning Analytics**:
   - **Active Error Banner**: Shows occurrence counts and session percentage directly alongside the error (e.g. `Frequency: 3x (50% of session errors)`).
   - **Sidebar Session Stats**: Live counter of total runs, clean builds, and errors caught.
   - **Visual SVG Histogram**: Integer-based, responsive vector bar chart graphing error categories without fractional float ticks.
   - **Ranked Occurrence Cards**: Relative progress meters and exact percentage shares.
   - **Clean Session Reset**: 1-click reset button to clear session analytics anytime.

9. **Security Sandbox & Watchdog**:
   - **AST Security Gate**: Intercepts dangerous calls (`os.system`, `subprocess`, file deletion, shell execution) before execution.
   - **2.0s Hard Watchdog**: Kills infinite loops (`while True:`) and runaway recursions safely.

10. **Green Computing / Sustainability**:
    - Integrated with **CodeCarbon** to monitor and track computational emissions during AI inference.

---

## 🏗️ Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                          USER PYTHON CODE                              │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│          STAGE 0: AGENTIC AI INGRESS GUARD & SECURITY SENTINEL         │
│   • Prompt Injection & Jailbreak Defense  • Risk Scoring (0–100)       │
│   • Indirect Comment/Docstring Scans      • Audit Logging              │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (Clean)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│             STAGE 1: MULTI-AGENT COMPILER SYSTEM (MACS)                │
│   • SyntaxGrammarAgent   (Phases 1-2: Tokenize, Lex & Parse AST)       │
│   • SemanticScopeAgent   (Phase 3: Symbol Table & Scope Resolution)    │
│   • OptimizationProfiler (Phase 5: Complexity & Health Grading)        │
│   • RuntimeWatchdogAgent (Phase 6: Isolated Subprocess Execution)      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (Exception Detected)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   STAGE 2: MULTI-TIER AI INFERENCE                     │
│    Tier 1: Gemini Flash Cloud AI                                       │
│      └─▶ (Fallback 503/429) ──▶ Tier 2: Local T5 Neural Bridge         │
│                                  └─▶ (Offline) ──▶ Tier 3: AST Rules   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (Candidate Fix Generated)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│       STAGE 3: EGRESS TROJAN GUARD & PRE-RECOMMENDATION SANDBOX        │
│   • Egress Guard: Checks fix for PII/secret harvesting & backdoors     │
│   • Execute candidate fix in isolated sandbox                          │
│   • If error persists ──▶ Self-correct & re-verify (Max 3 attempts)    │
│   • Output: Verified Clean Code or Best Available Resolution           │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    BALANCED STREAMLIT 2-COLUMN UI                      │
│   [Left Column]                        [Right Column]                  │
│   • Live Editor & Stats                • Diagnostics & Line Highlight  │
│   • 9 Quick Bug & Attack Presets       • Socratic Hints / Direct Mode  │
│   • Health & Optimality Scorecard      • 1-Click "Apply Fix" Card      │
│   ───────────────────────────────────────────────────────────────────  │
│   [Bottom Panel] Real-Time Error Frequency SVG Histogram & Analytics   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 to 3.14
- Windows 10/11, macOS, or Linux

### 1. Clone & Set Up Virtual Environment

```bash
git clone <repo-url>
cd ai-error-tutor

# Create virtual environment
python -m venv .venv

# Activate on Windows PowerShell
.\.venv\Scripts\Activate.ps1

# (Or on Linux/macOS)
# source .venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. (Optional) Configure Gemini API Key

Create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```
> **Note**: Even without a Gemini API key or internet access, AI Error Tutor functions seamlessly via its **Tier 2 Local T5 Model** and **Tier 3 AST Engine**!

---

## 🖥️ Running the Application

### Option A: Streamlit Web UI (Recommended)

```bash
python -m streamlit run main.py
```
Open your browser to `http://localhost:8501`.

### Option B: Terminal Live Demo (No Browser Required)

```bash
python demo.py
```
Runs 6 interactive showcases directly in your terminal, demonstrating typo fixes, Socratic mode, security interception, infinite loop protection, code health scoring, and Agentic AI prompt injection defense.

---

## 🧪 Automated Test Suite

AI Error Tutor comes with comprehensive test coverage:

```bash
# 1. Run the Agentic AI (AAI) attack simulation & security benchmark (20 scenarios)
python tests/simulate_aai_attacks.py

# 2. Run the Multi-Agent Compiler System (MACS) unit test suite
python -m unittest tests/test_multi_agent_system.py

# 3. Run the complete Streamlit UI & 7 error categories end-to-end test
python tests/test_streamlit_features_and_errors.py

# 4. Run the 21-point comprehensive matrix (100% pass)
python -m unittest tests/test_comprehensive_matrix.py

# 5. Run the 3-attempt sandbox fix verification test
python -m unittest tests/test_fix_verification.py

# 6. Run full discovery across all unit tests
python -m unittest discover tests
```

### Verified Test Matrix Coverage:
| Test Category | Test Case | Status |
|---|---|:---:|
| **AAI Security Guard** | Prompt injection, policy bypass, & Trojan defense (100% Precision/Recall) | `PASSED` |
| **Multi-Agent Compiler**| Phase 1-6 specialized agents & blackboard orchestration | `PASSED` |
| **Streamlit UI End-to-End**| 7 error types, theme toggling, Socratic hints, & apply fix | `PASSED` |
| **Sandbox Watchdog** | Infinite loop timeout termination | `PASSED` |
| **AST Security** | Intercepting hostile `os.system` / subprocess | `PASSED` |
| **Fix Verification** | 3-attempt sandbox pre-verification loop | `PASSED` |
| **Pedagogical Modes** | Socratic questions + progressive clues | `PASSED` |
| **1-Click Apply Fix** | In-place editor updates & clean re-analysis | `PASSED` |
| **Static Health** | Optimality & security grading | `PASSED` |
| **Levenshtein Engine**| Typo suggestions for misspelled identifiers | `PASSED` |
| **Multi-Tier AI** | Seamless cascade from Cloud AI to Local T5 to AST | `PASSED` |

---

## 📊 Supported Error Categories

- `AttackBlocked` (Agentic AI prompt injection, policy bypass, Trojan implants)
- `NameError` (Undefined variables, missing imports, Levenshtein typo fixes)
- `TypeError` (String/int concatenation, uncalled functions, invalid operations)
- `SyntaxError` (Missing colons, unmatched parentheses, syntax violations)
- `IndentationError` (Mismatched indents, missing block bodies)
- `ZeroDivisionError` (Division/modulo by zero)
- `IndexError` (List/tuple sequence indices out of range)
- `KeyError` (Missing dictionary keys)
- `AttributeError` (Non-existent object methods/attributes)
- `ValueError` (Invalid arguments or unparseable formats)
- `TimeoutError` (Infinite loops, runaway recursions caught by 2.0s watchdog)
- `SecurityError` (Hostile syscalls, banned modules, unsafe execution)
- `ImportError` / `ModuleNotFoundError` (Uninstalled or misspelled modules)
- `UnboundLocalError` (Referencing local variable before assignment)

---

## 📄 License
MIT License. Built for educational excellence.