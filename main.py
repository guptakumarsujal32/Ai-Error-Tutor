"""Streamlit UI for AI Error Tutor - CodeChef IDE Edition.

High-performance, two-pane IDE interface for Python error diagnostics,
security threat interception, and self-healing pedagogical tutoring.
"""

import os
import time
import math
import html
import streamlit as st
from codecarbon import EmissionsTracker

import config
from src.pipeline import AIErrorTutor
from llm.providers import get_router
from llm.ollama_client import check_ollama_health
import importlib
import src.error_capture as _ec_mod
importlib.reload(_ec_mod)
import src.ast_visualizer as _ast_vis_mod
importlib.reload(_ast_vis_mod)
from ui.execution_engine import SafeExecutionEngine, ExecutionResult
import ui.layout as _ui_layout
importlib.reload(_ui_layout)
import engine.repair_loop as _repair_loop_mod
importlib.reload(_repair_loop_mod)
from ui.layout import (
    DEMO_CODES,
    DEFAULT_SAMPLE_CODE,
    render_topbar,
    render_editor_pane,
    render_terminal_pane,
    render_bottom_panel,
    get_rate_limit_state,
    get_tab_widget_key,
    record_request_timestamp,
)

# ─────────────────────────────────────────────
# Streamlit Page Configuration
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="AI Error Tutor | IDE Compiler",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─────────────────────────────────────────────
# Session State Initialization
# ─────────────────────────────────────────────
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

if "total_runs" not in st.session_state:
    st.session_state.total_runs = 0

if "successful_runs" not in st.session_state:
    st.session_state.successful_runs = 0

if "error_stats" not in st.session_state:
    st.session_state.error_stats = {}

if "tutor_mode" not in st.session_state:
    st.session_state.tutor_mode = "Direct Solution"

if "hint_level" not in st.session_state:
    st.session_state.hint_level = 1

if "last_verified_fix" not in st.session_state:
    st.session_state.last_verified_fix = None

if "code_area" not in st.session_state:
    st.session_state["code_area"] = DEFAULT_SAMPLE_CODE

if "stdin_input" not in st.session_state:
    st.session_state["stdin_input"] = ""

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if "last_execution" not in st.session_state:
    st.session_state.last_execution = None

if "editor_version" not in st.session_state:
    st.session_state.editor_version = 0

if "editor_font_size" not in st.session_state:
    st.session_state.editor_font_size = 14

if "session_emissions_kg" not in st.session_state:
    st.session_state.session_emissions_kg = 0.0

if "cloud_emissions_kg" not in st.session_state:
    st.session_state.cloud_emissions_kg = 0.0

if "local_emissions_kg" not in st.session_state:
    st.session_state.local_emissions_kg = 0.0

if "cloud_ai_enabled" not in st.session_state:
    st.session_state.cloud_ai_enabled = True

if "offline_mode" not in st.session_state:
    st.session_state.offline_mode = False

if "missing_key_notice_shown" not in st.session_state:
    st.session_state.missing_key_notice_shown = False

# Sync provider toggles with global ProviderRouter
get_router().set_mode(
    cloud_enabled=bool(st.session_state.cloud_ai_enabled),
    offline_mode=bool(st.session_state.offline_mode),
)

if "request_timestamps" not in st.session_state:
    st.session_state.request_timestamps = []

if "attack_round_results" not in st.session_state:
    st.session_state.attack_round_results = None

if "editor_tabs" not in st.session_state:
    st.session_state.editor_tabs = {
        "main.py": st.session_state.get("code_area", DEFAULT_SAMPLE_CODE)
    }

if "active_tab" not in st.session_state:
    st.session_state.active_tab = "main.py"

if "next_tab_num" not in st.session_state:
    st.session_state.next_tab_num = 2

if "repair_report" not in st.session_state:
    st.session_state.repair_report = None

if "highlighted_line" not in st.session_state:
    st.session_state.highlighted_line = None

if "previous_issue_sigs" not in st.session_state:
    st.session_state.previous_issue_sigs = []

if "solved_since_last_run" not in st.session_state:
    st.session_state.solved_since_last_run = []

if "socratic_active_idx" not in st.session_state:
    st.session_state.socratic_active_idx = 0

if "socratic_issue_hints" not in st.session_state:
    st.session_state.socratic_issue_hints = {}

if "socratic_revealed_answers" not in st.session_state:
    st.session_state.socratic_revealed_answers = set()

# ─────────────────────────────────────────────
# Load CSS Stylesheet & Active Theme (Dark / Light)
# ─────────────────────────────────────────────
css_path = os.path.join(os.path.dirname(__file__), "ui", "styles.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        custom_css = f.read()
    st.markdown(f"<style>{custom_css}</style>", unsafe_allow_html=True)

if not st.session_state.get("dark_mode", True):
    st.markdown("""
<style>
/* Light Mode Theme Overrides */
html, body, [data-testid="stAppViewContainer"], .stApp, [data-testid="stMain"] {
    background-color: #f6f8fa !important;
    color: #1f2328 !important;
}
.brand-main-title {
    color: #1f2328 !important;
}
button[kind="secondary"] {
    background: #ffffff !important;
    border: 1px solid #d0d7de !important;
    color: #1f2328 !important;
}
button[kind="secondary"]:hover {
    background: #f3f4f6 !important;
    border-color: #8c959f !important;
    color: #000000 !important;
}
[data-testid="stSelectbox"],
.stSelectbox {
    --st-secondary-background-color: #ffffff;
    --st-text-color: #1f2328;
}
[data-testid="stSelectbox"] [data-baseweb="select"],
[data-testid="stSelectbox"] [data-baseweb="select"] > div,
.stSelectbox [data-baseweb="select"],
.stSelectbox [data-baseweb="select"] > div {
    background-color: #ffffff !important;
    background: #ffffff !important;
    border: 1px solid #d0d7de !important;
    border-radius: 6px !important;
    color: #1f2328 !important;
    -webkit-text-fill-color: #1f2328 !important;
}
[data-testid="stSelectbox"] [data-baseweb="select"] > div div,
[data-testid="stSelectbox"] [data-baseweb="select"] > div span,
[data-testid="stSelectbox"] [data-baseweb="select"] > div input,
.stSelectbox [data-baseweb="select"] > div div,
.stSelectbox [data-baseweb="select"] > div span,
.stSelectbox [data-baseweb="select"] > div input {
    background-color: transparent !important;
    background: transparent !important;
    color: #1f2328 !important;
    -webkit-text-fill-color: #1f2328 !important;
}
[data-testid="stSelectbox"] [data-baseweb="select"] svg,
div[data-baseweb="select"] svg {
    color: #57606a !important;
    fill: #57606a !important;
}
body div[data-baseweb="popover"],
body div[data-baseweb="popover"] div,
body div[data-baseweb="menu"],
body ul[data-testid="stSelectboxVirtualDropdown"],
body ul[role="listbox"],
body ul[role="listbox"] li,
body li[role="option"],
body li[role="option"] div,
body li[role="option"] span {
    background-color: #ffffff !important;
    background: #ffffff !important;
    color: #1f2328 !important;
    -webkit-text-fill-color: #1f2328 !important;
    border-color: #d0d7de !important;
}
body ul[role="listbox"] li:hover,
body ul[role="listbox"] li:hover *,
body ul[role="listbox"] li[aria-selected="true"],
body ul[role="listbox"] li[aria-selected="true"] *,
body li[role="option"]:hover,
body li[role="option"]:hover *,
body li[role="option"][aria-selected="true"],
body li[role="option"][aria-selected="true"] * {
    background-color: #eaeef2 !important;
    color: #0969da !important;
    -webkit-text-fill-color: #0969da !important;
}
[data-testid="stDownloadButton"] button {
    background: #ffffff !important;
    border: 1px solid #d0d7de !important;
    color: #1f2328 !important;
    font-weight: 600 !important;
    border-radius: 6px !important;
}
[data-testid="stDownloadButton"] button:hover {
    background: #f3f4f6 !important;
    border-color: #8c959f !important;
    color: #000000 !important;
}
.version-pill {
    background: #ffffff !important;
    border: 1px solid #d0d7de !important;
    color: #1f2328 !important;
}
.stTextArea textarea {
    background-color: #ffffff !important;
    color: #1f2328 !important;
    border: 1px solid #d0d7de !important;
}
.stTextArea textarea::placeholder {
    color: #6e7781 !important;
}
.co2-badge {
    background: rgba(26, 127, 55, 0.1) !important;
    border: 1px solid rgba(26, 127, 55, 0.4) !important;
    color: #1a7f37 !important;
}
.ide-panel-header, .judge-header {
    background: #eaeef2 !important;
    border-color: #d0d7de !important;
    color: #1f2328 !important;
}
.ide-tab {
    background: #ffffff !important;
    color: #1f2328 !important;
    border-color: #d0d7de !important;
}
.ide-stats {
    color: #57606a !important;
}
.editor-wrapper {
    border-color: #d0d7de !important;
}
.judge-telemetry-bar {
    background: #f6f8fa !important;
    border-color: #d0d7de !important;
    color: #57606a !important;
}
.judge-telemetry-item strong {
    color: #1f2328 !important;
}
.terminal-screen {
    background: #ffffff !important;
    border-color: #d0d7de !important;
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.06) !important;
}
.terminal-success {
    color: #1a7f37 !important;
}
.terminal-error {
    color: #cf222e !important;
}
.terminal-timeout {
    color: #9a6700 !important;
}
.terminal-blocked {
    color: #cf222e !important;
}
.terminal-idle {
    color: #6e7781 !important;
}
.bottom-panel-container {
    background: #ffffff !important;
    border-color: #d0d7de !important;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.06) !important;
}
.diag-card, .verify-box, .hint-step-card, .health-metric-card, .audit-entry-card {
    background: #f6f8fa !important;
    border-color: #d0d7de !important;
    color: #1f2328 !important;
    box-shadow: none !important;
}
.metric-title {
    color: #57606a !important;
}
.metric-value {
    color: #1f2328 !important;
}
.ast-context-box {
    background: #f6f8fa !important;
    border-color: #d0d7de !important;
    color: #1f2328 !important;
}
.ast-label {
    color: #57606a !important;
}
.ast-value {
    color: #0969da !important;
}
.socratic-question-box {
    background: rgba(130, 80, 223, 0.08) !important;
    color: #1f2328 !important;
}
.build-successful-banner {
    background: #dafbe1 !important;
    color: #116329 !important;
}
.build-successful-banner div {
    color: #116329 !important;
}
button[data-baseweb="tab"] {
    color: #57606a !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: #1f2328 !important;
}
p, label, .stMarkdown, [data-testid="stWidgetLabel"] p {
    color: #1f2328 !important;
}
[data-testid="stExpander"] {
    background-color: #f6f8fa !important;
    border-color: #d0d7de !important;
    color: #1f2328 !important;
}
hr {
    border-top-color: #d0d7de !important;
}
</style>
""", unsafe_allow_html=True)
else:
    st.markdown("""
<style>
html, body, [data-testid="stAppViewContainer"], .stApp, [data-testid="stMain"] {
    background-color: #0e1117 !important;
    color: #f0f6fc !important;
}
.version-pill {
    background: #252526 !important;
    border: 1px solid #3e3e42 !important;
    color: #e0e0e0 !important;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# Backend Engines
# ─────────────────────────────────────────────
@st.cache_resource
def load_tutor():
    return AIErrorTutor()

tutor = load_tutor()
tutor.error_capture = _ec_mod.ErrorCapture()
exec_engine = SafeExecutionEngine(timeout_seconds=2.0)

# ─────────────────────────────────────────────
# State Callbacks
# ─────────────────────────────────────────────
def get_active_code() -> str:
    """Returns the live code string for the currently active editor tab."""
    active_tab = st.session_state.get("active_tab", "main.py")
    active_key = get_tab_widget_key(active_tab)
    if active_key in st.session_state:
        return st.session_state[active_key]
    return st.session_state.get("editor_tabs", {}).get(active_tab, DEFAULT_SAMPLE_CODE)

def on_apply_fix(fixed_code: str):
    """Applies verified code fix to the active editor tab only."""
    active_tab = st.session_state.get("active_tab", "main.py")
    active_key = get_tab_widget_key(active_tab)
    st.session_state[active_key] = fixed_code
    if "editor_tabs" in st.session_state:
        st.session_state.editor_tabs[active_tab] = fixed_code
    st.session_state["last_verified_fix"] = fixed_code
    st.session_state.editor_version = st.session_state.get("editor_version", 0) + 1
    st.session_state.last_result = None
    st.session_state.last_execution = None
    st.session_state.repair_report = None
    st.session_state.highlighted_line = None

def on_clear_editor():
    """Clears the active editor tab content only."""
    active_tab = st.session_state.get("active_tab", "main.py")
    active_key = get_tab_widget_key(active_tab)
    st.session_state[active_key] = ""
    if "editor_tabs" in st.session_state:
        st.session_state.editor_tabs[active_tab] = ""
    st.session_state.editor_version = st.session_state.get("editor_version", 0) + 1
    st.session_state.last_result = None
    st.session_state.last_execution = None
    st.session_state.repair_report = None
    st.session_state.highlighted_line = None

def on_demo_select():
    """Loads selected demo snippet into the active editor tab only."""
    choice = st.session_state.get("selected_demo_dropdown")
    if choice and choice != "— Select a snippet —" and choice in DEMO_CODES:
        active_tab = st.session_state.get("active_tab", "main.py")
        active_key = get_tab_widget_key(active_tab)
        st.session_state[active_key] = DEMO_CODES[choice]
        if "editor_tabs" in st.session_state:
            st.session_state.editor_tabs[active_tab] = DEMO_CODES[choice]
        st.session_state.editor_version = st.session_state.get("editor_version", 0) + 1
        st.session_state.last_result = None
        st.session_state.last_execution = None
        st.session_state.repair_report = None
        st.session_state.highlighted_line = None

def on_switch_tab(tab_name: str):
    """Switches to another code editor tab without leaking edits between tabs."""
    tabs = st.session_state.get("editor_tabs", {})
    curr_tab = st.session_state.get("active_tab", "main.py")
    if curr_tab in tabs:
        curr_key = get_tab_widget_key(curr_tab)
        if curr_key in st.session_state:
            tabs[curr_tab] = st.session_state[curr_key]
    if tab_name in tabs and tab_name != curr_tab:
        st.session_state.active_tab = tab_name
        new_key = get_tab_widget_key(tab_name)
        st.session_state[new_key] = tabs[tab_name]
        st.session_state.editor_version = st.session_state.get("editor_version", 0) + 1
        st.session_state.last_result = None
        st.session_state.last_execution = None

def on_add_tab():
    """Creates and activates a new isolated code editor tab."""
    tabs = st.session_state.get("editor_tabs", {})
    curr_tab = st.session_state.get("active_tab", "main.py")
    if curr_tab in tabs:
        curr_key = get_tab_widget_key(curr_tab)
        if curr_key in st.session_state:
            tabs[curr_tab] = st.session_state[curr_key]
    num = st.session_state.get("next_tab_num", 2)
    new_name = f"script_{num}.py"
    while new_name in tabs:
        num += 1
        new_name = f"script_{num}.py"
    st.session_state.next_tab_num = num + 1
    starter_code = f'# {new_name}\n\nprint("Hello from {new_name}!")\n'
    tabs[new_name] = starter_code
    st.session_state.active_tab = new_name
    new_key = get_tab_widget_key(new_name)
    st.session_state[new_key] = starter_code
    st.session_state.editor_version = st.session_state.get("editor_version", 0) + 1
    st.session_state.last_result = None
    st.session_state.last_execution = None

def on_close_tab(tab_name: str):
    """Closes the specified tab (keeps at least 1 tab open)."""
    tabs = st.session_state.get("editor_tabs", {})
    if len(tabs) <= 1 or tab_name not in tabs:
        return
    curr_tab = st.session_state.get("active_tab", "main.py")
    if curr_tab != tab_name and curr_tab in tabs:
        curr_key = get_tab_widget_key(curr_tab)
        if curr_key in st.session_state:
            tabs[curr_tab] = st.session_state[curr_key]
    del tabs[tab_name]
    closed_key = get_tab_widget_key(tab_name)
    if closed_key != "code_area" and closed_key in st.session_state:
        del st.session_state[closed_key]
    if curr_tab == tab_name:
        new_active = next(iter(tabs.keys()))
        st.session_state.active_tab = new_active
        new_key = get_tab_widget_key(new_active)
        st.session_state[new_key] = tabs[new_active]
        st.session_state.editor_version = st.session_state.get("editor_version", 0) + 1
        st.session_state.last_result = None
        st.session_state.last_execution = None

def on_theme_toggle():
    """Toggles Dark / Light mode."""
    st.session_state.dark_mode = not st.session_state.dark_mode
    st.rerun()

def on_font_change():
    """Updates editor font size."""
    st.session_state.editor_font_size = st.session_state.get("font_size_selector", 14)

def on_mode_change():
    """Switches tutor pedagogical mode."""
    st.session_state.tutor_mode = st.session_state.get("tutor_mode_radio", "Direct Solution")
    st.session_state.hint_level = 1

def on_need_hint():
    """Increments progressive hint level in Socratic mode."""
    st.session_state.hint_level = st.session_state.get("hint_level", 1) + 1
    st.rerun()

def on_highlight_line(line_num: int):
    """Highlights a clicked issue's line number in the code editor."""
    st.session_state.highlighted_line = line_num

def on_apply_single_fix(issue: dict):
    """Applies a single issue's {old, new} patch to the active editor tab."""
    patch = issue.get("patch") or {}
    old_s = patch.get("old", "")
    new_s = patch.get("new", "")
    if not new_s:
        return
    active_tab = st.session_state.get("active_tab", "main.py")
    active_key = get_tab_widget_key(active_tab)
    current = get_active_code()
    lines = current.split("\n")
    ln = int(issue.get("line") or 1)
    idx = max(0, min(ln - 1, len(lines) - 1))

    updated = None
    if old_s and old_s in lines[idx]:
        lines[idx] = lines[idx].replace(old_s, new_s, 1)
        updated = "\n".join(lines)
    elif old_s and old_s in current:
        updated = current.replace(old_s, new_s, 1)
    elif 0 <= idx < len(lines):
        lines[idx] = new_s
        updated = "\n".join(lines)

    if updated is not None:
        st.session_state[active_key] = updated
        if "editor_tabs" in st.session_state:
            st.session_state.editor_tabs[active_tab] = updated
        st.session_state.editor_version = st.session_state.get("editor_version", 0) + 1
        st.session_state.highlighted_line = ln

def on_socratic_next_hint(issue_id: int):
    """Unlocks the next hint level (1 -> 2 -> 3) for a specific Socratic issue."""
    hints_map = dict(st.session_state.get("socratic_issue_hints", {}))
    hints_map[issue_id] = min(3, hints_map.get(issue_id, 1) + 1)
    st.session_state.socratic_issue_hints = hints_map

def on_socratic_reveal_answer(issue_id: int):
    """Explicitly unlocks the fix/explanation for a single issue in Socratic mode."""
    rev = set(st.session_state.get("socratic_revealed_answers", set()))
    rev.add(issue_id)
    st.session_state.socratic_revealed_answers = rev

def on_socratic_select_issue(idx: int):
    """Selects which single issue is currently revealed in Socratic Hint mode."""
    st.session_state.socratic_active_idx = max(0, idx)

def on_provider_mode_change():
    """Sync Cloud AI (Gemini) and Offline mode toggles into ProviderRouter."""
    get_router().set_mode(
        cloud_enabled=bool(st.session_state.get("cloud_ai_enabled", True)),
        offline_mode=bool(st.session_state.get("offline_mode", False)),
    )

# ─────────────────────────────────────────────
# Pipeline Execution Handler
# ─────────────────────────────────────────────
def run_pipeline(fix_warnings: bool = False):
    """Runs the Security Gate, Sandbox, and 4-pass Multi-Error Repair Loop for the active tab."""
    raw_code = get_active_code()
    active_tab = st.session_state.get("active_tab", "main.py")
    if "editor_tabs" in st.session_state:
        st.session_state.editor_tabs[active_tab] = raw_code
    code = raw_code.strip()
    stdin_data = st.session_state.get("stdin_input", "")

    if not code:
        st.warning("Please enter Python code before running.")
        return

    # Sync provider mode before execution
    router = get_router()
    router.set_mode(
        cloud_enabled=bool(st.session_state.get("cloud_ai_enabled", True)),
        offline_mode=bool(st.session_state.get("offline_mode", False)),
    )

    # Check Sliding Window Rate Limit (15 req/min, counting Gemini calls)
    rpm_limit = int(getattr(config, "RATE_LIMIT_RPM", 15))
    rate_left, countdown, is_blocked = get_rate_limit_state()
    if is_blocked:
        st.error(f"⚠️ Rate limit reached (max {rpm_limit} requests/min). Please wait {countdown} seconds.")
        return

    record_request_timestamp()
    gemini_calls_before = router.gemini_calls

    # Determine tutor mode
    pipeline_mode = "socratic" if st.session_state.tutor_mode == "Socratic Hint Mode" else "direct"

    t_start = time.perf_counter()
    progress_slot = st.empty()

    def _on_repair_progress(curr_i: int, total_i: int, round_n: int, msg: str):
        pct = min(99, int((curr_i / max(total_i, 1)) * 100))
        progress_slot.progress(pct, text=msg)

    with st.spinner("Compiling, sandboxing, and running Multi-Pass Repair Loop..."):
        # Track carbon emissions
        try:
            tracker = EmissionsTracker(project_name="AI_Error_Tutor_Analysis", log_level="error", save_to_file=False)
            tracker.start()
        except Exception:
            tracker = None

        # 1. Execute via SafeExecutionEngine with stdin (includes Ingress Security Gate)
        exec_res = exec_engine.run_code(code, stdin_data)
        st.session_state.last_execution = exec_res

        # 2. If blocked by Security Gate -> STOP immediately, run NO repair loop
        if exec_res.is_blocked:
            analysis_res = tutor.analyze_code(code, mode=pipeline_mode, stdin_data=stdin_data)
            repair_report = {
                "blocked": True,
                "block_reason": exec_res.block_reason,
                "issues": [],
                "fixed_code": raw_code,
                "diff": "",
                "rounds_used": 0,
                "final_run": {"status": "Blocked", "output": exec_res.block_reason},
                "error_count": 0,
                "warning_count": 0,
                "cascade_count": 0,
                "verified": False,
            }
        else:
            # 3. Run 4-pass Multi-Error Repair Loop (finds & fixes ALL errors)
            repair_report = tutor.analyze_all_errors(
                code=raw_code,
                mode=pipeline_mode,
                stdin_data=stdin_data,
                fix_warnings=fix_warnings,
                progress_callback=_on_repair_progress,
            )
            # Also produce ExplanationResult (for Code Health, AST context, and existing tabs)
            analysis_res = tutor.analyze_code(code, mode=pipeline_mode, stdin_data=stdin_data)

            if not repair_report.get("blocked"):
                analysis_res.repair_report = repair_report
                if repair_report.get("error_count", 0) > 0 or (fix_warnings and repair_report.get("warning_count", 0) > 0):
                    rep_verified = bool(repair_report.get("verified", False))
                    if rep_verified or not getattr(analysis_res, "fix_verified", False):
                        analysis_res.corrected_code = repair_report.get("fixed_code", analysis_res.corrected_code)
                        analysis_res.fix_verified = rep_verified
                        analysis_res.fix_verification_attempts = repair_report.get("rounds_used", 0)
                    elif getattr(analysis_res, "fix_verified", False) and getattr(analysis_res, "corrected_code", None):
                        # Analysis pipeline verified a clean fix while repair_report did not -> keep verified fix!
                        repair_report["fixed_code"] = analysis_res.corrected_code
                        repair_report["verified"] = True
                        repair_report["final_run"] = {"status": "Success", "output": ""}
                        for iss in repair_report.get("issues", []):
                            if iss.get("severity") == "error":
                                iss["status"] = "verified"
                    # If single-error analyze_code said success (e.g. static error inside uncalled func), keep success accurate
                    if repair_report.get("error_count", 0) > 0:
                        first_err = next(
                            (i for i in repair_report.get("issues", []) if i["severity"] == "error" and i["cascade_of"] is None),
                            None,
                        )
                        if first_err and analysis_res.success:
                            analysis_res.success = False
                            analysis_res.error_type = first_err["type"]
                            analysis_res.line_number = first_err["line"]
                            analysis_res.friendly_explanation = first_err["explanation"]

        progress_slot.empty()

        # Track solved issues since previous run (for Socratic mode progress feedback)
        prev_sigs = st.session_state.get("previous_issue_sigs", [])
        curr_open_sigs = [
            (i["type"], i["line"], i["vague_description"])
            for i in repair_report.get("issues", [])
            if i["severity"] == "error" and i["cascade_of"] is None
        ]
        curr_types_lines = {(t, l) for (t, l, _) in curr_open_sigs}
        if prev_sigs:
            solved = [p for p in prev_sigs if (p[0], p[1]) not in curr_types_lines]
            st.session_state.solved_since_last_run = solved
        else:
            st.session_state.solved_since_last_run = []
        st.session_state.previous_issue_sigs = curr_open_sigs
        st.session_state.socratic_active_idx = 0
        st.session_state.socratic_issue_hints = {}
        st.session_state.socratic_revealed_answers = set()
        st.session_state.highlighted_line = None

        # Track Cloud (Gemini) CO2 separately from Local (Ollama / CPU) CO2
        new_gemini_calls = max(0, router.gemini_calls - gemini_calls_before)
        # Estimated ~0.20 mg CO2 (2e-7 kg) per lightweight cloud flash inference call
        cloud_delta_kg = new_gemini_calls * 2.0e-7

        local_emissions_kg = None
        if tracker:
            try:
                local_emissions_kg = tracker.stop()
            except Exception:
                local_emissions_kg = None

        # Scientific Hardware Energy/Carbon Fallback Model (local CPU/GPU):
        # Power = 55W (0.055 kW) average active TDP; Carbon Intensity = 0.475 kg CO2/kWh
        t_elapsed = max(0.08, time.perf_counter() - t_start)
        if not local_emissions_kg:
            local_emissions_kg = (0.055 * (t_elapsed / 3600.0)) * 0.475

        st.session_state.cloud_emissions_kg += float(cloud_delta_kg)
        st.session_state.local_emissions_kg += float(local_emissions_kg)
        st.session_state.session_emissions_kg = (
            st.session_state.cloud_emissions_kg + st.session_state.local_emissions_kg
        )

        st.session_state.repair_report = repair_report
        st.session_state.last_result = analysis_res

        # Update Session Analytics
        st.session_state.total_runs += 1
        if analysis_res.success and repair_report.get("error_count", 0) == 0:
            st.session_state.successful_runs += 1
        else:
            counted = False
            for iss in repair_report.get("issues", []):
                if iss.get("severity") == "error" and iss.get("cascade_of") is None:
                    et = iss.get("type", "Error")
                    st.session_state.error_stats[et] = st.session_state.error_stats.get(et, 0) + 1
                    counted = True
            if not counted and analysis_res.error_type:
                st.session_state.error_stats[analysis_res.error_type] = (
                    st.session_state.error_stats.get(analysis_res.error_type, 0) + 1
                )

        if getattr(analysis_res, "corrected_code", None) and getattr(analysis_res, "fix_verified", False):
            st.session_state.last_verified_fix = analysis_res.corrected_code

    st.rerun()

def on_fix_warnings():
    """Re-runs the repair loop with fix_warnings=True when the user clicks 'Fix warnings'."""
    run_pipeline(fix_warnings=True)

# ─────────────────────────────────────────────
# Layout: Top Bar (CodeChef Slim Header + Provider Chain Controls)
# ─────────────────────────────────────────────
rate_left, rate_countdown, rate_blocked = get_rate_limit_state()
cloud_co2_mg = st.session_state.cloud_emissions_kg * 1_000_000.0
local_co2_mg = st.session_state.local_emissions_kg * 1_000_000.0
co2_mg = cloud_co2_mg + local_co2_mg
provider_status = get_router().get_status()

render_topbar(
    co2_val_mg=co2_mg,
    rate_left=rate_left,
    rate_countdown=rate_countdown,
    rate_blocked=rate_blocked,
    on_run_click=run_pipeline,
    on_analyze_click=run_pipeline,
    on_demo_select=on_demo_select,
    on_theme_toggle=on_theme_toggle,
    on_font_change=on_font_change,
    provider_status=provider_status,
    cloud_co2_mg=cloud_co2_mg,
    local_co2_mg=local_co2_mg,
    on_provider_mode_change=on_provider_mode_change,
)

# ─────────────────────────────────────────────
# Ollama Backup Health Check Banner
# ─────────────────────────────────────────────
try:
    gemini_ready = (
        provider_status.get("cloud_enabled")
        and not provider_status.get("offline_mode")
        and provider_status.get("gemini_key_present")
        and not provider_status.get("circuit_open")
    )
    if not gemini_ready:
        ollama_health = check_ollama_health(timeout=1.0)
        if not ollama_health.get("running", False):
            st.warning("Local fallback Ollama is not running (using Tier 3 Rule-based AST). Start Ollama with: ollama serve")
        elif ollama_health.get("missing_models"):
            missing_mod = ollama_health["missing_models"][0]
            st.warning(f"Local backup model missing. Run: ollama pull {missing_mod}")
except Exception:
    pass

# ─────────────────────────────────────────────
# Layout: Two-Pane CodeChef IDE (60% Left, 40% Right)
# ─────────────────────────────────────────────
col_left, col_right = st.columns([6, 4], gap="medium")

# Determine error line(s) for highlighting (clicked issue card takes priority)
error_line_to_highlight = st.session_state.get("highlighted_line")
if not error_line_to_highlight and st.session_state.last_result and not st.session_state.last_result.success:
    error_line_to_highlight = getattr(st.session_state.last_result, "line_number", None)

all_error_lines = []
rep_rep = st.session_state.get("repair_report")
if rep_rep and not rep_rep.get("blocked"):
    all_error_lines = sorted({
        int(iss["line"])
        for iss in rep_rep.get("issues", [])
        if iss.get("severity") == "error" and iss.get("line")
    })
if error_line_to_highlight and int(error_line_to_highlight) not in all_error_lines:
    all_error_lines.append(int(error_line_to_highlight))

with col_left:
    active_tab = st.session_state.get("active_tab", "main.py")
    updated_code = render_editor_pane(
        code_content=get_active_code(),
        font_size=st.session_state.get("editor_font_size", 14),
        is_dark=st.session_state.dark_mode,
        error_line=error_line_to_highlight,
        error_lines=all_error_lines,
        on_switch_tab=on_switch_tab,
        on_add_tab=on_add_tab,
        on_close_tab=on_close_tab
    )
    if updated_code is not None and "editor_tabs" in st.session_state:
        st.session_state.editor_tabs[active_tab] = updated_code

    active_code = updated_code if updated_code is not None else get_active_code()

    # Quick editor action row (Clear Editor + Download Code)
    ed_cols = st.columns([1.2, 1.4, 2.0])
    with ed_cols[0]:
        st.button("🗑 Clear Editor", on_click=on_clear_editor, use_container_width=True)
    with ed_cols[1]:
        st.download_button(
            label="⬇ Download Code",
            data=active_code,
            file_name=active_tab,
            mime="text/x-python",
            use_container_width=True,
            key="download_code_btn"
        )

with col_right:
    render_terminal_pane(
        exec_result=st.session_state.last_execution,
        current_code=active_code,
        is_dark=st.session_state.dark_mode,
        repair_report=st.session_state.get("repair_report")
    )

# ─────────────────────────────────────────────
# Layout: Collapsible Full-Width Bottom Panel
# ─────────────────────────────────────────────
render_bottom_panel(
    analysis_result=st.session_state.last_result,
    current_code=active_code,
    tutor_instance=tutor,
    on_apply_fix=on_apply_fix,
    on_need_hint=on_need_hint,
    on_mode_change=on_mode_change,
    repair_report=st.session_state.get("repair_report"),
    on_highlight_line=on_highlight_line,
    on_apply_single_fix=on_apply_single_fix,
    on_fix_warnings=on_fix_warnings,
    on_socratic_next_hint=on_socratic_next_hint,
    on_socratic_reveal_answer=on_socratic_reveal_answer,
    on_socratic_select_issue=on_socratic_select_issue,
)
