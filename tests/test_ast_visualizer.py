"""Pytest Suite for Adaptive AST Visualizer (Graph Mode vs. Text AST Mode).

Run with: python -m pytest tests/test_ast_visualizer.py -v
"""

import ast
import os
import re
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from src.ast_visualizer import (
    analyze_ast_view,
    build_ast_dot,
    build_ast_text_full,
    build_ast_text_sections,
    build_issue_line_map,
    decide_ast_mode,
    parse_ast_safe,
)


def _assert_valid_dot(dot: str) -> None:
    """Validate structural integrity of a generated Graphviz DOT string."""
    assert isinstance(dot, str) and dot.strip().startswith("digraph AST {")
    assert dot.strip().endswith("}")
    # Check balanced unquoted braces and balanced unescaped double-quotes per line
    for ln in dot.splitlines():
        # Strip escaped quotes before counting quotes on each attribute line
        no_esc = ln.replace("\\\\", "").replace('\\"', "")
        assert no_esc.count('"') % 2 == 0, f"Unbalanced quotes in DOT line: {ln}"
    assert re.search(r"\bn0\s*\[", dot), "Root node n0 missing from DOT"
    assert "->" in dot, "Expected edges in DOT output"


# ─────────────────────────────────────────────────────────────
# 1. A 10-line program: graph mode, valid DOT
# ─────────────────────────────────────────────────────────────
def test_1_ten_line_program_uses_graph_mode_and_valid_dot():
    code = "\n".join([
        "def average(scores):",
        "    total = 0",
        "    for s in scores:",
        "        total += s",
        "    if len(scores) == 0:",
        "        return 0",
        "    return total / len(scores)",
        "",
        "nums = [10, 20, 30]",
        "print(average(nums))",
    ])
    issues = [
        {"line": 7, "severity": "error", "type": "ZeroDivisionError", "message": "division by zero"},
        {"line": 9, "severity": "warning", "type": "UnusedVariable", "message": "unused warning"},
    ]

    res = analyze_ast_view(code, issues=issues, simplified=True, rankdir="TB")

    assert res["mode"] == "graph"
    assert res["node_count"] <= config.AST_GRAPH_MAX_NODES
    assert res["line_count"] == 10
    assert res["text_view"] is None
    assert "Graph mode (small code," in res["badge_text"]

    dot = res["dot_source"]
    _assert_valid_dot(dot)
    assert "FunctionDef: average(scores)" in dot
    assert "Assign: total = 0" in dot
    assert 'fillcolor="#fee2e2"' in dot  # red error highlight
    assert 'fillcolor="#fef9c3"' in dot  # yellow warning highlight
    assert "division by zero" in dot     # tooltip message
    assert 'rankdir="TB"' in dot

    # Verify Full tree mode includes Load/Store context nodes and LR layout works
    res_full = analyze_ast_view(code, issues=issues, simplified=False, rankdir="LR")
    _assert_valid_dot(res_full["dot_source"])
    assert 'rankdir="LR"' in res_full["dot_source"]
    assert "Load" in res_full["dot_source"]
    assert "Load" not in dot


# ─────────────────────────────────────────────────────────────
# 2. The 50-line buggy program: matches configured limits & works cleanly
# ─────────────────────────────────────────────────────────────
def test_2_fifty_line_buggy_program_uses_expected_mode():
    # Same 50-line benchmark structure from tests/test_repair_loop.py
    code = """import math

tax_rate = 0.08
counter = 0

def format_price(amount):
    return "Total: $" + amount

def lookup_discount(code_name):
    discounts = {"SAVE10": 0.10, "SAVE20": 0.20}
    return discounts[code_name]

def sum_items(items):
    total = 0
    for i in range(len(items) + 1):
        total += items[i]
    return total

def increment_counter():
    counter += 1
    return counter

def format_title(text):
    return text.titel()

def safe_average(values):
    return sum(values) / len(values)

def classify_score(score):
    if score >= 50:
        return "pass"

def run_report():
    price_text = format_price(19.99)
    disc = lookup_discount("VIP50")
    subtotal = sum_items([5, 10, 15])
    hits = increment_counter()
    heading = format_title("weekly summary")
    avg = safe_average([])
    grade = classify_score(80)
    total = subtotal - disc
    print(price_text, heading, hits, avg, grade, totl)

run_report()
"""
    decision = decide_ast_mode(code)
    expected_mode = (
        "graph"
        if (decision["node_count"] <= config.AST_GRAPH_MAX_NODES and decision["line_count"] <= config.AST_GRAPH_MAX_LINES)
        else "text"
    )
    res = analyze_ast_view(code)

    assert res["mode"] == expected_mode
    if expected_mode == "graph":
        _assert_valid_dot(res["dot_source"])
        assert res["text_view"] is None
    else:
        assert res["dot_source"] is None
        assert res["text_view"] is not None
        assert len(res["text_view"]["sections"]) >= 5
        assert "Graphs are disabled for big programs" in res["badge_text"]


# ─────────────────────────────────────────────────────────────
# 3. A 5000-line file: text mode, NO graph built, finishes < 3s
# ─────────────────────────────────────────────────────────────
def test_3_five_thousand_line_file_text_mode_fast_and_no_graph():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    stress_path = os.path.join(repo_root, "test_5000_lines_buggy.py")
    if os.path.exists(stress_path):
        with open(stress_path, "r", encoding="utf-8") as f:
            big_code = f.read()
    else:
        big_code = "\n".join(f"var_{i} = {i} + 1" for i in range(5000))

    t0 = time.perf_counter()
    res = analyze_ast_view(big_code, max_depth=config.AST_DEFAULT_MAX_DEPTH)
    elapsed = time.perf_counter() - t0

    assert res["mode"] == "text"
    assert res["dot_source"] is None, "Graph MUST NOT be built for 5,000-line files"
    assert res["line_count"] >= 4900
    assert elapsed < 3.0, f"5000-line AST text view took too long: {elapsed:.2f}s"
    assert "Text mode (large code," in res["badge_text"]
    assert res["text_view"]["displayed_rows"] <= config.AST_TEXT_MAX_ROWS
    if res["text_view"]["total_rows"] > config.AST_TEXT_MAX_ROWS:
        assert res["text_view"]["truncated"] is True
        assert "download the full AST" in res["text_view"]["truncation_message"]


# ─────────────────────────────────────────────────────────────
# 4. Boundary test: just under and just over node & line limits
# ─────────────────────────────────────────────────────────────
def test_4_boundary_under_and_over_node_and_line_limits():
    # Build a small program and read its exact node count
    base_code = "\n".join(f"x_{i} = {i}" for i in range(10))
    parsed = parse_ast_safe(base_code)
    exact_nodes = parsed["node_count"]
    exact_lines = parsed["line_count"]

    # Just at / under node limit AND line limit -> graph mode
    res_at = analyze_ast_view(base_code, max_nodes=exact_nodes, max_lines=exact_lines)
    assert res_at["mode"] == "graph"
    assert res_at["dot_source"] is not None

    # 1 node over limit -> text mode (no graph built)
    res_over_nodes = analyze_ast_view(base_code, max_nodes=exact_nodes - 1, max_lines=exact_lines + 10)
    assert res_over_nodes["mode"] == "text"
    assert res_over_nodes["dot_source"] is None

    # Within node limit, 1 line over line limit -> text mode (BOTH limits must hold!)
    res_over_lines = analyze_ast_view(base_code, max_nodes=exact_nodes + 100, max_lines=exact_lines - 1)
    assert res_over_lines["mode"] == "text"
    assert res_over_lines["dot_source"] is None


# ─────────────────────────────────────────────────────────────
# 5. Syntax error: friendly message, no crash
# ─────────────────────────────────────────────────────────────
def test_5_syntax_error_returns_friendly_message_no_crash():
    broken = "def greet(name)\n    print('hi')\n"
    res = analyze_ast_view(broken)

    assert res["mode"] == "error"
    assert res["error_type"] == "SyntaxError"
    assert res["error_line"] == 1
    assert res["dot_source"] is None
    assert res["text_view"] is None
    assert "line 1" in res["friendly_message"].lower()


# ─────────────────────────────────────────────────────────────
# 6. Special characters and unicode never break DOT or text tree
# ─────────────────────────────────────────────────────────────
def test_6_special_characters_and_unicode_safe_in_dot_and_text():
    tricky_code = (
        'msg = "He said \\"hello\\" \\\\ path\\\\to\\\\file\\nnext line"\n'
        'unicode_var = "Café naïve — 日本語 — 🚀 {braces} <tags> | pipes"\n'
        "def café_func(α, β):\n"
        '    return f"{α} -> {β}: {msg}"\n'
    )
    issues = [{"line": 2, "severity": "warning", "type": "UnusedVariable", "message": 'Weird "quote" & \\slash\\ 🚀'}]

    # Graph mode with special chars + unicode
    res_graph = analyze_ast_view(tricky_code, issues=issues, max_nodes=500, max_lines=100)
    assert res_graph["mode"] == "graph"
    _assert_valid_dot(res_graph["dot_source"])
    assert "café_func" in res_graph["dot_source"]

    # Text mode with special chars + unicode
    res_text = analyze_ast_view(tricky_code, issues=issues, max_nodes=5, max_lines=1)
    assert res_text["mode"] == "text"
    assert res_text["dot_source"] is None
    combined = "\n".join(s["text"] for s in res_text["text_view"]["sections"])
    assert "café_func" in combined
    assert "[WARNING 🟡]" in combined


# ─────────────────────────────────────────────────────────────
# 7. Code is NEVER executed (file-creation sentinel test)
# ─────────────────────────────────────────────────────────────
def test_7_code_is_never_executed(tmp_path):
    sentinel = tmp_path / "must_not_be_created.txt"
    payload = (
        f'with open(r"{sentinel}", "w") as f:\n'
        '    f.write("EXECUTED")\n'
        'raise SystemExit("should never run")\n'
    )

    res_graph = analyze_ast_view(payload)
    res_text = analyze_ast_view(payload, max_nodes=1, max_lines=1)
    full_txt = build_ast_text_full(payload)

    assert res_graph["mode"] == "graph"
    assert res_text["mode"] == "text"
    assert "With" in full_txt
    assert not sentinel.exists(), "AST visualizer MUST NEVER execute user code!"


# ─────────────────────────────────────────────────────────────
# 8. Search and depth filtering in text mode return expected rows
# ─────────────────────────────────────────────────────────────
def test_8_text_mode_search_and_depth_filtering():
    code = """def average(scores):
    total = 0
    for s in scores:
        if s > 0:
            total += s
    return total

class Tracker:
    def record(self, val):
        self.last = val

top_x = average([1, 2, 3])
"""
    parsed = parse_ast_safe(code)
    assert parsed["ok"] is True
    tree = parsed["tree"]

    # Shallow depth (max_depth=1) hides deeply nested If/AugAssign inside For
    shallow = build_ast_text_sections(tree, max_depth=1)
    shallow_all = "\n".join(s["text"] for s in shallow["sections"])
    assert "FunctionDef: average(scores)" in shallow_all
    assert "Assign: total = 0" in shallow_all
    assert "AugAssign:" not in shallow_all

    # Deeper depth (max_depth=6) reveals nested AugAssign
    deep = build_ast_text_sections(tree, max_depth=6)
    deep_all = "\n".join(s["text"] for s in deep["sections"])
    assert "AugAssign:" in deep_all
    # Check grouping: Top-level Statements + Function: average + Class: Tracker
    titles = [s["title"] for s in deep["sections"]]
    assert any("Top-level Statements" in t for t in titles)
    assert any("Function: average" in t for t in titles)
    assert any("Class: Tracker" in t for t in titles)

    # Search by node type
    by_type = build_ast_text_sections(tree, max_depth=6, search_query="Return")
    by_type_rows = [r for s in by_type["sections"] for r in s["text"].splitlines()]
    assert len(by_type_rows) == 1
    assert "Return: total" in by_type_rows[0]

    # Search by name
    by_name = build_ast_text_sections(tree, max_depth=6, search_query="Tracker")
    by_name_rows = [r for s in by_name["sections"] for r in s["text"].splitlines()]
    assert any("ClassDef: Tracker" in r for r in by_name_rows)
    assert all("average" not in r for r in by_name_rows)

    # Search by line number
    by_line = build_ast_text_sections(tree, max_depth=6, search_query="line 5")
    by_line_rows = [r for s in by_line["sections"] for r in s["text"].splitlines()]
    assert any("[line 5]" in r for r in by_line_rows)
    assert all("[line 5]" in r for r in by_line_rows)
