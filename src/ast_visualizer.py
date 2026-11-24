"""Adaptive AST Visualizer (Graph Mode for small code, Text Tree Mode for large code).

Safety invariant:
- User code is NEVER executed. Only ast.parse() is invoked inside try/except for
  (SyntaxError, RecursionError, MemoryError, ValueError).
- Thresholds (AST_GRAPH_MAX_NODES, AST_GRAPH_MAX_LINES, AST_TEXT_MAX_ROWS,
  AST_DEFAULT_MAX_DEPTH) are read from config.py with no hard-coded overrides.
"""

from __future__ import annotations

import ast
import hashlib
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

import config


# ─────────────────────────────────────────────────────────────
# Node Category Color Palette (Graph Mode + Legend)
# ─────────────────────────────────────────────────────────────
CONTEXT_NODES = (ast.Load, ast.Store, ast.Del)

FUNC_CLASS_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
    ast.Return,
    ast.Yield,
    ast.YieldFrom,
)
CONTROL_FLOW_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.Break,
    ast.Continue,
    ast.Raise,
)
# Python 3.10+ Match/match_case support
if hasattr(ast, "Match"):
    CONTROL_FLOW_NODES = CONTROL_FLOW_NODES + (ast.Match,)
if hasattr(ast, "TryStar"):
    CONTROL_FLOW_NODES = CONTROL_FLOW_NODES + (ast.TryStar,)

ASSIGN_NODES = (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.NamedExpr)
CALL_NODES = (ast.Call,)
NAME_CONST_NODES = (ast.Name, ast.Constant, ast.arg, ast.Attribute, ast.Load, ast.Store, ast.Del)

COLOR_STYLES: Dict[str, Dict[str, str]] = {
    "func_class": {"fillcolor": "#dbeafe", "color": "#2563eb", "fontcolor": "#1e3a8a", "label": "Functions & Classes"},
    "control":    {"fillcolor": "#ede9fe", "color": "#7c3aed", "fontcolor": "#4c1d95", "label": "Control Flow"},
    "assign":     {"fillcolor": "#dcfce7", "color": "#16a34a", "fontcolor": "#14532d", "label": "Assignments"},
    "call":       {"fillcolor": "#ffedd5", "color": "#ea580c", "fontcolor": "#7c2d12", "label": "Calls"},
    "name_const": {"fillcolor": "#f1f5f9", "color": "#94a3b8", "fontcolor": "#334155", "label": "Names & Constants"},
    "other":      {"fillcolor": "#f8fafc", "color": "#64748b", "fontcolor": "#1e293b", "label": "Module / Expressions"},
    "error":      {"fillcolor": "#fee2e2", "color": "#dc2626", "fontcolor": "#991b1b", "label": "Error Line"},
    "warning":    {"fillcolor": "#fef9c3", "color": "#ca8a04", "fontcolor": "#854d0e", "label": "Warning Line"},
}

OP_SYMBOLS: Dict[type, str] = {
    ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/", ast.FloorDiv: "//",
    ast.Mod: "%", ast.Pow: "**", ast.BitAnd: "&", ast.BitOr: "|", ast.BitXor: "^",
    ast.LShift: "<<", ast.RShift: ">>", ast.MatMult: "@",
    ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
    ast.Is: "is", ast.IsNot: "is not", ast.In: "in", ast.NotIn: "not in",
    ast.And: "and", ast.Or: "or", ast.Not: "not", ast.UAdd: "+", ast.USub: "-", ast.Invert: "~",
}


def compute_ast_cache_key(
    code: str,
    issues: Optional[Sequence[Dict[str, Any]]] = None,
    **options: Any,
) -> str:
    """Deterministic SHA-256 hash of code, relevant issues, and rendering options."""
    h = hashlib.sha256()
    h.update((code or "").encode("utf-8", errors="replace"))
    h.update(b"\x00")
    if issues:
        compact = [
            (i.get("line"), i.get("severity"), i.get("type"), i.get("message"))
            for i in issues
        ]
        h.update(json.dumps(compact, sort_keys=True, ensure_ascii=False).encode("utf-8", errors="replace"))
    h.update(b"\x00")
    h.update(json.dumps(options, sort_keys=True, ensure_ascii=False).encode("utf-8", errors="replace"))
    return h.hexdigest()


def build_issue_line_map(issues: Optional[Sequence[Dict[str, Any]]]) -> Dict[int, Dict[str, str]]:
    """
    Map 1-based line numbers -> {'severity': 'error'|'warning', 'message': '...'}.
    Errors take precedence over warnings on the same line.
    """
    by_line: Dict[int, Dict[str, str]] = {}
    if not issues:
        return by_line
    for iss in issues:
        ln = iss.get("line")
        if not ln:
            continue
        try:
            ln_int = int(ln)
        except (TypeError, ValueError):
            continue
        sev = "warning" if str(iss.get("severity", "error")).lower() == "warning" else "error"
        etype = str(iss.get("type") or ("Warning" if sev == "warning" else "Error"))
        msg = str(iss.get("message") or iss.get("explanation") or etype)
        summary = f"{etype}: {msg}" if etype not in msg else msg
        existing = by_line.get(ln_int)
        if existing is None:
            by_line[ln_int] = {"severity": sev, "message": summary}
        else:
            if existing["severity"] != "error" and sev == "error":
                existing["severity"] = "error"
            if summary not in existing["message"]:
                existing["message"] = f"{existing['message']} | {summary}"
    return by_line


def parse_ast_safe(code: str) -> Dict[str, Any]:
    """
    Safely parse Python source code with ast.parse ONLY (never executes code).
    Catches SyntaxError, RecursionError, MemoryError, and ValueError.
    """
    src = code if isinstance(code, str) else ""
    line_count = len(src.splitlines()) if src else 0
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        ln = e.lineno or 1
        msg = e.msg or str(e)
        return {
            "ok": False,
            "tree": None,
            "node_count": 0,
            "line_count": line_count,
            "error_type": "SyntaxError",
            "error_line": ln,
            "error_offset": e.offset,
            "error_message": msg,
            "friendly_message": (
                f"Cannot build an AST because there is a SyntaxError on line {ln}: {msg}. "
                "Fix the syntax error (or switch to the 'After fixes' tab once the repair loop finishes) to inspect the tree."
            ),
        }
    except (RecursionError, MemoryError, ValueError) as e:
        etype = type(e).__name__
        return {
            "ok": False,
            "tree": None,
            "node_count": 0,
            "line_count": line_count,
            "error_type": etype,
            "error_line": None,
            "error_offset": None,
            "error_message": str(e),
            "friendly_message": f"Unable to parse AST safely ({etype}: {e}).",
        }

    node_count = sum(1 for _ in ast.walk(tree))
    return {
        "ok": True,
        "tree": tree,
        "node_count": node_count,
        "line_count": line_count,
        "error_type": None,
        "error_line": None,
        "error_offset": None,
        "error_message": None,
        "friendly_message": None,
    }


def decide_ast_mode(
    code: str,
    max_nodes: Optional[int] = None,
    max_lines: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Decide between 'graph' (small code) and 'text' (big code) using config limits.
    Graph mode is selected ONLY if BOTH node_count <= max_nodes AND line_count <= max_lines.
    """
    lim_nodes = int(max_nodes if max_nodes is not None else getattr(config, "AST_GRAPH_MAX_NODES", 150))
    lim_lines = int(max_lines if max_lines is not None else getattr(config, "AST_GRAPH_MAX_LINES", 60))

    parsed = parse_ast_safe(code)
    if not parsed["ok"]:
        parsed["mode"] = "error"
        parsed["badge_text"] = f"AST unavailable ({parsed['error_type']})"
        parsed["max_nodes"] = lim_nodes
        parsed["max_lines"] = lim_lines
        return parsed

    nc = parsed["node_count"]
    lc = parsed["line_count"]
    if nc <= lim_nodes and lc <= lim_lines:
        mode = "graph"
        badge = f"Graph mode (small code, {nc} nodes)"
    else:
        mode = "text"
        badge = (
            f"Text mode (large code, {nc} nodes). "
            "Graphs are disabled for big programs to keep them readable."
        )

    parsed["mode"] = mode
    parsed["badge_text"] = badge
    parsed["max_nodes"] = lim_nodes
    parsed["max_lines"] = lim_lines
    return parsed


# ─────────────────────────────────────────────────────────────
# Lightweight Readable Labels & Safe Escaping
# ─────────────────────────────────────────────────────────────
def _truncate(text: str, max_len: int = 36) -> str:
    clean = str(text).replace("\r", " ").replace("\n", "\\n").strip()
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 3] + "..."


def _short_expr(node: Optional[ast.AST], depth: int = 0) -> str:
    """Fast O(1) bounded expression summarizer (safe on huge/deep ASTs)."""
    if node is None:
        return ""
    if depth > 2:
        return "..."
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return _truncate(repr(node.value), 22)
    if isinstance(node, ast.Attribute):
        base = _short_expr(node.value, depth + 1)
        return f"{base}.{node.attr}" if base else f".{node.attr}"
    if isinstance(node, ast.Call):
        fn = _short_expr(node.func, depth + 1)
        args_preview = ", ".join(_short_expr(a, depth + 1) for a in node.args[:2])
        if len(node.args) > 2 or node.keywords:
            args_preview = (args_preview + ", ..." if args_preview else "...")
        return f"{fn}({args_preview})"
    if isinstance(node, ast.Subscript):
        return f"{_short_expr(node.value, depth + 1)}[{_short_expr(node.slice, depth + 1)}]"
    if isinstance(node, ast.BinOp):
        sym = OP_SYMBOLS.get(type(node.op), type(node.op).__name__)
        return f"{_short_expr(node.left, depth + 1)} {sym} {_short_expr(node.right, depth + 1)}"
    if isinstance(node, ast.UnaryOp):
        sym = OP_SYMBOLS.get(type(node.op), type(node.op).__name__)
        return f"{sym}{_short_expr(node.operand, depth + 1)}"
    if isinstance(node, ast.Compare):
        left = _short_expr(node.left, depth + 1)
        if node.ops and node.comparators:
            sym = OP_SYMBOLS.get(type(node.ops[0]), type(node.ops[0]).__name__)
            right = _short_expr(node.comparators[0], depth + 1)
            return f"{left} {sym} {right}"
        return left
    if isinstance(node, ast.BoolOp):
        sym = OP_SYMBOLS.get(type(node.op), "op")
        return f" {sym} ".join(_short_expr(v, depth + 1) for v in node.values[:2])
    if isinstance(node, ast.List):
        elts = ", ".join(_short_expr(e, depth + 1) for e in node.elts[:3])
        return f"[{elts}{', ...' if len(node.elts) > 3 else ''}]"
    if isinstance(node, ast.Tuple):
        elts = ", ".join(_short_expr(e, depth + 1) for e in node.elts[:3])
        return f"({elts}{', ...' if len(node.elts) > 3 else ''})"
    if isinstance(node, ast.Dict):
        return "{...}" if node.keys else "{}"
    if isinstance(node, ast.JoinedStr):
        return "f'...'"
    return type(node).__name__


def format_node_label(node: ast.AST) -> str:
    """Return a concise, human-readable label for any AST node."""
    cls = type(node).__name__

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        params = [a.arg for a in (node.args.posonlyargs + node.args.args)]
        if node.args.vararg:
            params.append("*" + node.args.vararg.arg)
        params.extend(a.arg for a in node.args.kwonlyargs)
        if node.args.kwarg:
            params.append("**" + node.args.kwarg.arg)
        return _truncate(f"{cls}: {node.name}({', '.join(params)})", 48)

    if isinstance(node, ast.ClassDef):
        bases = ", ".join(_short_expr(b) for b in node.bases[:2])
        suffix = f"({bases})" if bases else ""
        return _truncate(f"ClassDef: {node.name}{suffix}", 48)

    if isinstance(node, ast.Assign):
        targets = ", ".join(_short_expr(t) for t in node.targets[:2])
        val = _short_expr(node.value)
        return _truncate(f"Assign: {targets} = {val}", 48)

    if isinstance(node, ast.AnnAssign):
        tgt = _short_expr(node.target)
        val = f" = {_short_expr(node.value)}" if node.value is not None else ""
        return _truncate(f"AnnAssign: {tgt}{val}", 48)

    if isinstance(node, ast.AugAssign):
        sym = OP_SYMBOLS.get(type(node.op), "")
        return _truncate(f"AugAssign: {_short_expr(node.target)} {sym}= {_short_expr(node.value)}", 48)

    if isinstance(node, (ast.For, ast.AsyncFor)):
        return _truncate(f"{cls}: {_short_expr(node.target)} in {_short_expr(node.iter)}", 48)

    if isinstance(node, ast.While):
        return _truncate(f"While: {_short_expr(node.test)}", 48)

    if isinstance(node, ast.If):
        return _truncate(f"If: {_short_expr(node.test)}", 48)

    if isinstance(node, ast.Return):
        return _truncate(f"Return: {_short_expr(node.value)}", 48) if node.value is not None else "Return"

    if isinstance(node, ast.Call):
        return _truncate(f"Call: {_short_expr(node)}", 48)

    if isinstance(node, ast.Name):
        return _truncate(f"Name: {node.id}", 40)

    if isinstance(node, ast.Constant):
        return _truncate(f"Constant: {repr(node.value)}", 40)

    if isinstance(node, ast.Attribute):
        return _truncate(f"Attribute: .{node.attr}", 40)

    if isinstance(node, ast.arg):
        return _truncate(f"arg: {node.arg}", 40)

    if isinstance(node, ast.Import):
        mods = ", ".join(f"{a.name} as {a.asname}" if a.asname else a.name for a in node.names[:3])
        return _truncate(f"Import: {mods}", 48)

    if isinstance(node, ast.ImportFrom):
        mods = ", ".join(a.name for a in node.names[:3])
        return _truncate(f"ImportFrom: {node.module or '.'} ({mods})", 48)

    if isinstance(node, ast.ExceptHandler):
        exc = _short_expr(node.type) if node.type else "bare"
        return _truncate(f"ExceptHandler: {exc}", 44)

    if isinstance(node, ast.BinOp):
        sym = OP_SYMBOLS.get(type(node.op), type(node.op).__name__)
        return f"BinOp ({sym})"

    if isinstance(node, ast.Compare):
        syms = ", ".join(OP_SYMBOLS.get(type(op), type(op).__name__) for op in node.ops[:2])
        return f"Compare ({syms})"

    if isinstance(node, ast.BoolOp):
        sym = OP_SYMBOLS.get(type(node.op), type(node.op).__name__)
        return f"BoolOp ({sym})"

    if isinstance(node, ast.UnaryOp):
        sym = OP_SYMBOLS.get(type(node.op), type(node.op).__name__)
        return f"UnaryOp ({sym})"

    if isinstance(node, ast.keyword):
        return _truncate(f"keyword: {node.arg or '**'}", 40)

    return cls


def escape_dot(text: str) -> str:
    """Safely escape strings for Graphviz DOT double-quoted attributes (handles quotes, slashes, newlines, unicode)."""
    s = str(text or "")
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")
    s = s.replace("\t", " ")
    # Remove any NUL or ASCII control chars that could break DOT parsers
    s = "".join(ch for ch in s if ord(ch) >= 32)
    return s


def _node_style(node: ast.AST, issue_map: Dict[int, Dict[str, str]]) -> Tuple[Dict[str, str], str]:
    """Return (style_dict, tooltip_text) for a DOT node, highlighting error/warning lines."""
    ln = getattr(node, "lineno", None)
    if ln is not None and ln in issue_map:
        iss = issue_map[ln]
        key = "error" if iss["severity"] == "error" else "warning"
        return COLOR_STYLES[key], f"Line {ln} — {iss['message']}"

    if isinstance(node, FUNC_CLASS_NODES):
        style = COLOR_STYLES["func_class"]
    elif isinstance(node, CONTROL_FLOW_NODES):
        style = COLOR_STYLES["control"]
    elif isinstance(node, ASSIGN_NODES):
        style = COLOR_STYLES["assign"]
    elif isinstance(node, CALL_NODES):
        style = COLOR_STYLES["call"]
    elif isinstance(node, NAME_CONST_NODES):
        style = COLOR_STYLES["name_const"]
    else:
        style = COLOR_STYLES["other"]

    tip = f"{type(node).__name__} (line {ln})" if ln is not None else type(node).__name__
    return style, tip


# ─────────────────────────────────────────────────────────────
# Small Code: Graph Mode (Graphviz DOT Builder)
# ─────────────────────────────────────────────────────────────
def build_ast_dot(
    tree: ast.AST,
    issues_by_line: Optional[Dict[int, Dict[str, str]]] = None,
    simplified: bool = True,
    rankdir: str = "TB",
) -> str:
    """
    Build a valid Graphviz DOT string for an AST.
    Does not invoke any external binary — rendered directly by st.graphviz_chart.
    """
    issue_map = issues_by_line or {}
    direction = "LR" if str(rankdir).upper() == "LR" else "TB"

    lines: List[str] = [
        "digraph AST {",
        f'  rankdir="{direction}";',
        '  graph [splines=true, nodesep=0.35, ranksep=0.45, bgcolor="transparent"];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, margin="0.12,0.06"];',
        '  edge [fontname="Helvetica", fontsize=8, color="#64748b", fontcolor="#64748b", arrowsize=0.65];',
    ]

    counter = [0]

    def _visit(node: ast.AST) -> str:
        nid = f"n{counter[0]}"
        counter[0] += 1

        label = format_node_label(node)
        ln = getattr(node, "lineno", None)
        if ln is not None and not isinstance(node, ast.Module):
            label_with_ln = f"{label}\\n[line {ln}]"
        else:
            label_with_ln = label

        style, tooltip = _node_style(node, issue_map)
        pen = "2.2" if style in (COLOR_STYLES["error"], COLOR_STYLES["warning"]) else "1.2"
        lines.append(
            f'  {nid} [label="{escape_dot(label_with_ln).replace("\\\\n", "\\n")}", '
            f'fillcolor="{style["fillcolor"]}", color="{style["color"]}", '
            f'fontcolor="{style["fontcolor"]}", penwidth={pen}, '
            f'tooltip="{escape_dot(tooltip)}"];'
        )

        for field_name, field_val in ast.iter_fields(node):
            if simplified and field_name == "ctx":
                continue
            if isinstance(field_val, ast.AST):
                if simplified and isinstance(field_val, CONTEXT_NODES):
                    continue
                child_id = _visit(field_val)
                lines.append(f'  {nid} -> {child_id} [label="{escape_dot(field_name)}"];')
            elif isinstance(field_val, list):
                for item in field_val:
                    if isinstance(item, ast.AST):
                        if simplified and isinstance(item, CONTEXT_NODES):
                            continue
                        child_id = _visit(item)
                        lines.append(f'  {nid} -> {child_id} [label="{escape_dot(field_name)}"];')

        return nid

    _visit(tree)
    lines.append("}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Big Code: Text AST Mode (Grouped Sections + Search + Max Depth)
# ─────────────────────────────────────────────────────────────
def _format_text_row(
    depth: int,
    node: ast.AST,
    issue_map: Dict[int, Dict[str, str]],
) -> Tuple[str, Optional[int], str]:
    """Return (formatted_row_line, lineno, node_type_name)."""
    indent = "  " * depth
    label = format_node_label(node)
    ln = getattr(node, "lineno", None)
    left = f"{indent}{label}"

    ln_part = f"[line {ln}]" if ln is not None else ""
    marker = ""
    if ln is not None and ln in issue_map:
        iss = issue_map[ln]
        if iss["severity"] == "error":
            marker = f"  [ERROR 🔴] {_truncate(iss['message'], 60)}"
        else:
            marker = f"  [WARNING 🟡] {_truncate(iss['message'], 60)}"

    if ln_part:
        pad = " " * max(2, 46 - len(left))
        row_text = f"{left}{pad}{ln_part}{marker}"
    else:
        row_text = f"{left}{marker}"

    return row_text, ln, type(node).__name__


def _walk_subtree_rows(
    root_node: ast.AST,
    start_depth: int,
    max_depth: Optional[int],
    search_lower: str,
    issue_map: Dict[int, Dict[str, str]],
    row_budget: Optional[int],
) -> Tuple[List[str], int, bool]:
    """
    Iteratively collect indented text rows for root_node (no recursion limit issues).
    Returns (rows, total_matching_count, was_truncated_in_this_call).
    """
    rows: List[str] = []
    total_matches = 0
    truncated = False

    # Explicit stack: (node, depth)
    stack: List[Tuple[ast.AST, int]] = [(root_node, start_depth)]
    while stack:
        node, depth = stack.pop()
        if max_depth is not None and depth > max_depth:
            continue

        row_text, ln, _ = _format_text_row(depth, node, issue_map)

        matched = True
        if search_lower:
            # Match by node type, label/name, or line number
            hay = row_text.lower()
            matched = (search_lower in hay) or (ln is not None and search_lower == str(ln))

        if matched:
            total_matches += 1
            if row_budget is None or len(rows) < row_budget:
                rows.append(row_text)
            else:
                truncated = True

        # Push children in reverse order so DFS preserves source order
        if max_depth is None or depth < max_depth:
            children: List[ast.AST] = []
            for field_name, field_val in ast.iter_fields(node):
                if field_name == "ctx":
                    continue
                if isinstance(field_val, ast.AST):
                    if not isinstance(field_val, CONTEXT_NODES):
                        children.append(field_val)
                elif isinstance(field_val, list):
                    for item in field_val:
                        if isinstance(item, ast.AST) and not isinstance(item, CONTEXT_NODES):
                            children.append(item)
            for child in reversed(children):
                stack.append((child, depth + 1))

    return rows, total_matches, truncated


def build_ast_text_sections(
    tree: ast.Module,
    issues_by_line: Optional[Dict[int, Dict[str, str]]] = None,
    max_depth: Optional[int] = None,
    search_query: str = "",
    max_rows: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Group a parsed Module AST into navigable collapsible sections:
      - One section per top-level FunctionDef / AsyncFunctionDef / ClassDef
      - One section for Top-level Statements
    Enforces max_depth, search filtering, and the 3,000-row display cap.
    """
    issue_map = issues_by_line or {}
    depth_lim = int(max_depth if max_depth is not None else getattr(config, "AST_DEFAULT_MAX_DEPTH", 6))
    display_cap = int(max_rows if max_rows is not None else getattr(config, "AST_TEXT_MAX_ROWS", 3000))
    search_l = (search_query or "").strip().lower()

    sections: List[Dict[str, Any]] = []
    top_level_stmts: List[ast.AST] = []
    def_nodes: List[ast.AST] = []

    for stmt in getattr(tree, "body", []):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            def_nodes.append(stmt)
        else:
            top_level_stmts.append(stmt)

    displayed_rows = 0
    total_rows = 0
    truncated = False

    def _has_issue_in_range(start_ln: Optional[int], end_ln: Optional[int]) -> Optional[str]:
        if start_ln is None:
            return None
        e_ln = end_ln or start_ln
        found_sev = None
        for ln, info in issue_map.items():
            if start_ln <= ln <= e_ln:
                if info["severity"] == "error":
                    return "error"
                found_sev = "warning"
        return found_sev

    # 1. Top-level statements section
    if top_level_stmts:
        sec_rows: List[str] = []
        sec_total = 0
        if not search_l or "module" in search_l:
            if displayed_rows < display_cap:
                sec_rows.append("Module")
                displayed_rows += 1
            else:
                truncated = True
            total_rows += 1
            sec_total += 1

        for stmt in top_level_stmts:
            remaining = max(0, display_cap - displayed_rows)
            s_rows, s_matches, s_trunc = _walk_subtree_rows(
                stmt,
                start_depth=1,
                max_depth=depth_lim,
                search_lower=search_l,
                issue_map=issue_map,
                row_budget=remaining,
            )
            sec_rows.extend(s_rows)
            displayed_rows += len(s_rows)
            total_rows += s_matches
            sec_total += s_matches
            if s_trunc or (s_matches > len(s_rows)):
                truncated = True

        if sec_rows:
            first_ln = getattr(top_level_stmts[0], "lineno", 1)
            last_ln = getattr(top_level_stmts[-1], "end_lineno", getattr(top_level_stmts[-1], "lineno", first_ln))
            sev_flag = None
            for stmt in top_level_stmts:
                s_sev = _has_issue_in_range(getattr(stmt, "lineno", None), getattr(stmt, "end_lineno", None))
                if s_sev == "error":
                    sev_flag = "error"
                    break
                elif s_sev == "warning":
                    sev_flag = "warning"
            badge = " 🔴" if sev_flag == "error" else (" 🟡" if sev_flag == "warning" else "")
            sections.append({
                "title": f"Top-level Statements ({len(top_level_stmts)} statements, lines {first_ln}–{last_ln}){badge}",
                "kind": "top_level",
                "line_start": first_ln,
                "line_end": last_ln,
                "row_count": len(sec_rows),
                "total_rows": sec_total,
                "text": "\n".join(sec_rows),
                "severity": sev_flag,
            })

    # 2. One section per top-level Function or Class
    for node in def_nodes:
        remaining = max(0, display_cap - displayed_rows)
        s_rows, s_matches, s_trunc = _walk_subtree_rows(
            node,
            start_depth=0,
            max_depth=depth_lim,
            search_lower=search_l,
            issue_map=issue_map,
            row_budget=remaining,
        )
        total_rows += s_matches
        if s_trunc or (s_matches > len(s_rows)):
            truncated = True
        if s_rows:
            displayed_rows += len(s_rows)
            s_ln = getattr(node, "lineno", 1)
            e_ln = getattr(node, "end_lineno", s_ln)
            kind = "Class" if isinstance(node, ast.ClassDef) else "Function"
            sev_flag = _has_issue_in_range(s_ln, e_ln)
            badge = " 🔴" if sev_flag == "error" else (" 🟡" if sev_flag == "warning" else "")
            sections.append({
                "title": f"{kind}: {node.name} (lines {s_ln}–{e_ln}, {len(s_rows)} rows){badge}",
                "kind": kind.lower(),
                "name": node.name,
                "line_start": s_ln,
                "line_end": e_ln,
                "row_count": len(s_rows),
                "total_rows": s_matches,
                "text": "\n".join(s_rows),
                "severity": sev_flag,
            })

    trunc_msg = (
        f"Tree truncated (showing {displayed_rows:,} of {total_rows:,} rows), download the full AST."
        if truncated
        else ""
    )

    return {
        "sections": sections,
        "displayed_rows": displayed_rows,
        "total_rows": total_rows,
        "truncated": truncated,
        "truncation_message": trunc_msg,
        "max_depth": depth_lim,
        "search_query": search_query,
    }


def build_ast_text_full(
    code: str,
    issues_by_line: Optional[Dict[int, Dict[str, str]]] = None,
) -> str:
    """Build the complete, un-truncated indented text AST for downloading as .txt."""
    parsed = parse_ast_safe(code)
    if not parsed["ok"] or parsed["tree"] is None:
        return parsed.get("friendly_message") or "AST unavailable."

    issue_map = issues_by_line or {}
    rows, _, _ = _walk_subtree_rows(
        parsed["tree"],
        start_depth=0,
        max_depth=None,
        search_lower="",
        issue_map=issue_map,
        row_budget=None,
    )
    return "\n".join(rows)


def analyze_ast_view(
    code: str,
    issues: Optional[Sequence[Dict[str, Any]]] = None,
    simplified: bool = True,
    rankdir: str = "TB",
    max_depth: Optional[int] = None,
    search_query: str = "",
    max_nodes: Optional[int] = None,
    max_lines: Optional[int] = None,
    max_rows: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Unified adaptive AST builder:
    - Small code (nodes <= AST_GRAPH_MAX_NODES AND lines <= AST_GRAPH_MAX_LINES): returns DOT graph only.
    - Big code: returns navigable text AST sections ONLY (dot_source is None — never builds a graph).
    - Syntax / parse error: returns friendly error message and line number.
    """
    decision = decide_ast_mode(code, max_nodes=max_nodes, max_lines=max_lines)
    issue_map = build_issue_line_map(issues)

    if decision["mode"] == "error":
        return {
            "mode": "error",
            "node_count": 0,
            "line_count": decision["line_count"],
            "badge_text": decision["badge_text"],
            "error_type": decision["error_type"],
            "error_line": decision["error_line"],
            "error_message": decision["error_message"],
            "friendly_message": decision["friendly_message"],
            "dot_source": None,
            "text_view": None,
        }

    tree = decision["tree"]
    if decision["mode"] == "graph":
        dot_str = build_ast_dot(
            tree,
            issues_by_line=issue_map,
            simplified=simplified,
            rankdir=rankdir,
        )
        return {
            "mode": "graph",
            "node_count": decision["node_count"],
            "line_count": decision["line_count"],
            "badge_text": decision["badge_text"],
            "dot_source": dot_str,
            "text_view": None,
            "legend": COLOR_STYLES,
        }

    # Text mode for big code — NEVER build a DOT graph
    text_view = build_ast_text_sections(
        tree,
        issues_by_line=issue_map,
        max_depth=max_depth,
        search_query=search_query,
        max_rows=max_rows,
    )
    return {
        "mode": "text",
        "node_count": decision["node_count"],
        "line_count": decision["line_count"],
        "badge_text": decision["badge_text"],
        "dot_source": None,
        "text_view": text_view,
    }
