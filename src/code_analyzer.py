"""
Code Health & Optimality Analyzer
Analyzes Python code for security posture and performance/algorithmic efficiency.
"""

import ast
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class CodeHealthReport:
    """Detailed health report evaluating security and optimality."""
    security_score: int
    security_grade: str
    optimality_score: int
    optimality_grade: str
    security_findings: List[str] = field(default_factory=list)
    optimality_findings: List[str] = field(default_factory=list)
    complexity_notes: List[str] = field(default_factory=list)


class CodeHealthAnalyzer:
    """Static AST-based analyzer for code efficiency and security scoring."""

    def __init__(self):
        pass

    def _calculate_grade(self, score: int) -> str:
        """Convert a 0-100 score to an academic grade."""
        if score >= 95:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"

    def analyze(self, code: str, security_warnings: Optional[List] = None) -> CodeHealthReport:
        """
        Analyze code and return comprehensive security & optimality metrics.
        """
        security_score = 100
        sec_findings = []

        # 1. Security Score Evaluation
        if security_warnings:
            has_blocked = any(getattr(w, 'level', '') == 'BLOCKED' for w in security_warnings)
            warning_count = sum(1 for w in security_warnings if getattr(w, 'level', '') == 'WARNING')

            if has_blocked:
                security_score = 10
                sec_findings.append("Critical: Code contains blocked high-risk system/shell or forbidden module operations.")
            else:
                security_score = max(30, 100 - (warning_count * 15))
                for w in security_warnings:
                    sec_findings.append(f"Line {getattr(w, 'line_number', '?')}: {getattr(w, 'message', str(w))}")
        
        if not sec_findings:
            sec_findings.append("Code passed all static security filters with zero sandbox policy violations.")

        # 2. Optimality & Efficiency Evaluation via AST
        optimality_score = 100
        opt_findings = []
        complexity_notes = []

        try:
            tree = ast.parse(code)
            
            # Check for Nested Loops (O(N^2) / O(N^3) complexity)
            nested_loop_count = 0
            for node in ast.walk(tree):
                if isinstance(node, (ast.For, ast.While)):
                    for child in ast.iter_child_nodes(node):
                        if isinstance(child, (ast.For, ast.While)):
                            nested_loop_count += 1
                            line_num = getattr(child, 'lineno', '?')
                            opt_findings.append(
                                f"Nested loop detected at line {line_num}. Time complexity is O(N^2) or higher. "
                                f"Consider pre-indexing with a dict or set for O(N) lookups."
                            )
            if nested_loop_count > 0:
                optimality_score -= min(30, nested_loop_count * 15)
                complexity_notes.append("High Polynomial Time Complexity (O(N^2)+)")
            else:
                complexity_notes.append("Linear or Constant Loop Depth (O(N) / O(1))")

            # Check for string concatenation inside loops (s = s + str or s += str)
            string_concat_in_loop = False
            for node in ast.walk(tree):
                if isinstance(node, (ast.For, ast.While)):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.AugAssign) and isinstance(sub.op, ast.Add):
                            if isinstance(sub.target, ast.Name):
                                string_concat_in_loop = True
                                line_num = getattr(sub, 'lineno', '?')
                                opt_findings.append(
                                    f"Repeated addition/concatenation inside loop at line {line_num}. "
                                    f"In Python, repeated string concatenation allocates new memory on each iteration. Use ''.join() for optimal speed."
                                )
                                break
            if string_concat_in_loop:
                optimality_score -= 15

            # Check for manual list accumulator loops that could be list comprehensions
            manual_appends = 0
            for node in ast.walk(tree):
                if isinstance(node, ast.For):
                    # Check if body consists solely of an append call
                    for stmt in node.body:
                        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                            func = stmt.value.func
                            if isinstance(func, ast.Attribute) and func.attr == 'append':
                                manual_appends += 1
                                line_num = getattr(stmt, 'lineno', '?')
                                opt_findings.append(
                                    f"Manual '.append()' loop found at line {line_num}. "
                                    f"Consider replacing with a list comprehension for faster C-level execution."
                                )
                                break
            if manual_appends > 0:
                optimality_score -= min(15, manual_appends * 5)

            # Check for searching list with 'in' inside loop
            list_search_in_loop = False
            for node in ast.walk(tree):
                if isinstance(node, (ast.For, ast.While)):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Compare):
                            for op in sub.ops:
                                if isinstance(op, (ast.In, ast.NotIn)):
                                    line_num = getattr(sub, 'lineno', '?')
                                    opt_findings.append(
                                        f"Membership check ('in' / 'not in') inside loop at line {line_num}. "
                                        f"Ensure the target collection is a set/dict for O(1) average lookup time."
                                    )
                                    list_search_in_loop = True
                                    break
            if list_search_in_loop:
                optimality_score -= 10

        except SyntaxError:
            optimality_score = 40
            opt_findings.append("Syntax error prevented complete AST optimality analysis.")
            complexity_notes.append("Syntax Unparseable")

        # Floor score at 10
        optimality_score = max(10, min(100, optimality_score))
        security_score = max(0, min(100, security_score))

        if not opt_findings:
            opt_findings.append("No common performance bottlenecks detected. Code uses clean linear patterns.")

        return CodeHealthReport(
            security_score=security_score,
            security_grade=self._calculate_grade(security_score),
            security_findings=sec_findings,
            optimality_score=optimality_score,
            optimality_grade=self._calculate_grade(optimality_score),
            optimality_findings=opt_findings,
            complexity_notes=complexity_notes
        )
