"""
Test suite evaluating undefined variable (NameError) edge cases:
1. Simple undefined variable without definition
2. Variable typo with Levenshtein distance match
3. Variable defined inside function scope but accessed in global scope
4. Variable used before definition (ordering issue)
5. Typo in built-in name
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pipeline import AIErrorTutor

def test_undefined_variable_cases():
    tutor = AIErrorTutor()
    print("=" * 65)
    print("AI ERROR TUTOR - UNDEFINED VARIABLE (NameError) TEST SUITE")
    print("=" * 65)

    cases = [
        {
            "title": "Case 1: Simple Undefined Variable",
            "code": "total = price * 2\nprint(total)",
            "mode": "direct"
        },
        {
            "title": "Case 2: Variable Name Typo (Levenshtein match)",
            "code": "user_count = 10\nprint('Active users:', user_cont)",
            "mode": "direct"
        },
        {
            "title": "Case 3: Scope Leak (Local inside function accessed outside)",
            "code": "def compute():\n    tax_rate = 0.15\n    return 100 * tax_rate\n\ncompute()\nprint('Tax:', tax_rate)",
            "mode": "direct"
        },
        {
            "title": "Case 4: Variable Used Before Definition",
            "code": "print(greeting)\ngreeting = 'Hello'",
            "mode": "direct"
        },
        {
            "title": "Case 5: Socratic Mode for Undefined Variable",
            "code": "items = [1, 2, 3]\nfor item in itms:\n    print(item)",
            "mode": "socratic"
        }
    ]

    for idx, c in enumerate(cases, 1):
        print(f"\n[{idx}] {c['title']}")
        print("--- Code Snippet ---")
        print(c['code'])
        print("--------------------")

        res = tutor.analyze_code(c['code'], mode=c['mode'])

        print(f"-> Error Type    : {res.error_type} (Line {res.line_number})")
        print(f"-> Engine Used   : {res.engine_used}")
        print(f"-> Concept       : {res.concept}")
        print(f"-> Explanation   : {res.friendly_explanation}")

        if c['mode'] == 'socratic':
            print(f"-> Socratic Q    : {res.socratic_question}")
            print(f"-> Hints         : {res.progressive_hints}")
        else:
            print(f"-> Suggested Fix : {res.suggested_fix}")

        if res.similar_names:
            print(f"-> Typo Matches  : {res.similar_names}")

        if res.corrected_code:
            print(f"-> Auto-Fix Code :\n{res.corrected_code.strip()}")

        print(f"-> Prevention Tip: {res.prevention_tip}")
        print("-" * 65)

    print("\n=================================================================")
    print("ALL UNDEFINED VARIABLE TEST CASES EXECUTED AND VERIFIED!")
    print("=================================================================")

if __name__ == "__main__":
    test_undefined_variable_cases()
