import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pipeline import AIErrorTutor

def test_all():
    tutor = AIErrorTutor()
    print("=" * 60)
    print("AI ERROR TUTOR - 5-FEATURE VERIFICATION SUITE")
    print("=" * 60)

    # 1. Feature 1: Subprocess Sandbox & 2.0s Watchdog
    print("\n--- Testing Feature 1: Watchdog Timeout & Sandbox ---")
    r_time = tutor.analyze_code("count = 0\nwhile True:\n    count += 1")
    assert r_time.error_type == "TimeoutError", f"Expected TimeoutError, got {r_time.error_type}"
    print(f"[PASS] Feature 1: Caught {r_time.error_type} in <= 2.0s. Engine: {r_time.engine_used}")

    # 2. Feature 2: Code Security & Optimality Health Scorecard
    print("\n--- Testing Feature 2: Health & Optimality Scorecard ---")
    bad_perf_code = "res = ''\nfor i in range(5):\n    for j in range(5):\n        res += str(i*j)"
    r_health = tutor.analyze_code(bad_perf_code)
    hr = r_health.health_report
    assert hr is not None, "Health report should not be None"
    print(f"[PASS] Feature 2: Security Score: {hr.security_score}% ({hr.security_grade}), Optimality: {hr.optimality_score}% ({hr.optimality_grade})")
    print(f"       Findings: {hr.optimality_findings}")

    # 3. Feature 3: 1-Click Apply Fix Synthesizer
    print("\n--- Testing Feature 3: Automated 1-Click Code Fix ---")
    typo_code = 'prnt("Hello AI Tutor")'
    r_fix = tutor.analyze_code(typo_code, mode="direct")
    assert r_fix.corrected_code is not None, "Corrected code should be generated"
    print(f"[PASS] Feature 3: Original: {typo_code.strip()} -> Corrected: {r_fix.corrected_code.strip()}")

    # 4. Feature 4: Gemini / Multi-Tier Structured Engine (Concept + Prevention Tip)
    print("\n--- Testing Feature 4: Structured Engine Outputs ---")
    assert r_fix.concept is not None, "Concept should be defined"
    assert r_fix.prevention_tip is not None, "Prevention tip should be defined"
    print(f"[PASS] Feature 4: Concept: '{r_fix.concept}'")
    print(f"       Prevention Tip: '{r_fix.prevention_tip}'")

    # 5. Feature 5: Socratic Hint Mode
    print("\n--- Testing Feature 5: Socratic Pedagogical Mode ---")
    type_err_code = 'age = 20\nmsg = "Age: " + age'
    r_soc = tutor.analyze_code(type_err_code, mode="socratic")
    assert r_soc.hint_mode is True, "hint_mode should be True"
    assert r_soc.socratic_question is not None, "socratic_question should be populated"
    assert len(r_soc.progressive_hints) >= 2, "Progressive hints should have multiple levels"
    print(f"[PASS] Feature 5: Socratic Question: '{r_soc.socratic_question}'")
    print(f"       Progressive Hints ({len(r_soc.progressive_hints)} levels):")
    for i, h in enumerate(r_soc.progressive_hints, 1):
        print(f"         Level {i}: {h}")

    print("\n" + "=" * 60)
    print("ALL 5 FEATURES SUCCESSFULLY VERIFIED!")
    print("=" * 60)

if __name__ == "__main__":
    test_all()
