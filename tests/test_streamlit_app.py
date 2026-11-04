"""
Interactive Streamlit AppTest simulating UI actions:
1. Entering buggy code in text_area
2. Running analysis
3. Verifying output cards and suggested fix
4. Clicking 'Apply Fix to Editor' button (validating on_click callback without instantiation errors)
5. Re-analyzing to verify clean execution
"""

import os
import sys
from streamlit.testing.v1 import AppTest

def test_streamlit_interactive_flow():
    print("=" * 60)
    print("STREAMLIT APPTEST: INTERACTIVE UI & APPLY FIX VALIDATION")
    print("=" * 60)

    main_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")
    app = AppTest.from_file(main_path, default_timeout=120)
    app.run(timeout=120)
    assert not app.exception, f"App threw unexpected exception on startup: {app.exception}"
    print("[PASS] Step 1: Streamlit App started and rendered initial screen without errors.")

    # 1. Enter TypeError snippet into the text area
    buggy_code = 'name = "Alice"\nscore = 95\nprint("Student " + name + " scored: " + score)'
    app.text_area(key="code_area").input(buggy_code)
    app.run(timeout=120)
    assert not app.exception, f"App threw error when typing in editor: {app.exception}"
    print("[PASS] Step 2: Entered code into editor text_area successfully.")

    # 2. Click 'Run Analysis' button
    run_btn = next((b for b in app.button if "Run Analysis" in b.label), None)
    assert run_btn is not None, "Could not find 'Run Analysis' button"
    run_btn.click()
    app.run(timeout=120)
    assert not app.exception, f"App threw error during analysis execution: {app.exception}"
    print("[PASS] Step 3: [Run Analysis] clicked and execution completed cleanly.")

    # 3. Verify that result was generated and 'Apply Fix to Editor' button is present
    last_res = app.session_state["last_result"]
    assert last_res is not None, "Expected last_result in session_state"
    assert last_res.error_type == "TypeError", f"Expected TypeError, got {last_res.error_type}"
    print(f"[PASS] Step 4: Correctly diagnosed {last_res.error_type} at line {last_res.line_number}.")
    print(f"       Suggested Fix: {last_res.suggested_fix}")
    print(f"       Corrected Code Preview:\n{last_res.corrected_code}")

    apply_btn = next((b for b in app.button if "Apply Fix" in b.label), None)
    assert apply_btn is not None, "Could not find 'Apply Fix to Editor' button"

    # 4. Click 'Apply Fix to Editor' button
    print("\n--- Testing Apply Fix Button Callback ---")
    apply_btn.click()
    app.run(timeout=120)
    assert not app.exception, f"App threw error when clicking Apply Fix: {app.exception}"

    # Verify that code_area was updated with the corrected code!
    current_editor_code = app.session_state["code_area"]
    assert "str(score)" in current_editor_code or "+ str(" in current_editor_code, f"Editor code was not updated! Found: {current_editor_code}"
    print("[PASS] Step 5: [Apply Fix to Editor] clicked! Editor was updated in-place with:")
    print("------------------------------------------------------------")
    print(current_editor_code)
    print("------------------------------------------------------------")

    # 5. Run analysis on the fixed code
    print("\n--- Verifying Fixed Code Re-Analysis ---")
    run_btn = next((b for b in app.button if "Run Analysis" in b.label), None)
    run_btn.click()
    app.run(timeout=120)
    assert not app.exception, f"App threw error when analyzing fixed code: {app.exception}"
    
    new_res = app.session_state["last_result"]
    assert new_res is not None and new_res.success is True, f"Expected successful build, got {new_res}"
    print("[PASS] Step 6: Fixed code re-analyzed: 'Build successful - No runtime errors detected.'")

    print("\n" + "=" * 60)
    print("ALL INTERACTIVE UI STEPS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == "__main__":
    test_streamlit_interactive_flow()
