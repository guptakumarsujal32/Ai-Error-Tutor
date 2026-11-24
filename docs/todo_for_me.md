# Checklist Before Final Submission (`docs/todo_for_me.md`)

Every item below corresponds to a yellow-highlighted `[TO BE FILLED: ...]` placeholder in [AI_Error_Tutor_Project_Documentation.docx](AI_Error_Tutor_Project_Documentation.docx) or an external fact/decision you should verify before handing in the report.

---

## 1. Missing Application Screenshots (`docs/screenshots/`)

Create the folder `docs/screenshots/`, capture the 11 screenshots below from your running Streamlit app (`streamlit run main.py`) and terminal, and paste them into the corresponding dashed boxes in the Word file (or re-run the builder script once saved):

- [ ] `docs/screenshots/01_gui_main.png` — Main Streamlit IDE workspace showing the multi-tab code editor, error-line highlights, terminal output, and bottom analysis tabs
- [ ] `docs/screenshots/02_clean_execution.png` — Screenshot of a clean bug-free Python script running in AI Error Tutor with zero errors
- [ ] `docs/screenshots/03_multi_error_diagnostics.png` — Screenshot of the Diagnostics tab showing multiple errors, warnings, and a cascade tag on a multi-bug script
- [ ] `docs/screenshots/04_direct_solution_diff.png` — Screenshot of the Tutor & Fix / Fixed Code tabs displaying a unified diff and sandbox-verified 1-click Apply button
- [ ] `docs/screenshots/05_socratic_hints.png` — Screenshot of Socratic Hint Mode showing progressive Level 1-3 hints with the full solution locked
- [ ] `docs/screenshots/06_ast_graph_small.png` — Screenshot of the AST Graph tab on a small (<60 lines, <150 nodes) script displaying the color-coded Graphviz DOT diagram and legend
- [ ] `docs/screenshots/07_ast_text_large.png` — Screenshot of the AST Graph tab on a large (>150 nodes) script displaying Text Mode badge, collapsible expanders, search box, and Max Depth slider
- [ ] `docs/screenshots/08_security_quarantine.png` — Screenshot of the Security & Audit tab blocking a malicious import or prompt-injection payload with risk score and audit log
- [ ] `docs/screenshots/09_code_health_analytics.png` — Screenshot of Code Health grading (A+ to F) and Session Analytics showing local vs. cloud CO2 telemetry and cache hits
- [ ] `docs/screenshots/10_attack_lab.png` — Screenshot of the Attack Lab tab showing 33/33 defended attacks across 11 categories (24 blocked, 9 contained, 0 escaped)
- [ ] `docs/screenshots/11_pytest_results.png` — Screenshot of terminal output showing python -m pytest passing 51/51 automated tests across the 7 core suites

## 2. Missing Evaluation Metrics (Not Present in Codebase)

- [ ] **Missing Table Metric:** Conduct small student/peer trial (e.g., 10-20 users) and record Likert helpfulness score if required by your department
- [ ] **Confusion Matrix (Intentionally Omitted):** The professor's template included a confusion matrix because that older project trained a T5 classifier. Our live system is a hybrid multi-agent LLM + AST repair pipeline (not a supervised error-type classifier), so no confusion matrix was fabricated. If your course rubric explicitly requires a confusion matrix, build a labeled benign-vs.-malicious code dataset (e.g., 50 benign + 50 malicious samples), run `AAISecurityGuard` + `CodeSecurityValidator` on it, and add a real binary security-gate confusion matrix.

## 3. References & Verification Status

- All **20 IEEE references (`[1]`–`[20]`)** in the `REFERENCES` section were verified online against publisher/DOI/arXiv metadata (zero unverified or fabricated citations).
- Still double-check your university's title page / author name / roll number / guide name requirements: the professor's template PDF starts directly with the 24 pt Title and Abstract (no separate cover page or author block), so our `.docx` follows that exact layout. Add your name, roll number, and faculty guide below the title if your department expects them.

## 4. Claims & Details for You to Confirm

- [ ] Confirm the exact **project title** on Page 1 (`AI Error Tutor: A Security-Gated Multi-Agent Compiler and Hybrid LLM Framework for Python Error Diagnosis and Repair`).
- [ ] Confirm the **hardware specs** in Table 1 match the laptop you will demo on (`Windows 11`, `13th Gen Intel Core i5-13420H`, `15.64 GB RAM`, `NVIDIA GeForce RTX 3050 A 4 GB`, `Python 3.14.6`).
- [ ] Confirm **LibreOffice / Word visual layout**: LibreOffice (`soffice`) was not installed on this machine, so open `docs/AI_Error_Tutor_Project_Documentation.docx` in Microsoft Word once to verify page breaks around figures, tables, and the Appendix.
- [ ] Confirm that you are comfortable reporting the honest **44-line offline AST-only vs. live hybrid LLM** comparison in Table 3 (`Offline AST-only: verified = No` vs. `Live Hybrid LLM: verified = Yes in 25.28 s`), which empirically justifies why the LLM layer is needed.
