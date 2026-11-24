# Template Format Specification (`docs/format_spec.md`)

Measured directly from [template.pdf](file:///c:/codes/AI%20Error%20Tutor/AI%20Error%20Tutor/ai-error-tutor/docs/template.pdf) (22 pages) using PyMuPDF (`pymupdf 2.1`, `page.get_text("dict")` and `page.get_drawings()`).

> **Annotation Exclusion Rule:** All red rectangle outlines, black-bordered callout boxes (e.g., *"General Introduction of the domain and title"*, *"Challenges"*, *"Pseudocode"*, *"Purpose of This"*, *"Draw an Existing Architecture Here"*, *"REFER APPENDIX BELOW"*), and arrows in the template PDF are professor instructions only and will **never** appear in the generated `.docx`.

---

## 1. Page Geometry, Margins, Columns & Running Elements

| Property | Measured in `template.pdf` | Target `.docx` Setting |
|---|---|---|
| Page Size (Main Paper, pp. 1–15) | US Letter: `612.0 × 792.0 pt` (`8.50 × 11.00 in`) | US Letter (`8.50 × 11.00 in`) |
| Page Size (Appendix, pp. 16–22) | A4: `595.2 × 841.92 pt` (`8.27 × 11.69 in`) *(merged separately in template)* | US Letter (`8.50 × 11.00 in`) for uniform printing *(or A4 section break if preferred)* |
| Column Layout | Single column across all 22 pages | Single column |
| Left Margin | `78.5 pt` (`1.09 in`) body; `72.0 pt` (`1.00 in`) appendix | `1.09 in` (`78.5 pt`) body (`1.00 in` in Appendix section) |
| Right Margin | `76.7 pt` (`1.07 in`) pp. 1–6 & 14–15; `92.8 pt` (`1.29 in`) pp. 7–9 & 12–13; `69.5 pt` (`0.97 in`) appendix | `1.07 in` (`77.0 pt`) uniform right margin |
| Top Margin | `45.0–51.2 pt` (`0.63–0.71 in`) main; `72.3 pt` (`1.00 in`) appendix | `0.70 in` (`50.4 pt`) main; `1.00 in` appendix |
| Bottom Margin | `~40–58 pt` (`0.56–0.80 in`) | `0.75 in` (`54.0 pt`) |
| Header / Footer / Page Numbers | None present on any of the 22 pages | None (clean unnumbered layout matching template) |

---

## 2. Typography & Paragraph Styles (Measured)

| Element | Font Family | Size (pt) | Style (B/I/U) | Alignment | Line Spacing | Indentation & Paragraph Spacing |
|---|---|---|---|---|---|---|
| **Paper Title** (p. 1) | Times New Roman | `24.0 pt` | Regular (not bold) | Centered | `27.8 pt` (`~1.15×`) | Before: `0 pt`, After: `24 pt` |
| **Abstract Heading** (p. 1) | Times New Roman | `16.0 pt` (`16.08`) | **Bold**, **Underline** | Centered | `1.15×` | Before: `12 pt`, After: `8 pt` |
| **Abstract Body** (p. 1) | Times New Roman | `12.0 pt` | Regular | Justified | `20.7 pt` (`1.5×`) | First-line indent: `0.14 in` (`10.1 pt`), After: `8 pt` |
| **Index Terms** (p. 2) | Times New Roman | `12.0 pt` | Label: **Bold Italic + Underline** (`Index Terms—`); Terms: Regular | Left / Justified | `1.5×` | First-line indent: `0.14 in` (`10.1 pt`), After: `14 pt` |
| **Heading 1 (Roman Sections I.–VI.)** | Times New Roman | `14.0 pt` *(measured `13.92 pt` numeral, `11.04–13.92 pt` title)* | **Bold**, ALL CAPS, Title **Underlined** | Centered | `1.15×` | Before: `16 pt`, After: `10 pt`, `keep_with_next=True` |
| **Inline Sub-label** (`Our Contribution:`) | Times New Roman | `12.0 pt` | **Bold** | Left | `1.5×` | Before: `6 pt`, After: `4 pt` |
| **Heading 2 (Lettered Sub-sections `A.`, `B.`, `C.`, `D.`...)** | Times New Roman | `14.0 pt` (`13.92 pt`) | **Bold**, *Italic*, **Underline** | Left | `1.15×` | Left indent: `-0.18 in` (flush left `0.90 in` from edge), Before: `12 pt`, After: `6 pt`, `keep_with_next=True` |
| **Body Paragraph** | Times New Roman | `12.0 pt` | Regular | Justified | `20.7 pt` (`1.5×`) | First-line indent: `0.14 in` (`10.1 pt`) on section opening / new paragraphs, After: `6 pt` |
| **Equations** (p. 6) | Cambria Math / Times New Roman | `12.0–13.0 pt` | *Italic* math variables, Regular operators & number `(1)` | Centered/Indented equation, Right-aligned `(N)` | `1.15×` | Before: `8 pt`, After: `8 pt` |
| **Algorithm Title** (pp. 6–9) | Times New Roman | `12.0–14.0 pt` | **Bold**, **Underline** | Left | `1.15×` | Before: `10 pt`, After: `4 pt`, `keep_with_next=True` |
| **Algorithm `Require:` / `Ensure:`** | Times New Roman | `12.0 pt` | Label **Bold**, variables *Italic* | Left | `1.25×` (`~16 pt`) | Flush left, After: `2 pt` |
| **Algorithm Numbered Lines** (`1:`, `2:`, ...) | Times New Roman | `12.0 pt` | Control keywords (**if, then, else, end if, for, do, end for, return, break**) **Bold**; variables *Italic* | Left | `1.25×` (`~16–18 pt`) | Nested blocks indented `+0.40 in` (`~30 pt`) per level; no outer box border |
| **Figure Caption (Main Paper)** (pp. 5, 10–12) | Times New Roman | `12.0 pt` | Regular (`Figure 1:` / `Figure 2.`) *(bold on `Figure 1. Proposed Architecture`)* | Centered | `1.15×` | Placed **below** figure; Before: `6 pt`, After: `6 pt` |
| **Figure Description Paragraph** | Times New Roman | `12.0 pt` | Regular | Justified | `1.5×` *(p. 12 uses `1.15×`)* | Placed directly below every figure caption; After: `8 pt` |
| **Tables** (pp. 10, 13) | Times New Roman | `11.0–12.0 pt` | Header row **Bold**; body Regular | Left-aligned cells | `1.15×` | Clean minimalist horizontal rules (`#D0D7DE`), no vertical grid lines, white background |
| **References Heading** (p. 14) | Times New Roman | `12.0 pt` *(template measured `9.6 pt` small-caps style)* | ALL CAPS (`REFERENCES`), **Bold** | Centered | `1.15×` | New page; Before: `6 pt`, After: `10 pt` |
| **Reference Entry** (pp. 14–15) | Times New Roman | `12.0 pt` | Regular; Conference/Journal title *Italic*; Title in quotes | Justified | `20.7 pt` (`1.5×`) | Hanging indent `0.25 in` (`18.2 pt`: `[1]` at `60.3 pt`, wrapped lines at `78.5 pt`), After: `4 pt` |
| **Appendix Heading** (p. 16) | Times New Roman *(Calibri in template p. 16)* | `20.0 pt` (`19.92 pt`) | **Bold**, **Underline**, ALL CAPS (`APPENDIX`) | Centered | `1.15×` | Starts on new page; After: `8 pt` |
| **Appendix Subtitle** (p. 16) | Times New Roman | `16.0 pt` (`16.08 pt`) | **Bold** (`(Sample Screenshots with Description)`) | Centered | `1.15×` | After: `14 pt` |
| **Appendix Figure Caption** (pp. 16–22) | Times New Roman | `11.0 pt` (`11.04 pt`) | **Bold** (`Fig. 1. <Title>.`) | Left-aligned | `1.15×` | Below screenshot; Before: `6 pt`, After: `4 pt` |
| **Appendix Figure Description** (pp. 16–22) | Times New Roman | `11.0 pt` (`11.04 pt`) | Regular | Justified | `13.7 pt` (`1.15×`) | Directly below caption; After: `12 pt` |

---

## 3. Document Section Order & Page Structure

1. **Title** (Page 1, centered 24 pt Times New Roman, regular weight)
2. **Abstract** (Page 1, one cohesive justified paragraph covering domain intro, challenges, proposed work, and real verified results)
3. **Index Terms** (Top of Page 2, bold-italic-underlined lead-in)
4. **I. INTRODUCTION** — Domain & purpose, challenges, motivation, research gaps, problem statement, and **Our Contribution:** (phase-wise overview)
5. **II. BACKGROUND CONCEPTS** — Preliminaries grounded in the actual project (compiler phases, AST, symbol tables, Levenshtein distance, SAST, sandboxing, LLMs & prompt injection, local vs. cloud models, multi-agent roles, cyclomatic complexity)
6. **III. RELATED WORK** — Organized under the template's four themes (at least 15 verified recent papers):
   - Compiler-Aware Error Explanation and Novice Programming Support
   - Lightweight Models for Programming Feedback
   - Structure-Aware AI and Static Vulnerability Analysis
   - Synthesis and Positioning of AI Error Tutor
7. **IV. PROPOSED FRAMEWORK** — High-level overview + **Existing Architecture** diagram + **Proposed Architecture** diagram (`Figure 1. Proposed Architecture`), followed by lettered sub-sections:
   - *A. User Interface:*
   - *B. Security Validator Engine:* (Equation + Algorithm 1)
   - *C. Code Execution Engine*
   - *D. AI Engine:* (Algorithm 2: Provider Fallback with Circuit Breaker)
   - *E. Multi-Agent Repair Loop:* (Algorithm 3: 4-Pass Multi-Error Repair Loop)
   - *F. Socratic Tutoring with Leak Verification:* (Algorithm 4: Socratic Hint Generation & Leak Check)
   - *G. Attacker Agent and Attack Lab:*
   - *H. Adaptive AST Visualisation:*
8. **V. EXPERIMENTAL RESULTS AND PERFORMANCE ANALYSIS** — Step-wise experimental setup, real Software & Hardware Specifications Table, GUI Screenshot + Description, 300-dpi Matplotlib Performance Graphs (each with a description paragraph below), and Evaluation Metrics Table with real numerical results (yellow `[TO BE FILLED: ...]` placeholders only where human-study data does not exist)
9. **VI. CONCLUSION** — Problem addressed, verified experimental findings, honest limitations, and future scope
10. **REFERENCES** — IEEE numbered style (`[1]`, `[2]`, ...) with every citation web-verified against publisher/DOI records
11. **APPENDIX (Sample Screenshots with Description)** — Real screenshots from `docs/screenshots/` (or clearly marked placeholders with exact filenames if missing), each with `Fig. N.` bold 11 pt caption and 11 pt description paragraph.
