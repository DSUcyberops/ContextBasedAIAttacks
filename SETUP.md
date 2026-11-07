# Replication Setup Guide

**Dissertation:** Context-Based Adversarial Manipulation of AI Code Generators  
**Author:** Walther A. Del Orbe | waltdelorbe@gmail.com  
**Chair:** Dr. Michael Ham | **Committee:** Dr. O'Brien · Dr. Kramer

---

## Prerequisites

- **Python 3.9 or later** — download from [python.org](https://www.python.org/downloads/)
- **Git** (optional) — only needed if cloning from GitHub; not required if unzipping the archive

Verify your Python version:

```bash
python --version        # Windows
python3 --version       # macOS / Linux
```

You need **3.9, 3.10, 3.11, or 3.12**. Python 3.13+ has not been tested.

---

## Step 1 — Get the files

**Option A — Unzip the archive (simplest)**

```
ContextBasedAIAttacks.zip
└── ContextBasedAIAttacks/   ← your working directory
```

**Option B — Clone from GitHub (if published)**

```bash
git clone https://github.com/DSUcyberops/ContextBasedAIAttacks.git
cd dissertation-verification
```

---

## Step 2 — Create a virtual environment

A virtual environment keeps these packages isolated from your system Python and ensures exact version matching.

### macOS / Linux

```bash
cd dissertation-verification          # enter the project folder
python3 -m venv venv                  # create the environment
source venv/bin/activate              # activate it
# your prompt will change to: (venv) $
```

### Windows (Command Prompt)

```bat
cd dissertation-verification
python -m venv venv
venv\Scripts\activate.bat
:: your prompt will change to: (venv) C:\...>
```

### Windows (PowerShell)

```powershell
cd dissertation-verification
python -m venv venv
.\venv\Scripts\Activate.ps1
# If you get an execution-policy error, run first:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Step 3 — Install exact dependencies

```bash
pip install -r requirements.txt
```

This installs **numpy 2.0.2** and **scipy 1.14.1** — the exact versions used when the experiments were run. Installing different versions may produce floating-point rounding differences in the 4th or 5th decimal place, which does not affect any reported statistic (all results are rounded to 1 decimal place).

Verify the install:

```bash
python -c "import numpy, scipy; print('numpy', numpy.__version__, '| scipy', scipy.__version__)"
# Expected: numpy 2.0.2 | scipy 1.14.1
```

---

## Step 4 — Run the verification script

```bash
# From inside the ContextBasedAIAttacks/ folder with venv active:
python scripts/verify_statistics.py
```

The script will:
1. Load all JSON data files from `data/`
2. Apply the `detect_vulnerability()` detector to raw records (Phases 2, 3 (commercial))
3. Read pre-scored fields for Phases 1, 4, and the GPT-6 supplemental
4. Compute chi-square, phi coefficient, and bootstrap CIs for every phase
5. Print a formatted verification report to the terminal

**Expected runtime:** under 60 seconds on any modern laptop.

### Optional flags

```bash
# Save machine-readable JSON output
python scripts/verify_statistics.py --output verification_results.json

# Point to a different data directory
python scripts/verify_statistics.py --data-dir /path/to/data
```

---

## Step 5 — View the interactive HTML reports

Two standalone HTML pages are included — open either directly in any web browser. No server required, no internet connection needed.

### statistical_verification.html — Chapter 4 Tables + Math Derivations

```bash
# macOS
open statistical_verification.html

# Linux
xdg-open statistical_verification.html

# Windows
start statistical_verification.html
```

Shows all seven dissertation tables (Tables 4.1–4.7), every mathematical derivation with worked examples, bootstrap confidence intervals, and step-by-step computation traces.

### final_statistics_verification.html — Chair Review: Every Reported Statistic

```bash
# macOS
open final_statistics_verification.html

# Linux
xdg-open final_statistics_verification.html

# Windows
start final_statistics_verification.html
```

A dedicated verification page for Dr. Ham and the committee. Lists every quantitative claim in the dissertation (all 52 statistics), organized by research question, with: exact dissertation value, source table, raw counts, formula, computed value, and verification status (✔ Verified / ⊘ Accepted/Noted). Includes full chi-square derivations, confidence interval table, Cohen's κ worked example, and a master checklist.

---

## Step 6 — Deactivate when done

```bash
deactivate
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python: command not found` | Use `python3` instead, or add Python to your PATH |
| `pip: command not found` | Use `pip3`, or `python -m pip` |
| PowerShell execution policy error | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `ModuleNotFoundError: No module named 'scipy'` | Make sure the venv is activated (check for `(venv)` prefix) |
| Numbers differ slightly from dissertation | Expected if using different scipy/numpy versions; differences appear only after the 3rd decimal place |
| Script can't find data files | Run from the `ContextBasedAIAttacks/` root directory |

---

## What the script does NOT require

- No OpenAI API key
- No internet connection
- No GPU or special hardware
- No Docker or container runtime
- No conda or other package manager (plain `pip` is sufficient)

---

## Reproducing the original experiments (optional — not required for verification)

The original experiment scripts in `scripts/experiment_scripts/` require:
- An OpenAI API key with access to the relevant models
- Hugging Face `transformers` and `torch` for local models (CodeT5+, CodeLlama)
- Significant compute time and API cost (~$16.53 for the GPT-6 Astra run alone)

These are provided for transparency only. **Running `verify_statistics.py` is the intended verification method.**

---

## Citation

```
Del Orbe, W. A. (2026). Context-Based Adversarial Manipulation of AI Code
Generators — Statistical Verification Repository [Ph.D. dissertation].
Dakota State University, Beacom College of Computer and Cyber Sciences.
Contact: waltdelorbe@gmail.com
```
