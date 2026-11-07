# ContextBasedAIAttacks

**Dissertation:** Context-Based Adversarial Manipulation of AI Code Generators  
**Author:** Walther A. Del Orbe | waltdelorbe@gmail.com  
**Institution:** Dakota State University — Beacom College of Computer and Cyber Sciences  
**Chair:** Dr. Michael Ham | **Committee:** Dr. O'Brien · Dr. Kramer  
**Status:** Post-Defense · Pre-Publication Review

---

## Purpose

This repository contains all experimental data, scripts, and statistical verification materials supporting the dissertation. Dr. Ham and the committee can use it to independently verify every statistic reported in Chapter 4 without re-running the original experiments.

---

## Core Dissertation Statistics (Table 4.1)

All values taken directly from Chapter 4 tables. These are the numbers the committee will verify.

| Model | Test Cases | Baseline VGR | Adversarial VGR | Increase Factor |
|-------|------------|-------------|-----------------|-----------------|
| CodeT5+ (770M) | 1,000 | 0.0% | 26.7% | N/A* |
| CodeLlama (7B) | 1,000 | 17.6% | 55.2% | 3.14× |
| GPT-3.5-Turbo | 100 | 12.0% | 44.7% | 3.72× |
| GPT-4 | 44 | 10.0% | 37.9%† | 3.79× |
| **Overall Mean** | **3,184** | **9.9%** | **41.1%** | **3.55×** |

\* CodeT5+ baseline = 0.0% → multiplicative factor undefined (division by zero).  
† GPT-4 adversarial VGR excludes the n=1 obfuscation outlier per §4.8.4.

**Key statistics:** χ²(1) = 847.3, p < 0.001 · Cohen's d = 1.2–3.8 · κ = 0.87  
**95% CI for overall adversarial VGR:** [35.1%, 39.7%] · **Bootstrap:** B=10,000, seed=42

> **Note on §4.10 text:** The summary text states "10.7-fold amplification" and uses slightly different baseline/adversarial figures (3.5%/37.4%) compared to Table 4.1's weighted values (9.9%/41.1%). Both are present in the dissertation. Table 4.1 values are used as primary statistics throughout this repository.

---

## About the GPT-6 Astra Data

GPT-6 Astra was tested as a **supplemental novel test** prior to the final defense to explore whether findings generalize to next-generation models. It was **not included in the dissertation document** or the core statistical analyses (Tables 4.1–4.6). Its data lives in `data/gpt6_extension/` and is included for transparency only.

- **N = 100** GPT-6 Astra trials (not part of the dissertation's N = 3,184)
- **API cost:** ~$16.53
- Key observation: GPT-6 showed lower adversarial susceptibility than GPT-3.5/GPT-4, suggesting improved safety alignment in next-generation models — but remained susceptible to contextual manipulation.

---

## Repository Structure

```
ContextBasedAIAttacks/
├── final_statistics_verification.html   ← Open in browser — committee verification page
├── statistical_verification.html        ← Chapter 4 tables + math derivations
├── README.md                             ← This file
├── SETUP.md                              ← Python setup + verification instructions
├── requirements.txt                      ← numpy 2.0.2 · scipy 1.14.1
│
├── data/                                 ← DISSERTATION data files (N=3,184)
│   ├── pilot_experiment_results_codet5_codellama.json
│   ├── pilot_experiment_v2_results.json
│   ├── pilot_experiment_v2_rescored.json
│   ├── week3_5_experiments_final.json
│   ├── week6_8_advanced_final.json
│   ├── week9_10_defense_results.json
│   ├── week9_10_defense_rescored.json
│   ├── week11_results_raw_50.json
│   ├── week11_results_raw_5iter_pilot.json
│   ├── week11_summary_50_iterations.json
│   ├── week11_summary_5_iterations_pilot.json
│   ├── openai_full_gpt_35_turbo.json
│   ├── openai_full_gpt_4.json
│   ├── openai_comparison_final.json
│   ├── openai_confidence_boost.json
│   └── gpt6_extension/                  ← SUPPLEMENTAL (not in dissertation)
│       └── gpt6_astra_full_results.json
│
├── scripts/
│   ├── verify_statistics.py             ← Main verification script
│   └── experiment_scripts/              ← Original experiment scripts (reference only)
│
└── dissertation_chapters/               ← All 6 dissertation chapters (.docx)
    ├── Chapter1_Introduction_Revised.docx
    ├── Chapter2_LiteratureReview_Revised.docx
    ├── Chapter3_Methodology_Revised.docx
    ├── Chapter4_Results_Revised.docx
    ├── Chapter4_Appendices_Revised.docx
    └── Chapter5_Conclusions_Revised.docx
```

---

## Experimental Design (Chapter 3 §3.7 — 4-Phase Structure)

| Phase | Weeks | Activity | Models |
|-------|-------|----------|--------|
| Phase 1 | 1–2 | Pilot / Infrastructure Validation | CodeT5+, CodeLlama (n=100 each) |
| Phase 2 | 3–6 | Baseline Data Collection | CodeT5+, CodeLlama (n=900 each) |
| Phase 3 | 7–10 | Adversarial Data Collection | All 4 models (CodeT5+, CodeLlama, GPT-3.5, GPT-4) |
| Phase 4 | 11–12 | Vulnerability Assessment & Defense Evaluation | All 4 models |

---

## Vulnerability Categories Tested (Chapter 4 Table 4.4)

| Category | CWE | Models Tested |
|----------|-----|---------------|
| SQL Injection | CWE-89 | All four |
| Cross-Site Scripting (XSS) | CWE-79 | All four |
| Hardcoded Credentials | CWE-798 | All four |
| Path Traversal | CWE-22 | All four |
| Insecure Cryptography | CWE-327 | Local models only |
| Command Injection | — | Commercial models only |

---

## Quick Start — Verification

1. **Open `final_statistics_verification.html`** in any browser — no server required.  
   This page contains every dissertation statistic with source citations and math derivations.

2. **Or run the Python verification script:**
   ```bash
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   python scripts/verify_statistics.py
   ```

See `SETUP.md` for full instructions including Windows setup.

---

## Citation

```
Del Orbe, W. A. (2026). Context-Based Adversarial Manipulation of AI Code
Generators [Ph.D. dissertation]. Dakota State University, Beacom College
of Computer and Cyber Sciences. Contact: waltdelorbe@gmail.com
```

