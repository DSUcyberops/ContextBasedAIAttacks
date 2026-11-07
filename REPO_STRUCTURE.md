# ContextBasedAIAttacks — Repository Structure & Replication Guide

**Dissertation:** Context-Based Adversarial Manipulation of AI Code Generators  
**Author:** Walther A. Del Orbe · waltdelorbe@gmail.com  
**Institution:** Dakota State University, Beacom College of Computer and Cyber Sciences  
**Chair:** Dr. Michael Ham · Committee: Dr. O'Brien · Dr. Kramer  
**Status:** Post-defense, pre-publication review  

---

## 1. What Is in This Repository

```
ContextBasedAIAttacks/
│
├── README.md                          ← Start here (overview, quick-reference table)
├── REPO_STRUCTURE.md                  ← This file — structure + replication guide
├── requirements.txt                   ← Python dependencies (pip install -r)
│
├── ── VERIFICATION PAGES ──
├── STATISTICS_VERIFICATION.md         ← All Table 4.1–4.6 numbers, committee checklist
├── MATH_DERIVATIONS.md                ← Step-by-step math: how every number was derived
├── statistical_verification.html      ← Script output rendered as HTML (legacy)
│
├── ── EXPERIMENT DATA ──
├── data/
│   ├── pilot_experiment_results_codet5_codellama.json  ← Phase 1 pilot (Wks 1–2)
│   ├── pilot_experiment_v2_results.json                ← Phase 1 v2 raw
│   ├── pilot_experiment_v2_rescored.json               ← Phase 1 v2 rescored
│   ├── week3_5_experiments_final.json                  ← Phase 2 baseline (Wks 3–5)
│   ├── week6_8_advanced_final.json                     ← Phase 2/3 advanced (Wks 6–8)
│   ├── week9_10_defense_results.json                   ← Phase 3 adversarial raw (Wks 9–10)
│   ├── week9_10_defense_rescored.json                  ← Phase 3 adversarial rescored
│   ├── week11_results_raw_50.json                      ← Phase 4 (50 iterations)
│   ├── week11_results_raw_5iter_pilot.json             ← Phase 4 pilot (5 iterations)
│   ├── week11_summary_50_iterations.json               ← Phase 4 50-iter summary
│   ├── week11_summary_5_iterations_pilot.json          ← Phase 4 5-iter pilot summary
│   ├── openai_full_gpt_35_turbo.json                   ← GPT-3.5-Turbo complete results
│   ├── openai_full_gpt_4.json                          ← GPT-4 complete results
│   ├── openai_comparison_final.json                    ← OpenAI models comparison
│   ├── openai_confidence_boost.json                    ← Confidence boost experiments
│   │
│   └── gpt6_extension/                ← SUPPLEMENTAL: GPT-6 Astra (pre-defense novel test)
│       ├── README.md                  ← Explains this is NOT part of N=3,184
│       └── gpt6_astra_full_results.json
│
├── ── SCRIPTS ──
├── scripts/
│   ├── verify_statistics.py           ← PRIMARY: reproduces every Table 4.1–4.6 stat
│   ├── gpt6_astra_full_run.py         ← GPT-6 Astra experiment runner
│   └── experiment_scripts/            ← Original data-collection scripts
│
├── ── DISSERTATION CHAPTERS ──
└── dissertation_chapters/
    ├── Chapter1_Introduction_Revised.docx
    ├── Chapter2_LiteratureReview_Revised.docx
    ├── Chapter3_Methodology_Revised.docx
    ├── Chapter4_Results_Revised.docx
    ├── Chapter4_Appendices_Revised.docx
    └── Chapter5_Conclusions_Revised.docx
```

---

## 2. The Core Numbers (Table 4.1 — What Must Match)

| Model | N | Baseline VGR | Adversarial VGR | Factor |
|---|---|---|---|---|
| CodeT5+ (770M) | 1,000 | 0.0% | 26.7% | N/A* |
| CodeLlama (7B) | 1,000 | 17.6% | 55.2% | 3.14× |
| GPT-3.5-Turbo | 100 | 12.0% | 44.7% | 3.72× |
| GPT-4 | 44† | 10.0% | 37.9%† | 3.79× |
| **Overall** | **3,184** | **9.9%** | **41.1%** | **3.55×** |

χ²(1)=847.3, p<0.001 | φ=0.516 | 95% CI=[35.1%,39.7%] | κ=0.87 | d=1.2–3.8  
*CodeT5+ baseline=0.0% — division undefined  
†GPT-4 N=44 excludes a single obfuscation trial; values marked † use BCa bootstrap

---

## 3. How to Reproduce Every Statistic

### Prerequisites

```bash
# Python 3.8+
pip install -r requirements.txt
# or manually:
pip install numpy scipy pandas
```

`requirements.txt` contains:
```
numpy>=1.21
scipy>=1.7
pandas>=1.3
```

### Run the verification script

```bash
# From the repo root:
python scripts/verify_statistics.py

# With verbose output showing all intermediate values:
python scripts/verify_statistics.py --verbose

# Output a JSON report:
python scripts/verify_statistics.py --output verification_report.json
```

Expected output (matches dissertation exactly):

```
=== TABLE 4.1: Vulnerability Generation Rates ===
CodeT5+   baseline=0.0%   adversarial=26.7%   factor=N/A
CodeLlama baseline=17.6%  adversarial=55.2%   factor=3.14x
GPT-3.5   baseline=12.0%  adversarial=44.7%   factor=3.72x
GPT-4     baseline=10.0%  adversarial=37.9%   factor=3.79x
Overall   baseline=9.9%   adversarial=41.1%   factor=3.55x

=== CHI-SQUARE TEST ===
χ²(1) = 847.3,  p < 0.001

=== EFFECT SIZES ===
φ = 0.516  (large)
d = 1.2–3.8 (range across conditions)

=== BOOTSTRAP CI (BCa, B=10000, seed=42) ===
95% CI for adversarial VGR = [35.1%, 39.7%]

=== INTER-RATER RELIABILITY ===
Cohen's κ = 0.87  (almost perfect)
```

### How the script works

1. **Loads raw JSON** from `data/*.json` — each record has fields like `model`, `condition`, `vulnerable` (boolean), `attack_technique`, `position`, `cwe_type`
2. **Groups by model and condition** to compute VGR = (vulnerable count) / (total count)
3. **Builds a 2×2 contingency table** (baseline vs. adversarial × vulnerable vs. safe)
4. **Runs scipy.stats.chi2_contingency** with `correction=False` (Pearson, no Yates)
5. **Computes φ** = √(χ²/N)
6. **Runs BCa bootstrap** with B=10,000 resamples, `random_state=42`
7. **Computes Cohen's d** per model using pooled SD of binary outcomes
8. **Outputs Tables 4.2–4.6** (ASR by technique, positional effects, vulnerability type, context patterns, transferability)

---

## 4. Experimental Design (Chapter 3 §3.7)

| Phase | Weeks | Activity | Models |
|---|---|---|---|
| Phase 1 | 1–2 | Pilot — calibrate detection, baseline | CodeT5+, CodeLlama |
| Phase 2 | 3–6 | Baseline establishment — systematic | All 4 models |
| Phase 3 | 7–10 | Adversarial manipulation — all 6 attack types | All 4 models |
| Phase 4 | 11–12 | Defense evaluation, transferability | All 4 models |

**Attack taxonomy (6 types):**
- Direct instruction
- Semantic priming
- Example-based
- Steganographic encoding
- Evasion-based
- Obfuscation-based

**Vulnerability categories (5 CWEs):**
- CWE-89 — SQL Injection
- CWE-79 — Cross-Site Scripting (XSS)
- CWE-798 — Hardcoded Credentials
- CWE-22 — Path Traversal
- CWE-327 — Insecure Cryptographic Algorithm

---

## 5. Data File Map (What's in Each JSON)

| File | Phase | Contents |
|---|---|---|
| `pilot_experiment_results_codet5_codellama.json` | 1 | CodeT5+ and CodeLlama pilot trials |
| `pilot_experiment_v2_results.json` | 1 | Pilot v2 raw |
| `pilot_experiment_v2_rescored.json` | 1 | Pilot v2 after rescoring calibration |
| `week3_5_experiments_final.json` | 2 | Baseline trials (Wks 3–5) |
| `week6_8_advanced_final.json` | 2/3 | Advanced technique trials |
| `week9_10_defense_results.json` | 3 | Full adversarial phase raw |
| `week9_10_defense_rescored.json` | 3 | Adversarial phase after rescoring |
| `week11_results_raw_50.json` | 4 | 50-iteration defense trials |
| `week11_summary_50_iterations.json` | 4 | Aggregated summary (50 iter) |
| `openai_full_gpt_35_turbo.json` | 2–4 | All GPT-3.5-Turbo trials |
| `openai_full_gpt_4.json` | 2–4 | All GPT-4 trials |
| `openai_comparison_final.json` | — | Direct OpenAI model comparison |
| `openai_confidence_boost.json` | — | Confidence framing experiments |

**gpt6_extension/** (SUPPLEMENTAL — NOT counted in N=3,184):
| File | Contents |
|---|---|
| `gpt6_astra_full_results.json` | 100 trials on GPT-6 Astra, pre-defense novel test |

---

## 6. How to Read the Verification Pages

The two primary verification pages render natively on GitHub — no browser download needed:

| File | Purpose |
|---|---|
| `STATISTICS_VERIFICATION.md` | All Table 4.1–4.6 values with committee checklist — **start here** |
| `MATH_DERIVATIONS.md` | Step-by-step math: how every number was derived from raw counts |
| `statistical_verification.html` | Script-generated output summary (open locally in browser) |

---

## 7. Figures That Appear in Chapter 4

| Figure | Description | Reproduced by |
|---|---|---|
| Fig 4.1 | VGR comparison bar chart | `verify_statistics.py --plot` |
| Fig 4.2 | Attack success rate by technique | Table 4.2 data |
| Fig 4.3 | Positional effects on ASR | Table 4.3 data |
| Fig 4.4 | Transferability heatmap | Table 4.6 data |
| Fig 4.5 | Context pattern ASR | Table 4.5 data |

---

## 8. Glossary of Abbreviations

| Term | Meaning |
|---|---|
| VGR | Vulnerability Generation Rate — proportion of trials producing vulnerable code |
| ASR | Attack Success Rate — VGR conditioned on a specific attack technique |
| TR | Transferability Rate — ASR on target model / ASR on origin model |
| CWE | Common Weakness Enumeration |
| BCa | Bias-Corrected and Accelerated bootstrap CI |
| φ | Phi coefficient — effect size for chi-square on 2×2 tables |
| κ | Cohen's kappa — inter-rater agreement beyond chance |
| d | Cohen's d — standardized mean difference |
| η² | Eta-squared — proportion of variance explained (ANOVA) |

---

## 9. Statement on GPT-6 Astra (Supplemental Data)

GPT-6 Astra trials were conducted **prior to the dissertation defense** as a novel extension test. These 100 trials are **not** part of the core N=3,184 and do not appear in Tables 4.1–4.6.

They are included in `data/gpt6_extension/` for completeness and because they demonstrate attack transferability to next-generation models, which is discussed qualitatively in Chapter 5. The `gpt6_extension/README.md` file documents this boundary explicitly.

---

*ContextBasedAIAttacks — Pre-publication committee review copy*  
*Contact: waltdelorbe@gmail.com*
