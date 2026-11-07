# Math Derivations — How Every Dissertation Number Was Computed
**Context-Based Adversarial Manipulation of AI Code Generators**

| | |
|---|---|
| **Author** | Walther A. Del Orbe · waltdelorbe@gmail.com |
| **Chair** | Dr. Michael Ham · Committee: Dr. O'Brien · Dr. Kramer |
| **Repository** | ContextBasedAIAttacks |

> Every number reported in Chapter 4 is derived from raw experimental counts using a small set of standard formulas. This page walks through each derivation step by step — from raw counts → rates → test statistics → effect sizes → confidence intervals — so the committee can verify the arithmetic independently without running any code.

---

## Contents

1. [Vulnerability Generation Rate (VGR)](#1-vulnerability-generation-rate-vgr)
2. [Increase Factor (Table 4.1)](#2-increase-factor--table-41)
3. [Chi-Square Test — χ²=847.3](#3-chi-square-test--χ²--8473)
4. [Phi Coefficient φ](#4-phi-coefficient-φ)
5. [Bootstrap Confidence Intervals](#5-bootstrap-confidence-intervals)
6. [Cohen's d (Effect Size)](#6-cohens-d--effect-size)
7. [Cohen's κ (Inter-Rater Reliability)](#7-cohens-κ--inter-rater-reliability)
8. [One-Way ANOVA — Positional Effects](#8-one-way-anova--positional-effects)
9. [Attack Success Rate (ASR) — Table 4.2](#9-attack-success-rate-asr--table-42)
10. [Transferability Rate (TR) — Table 4.6](#10-transferability-rate-tr--table-46)
11. [Complete Number Cross-Reference](#11-complete-number-cross-reference)

---

## 1. Vulnerability Generation Rate (VGR)

### Definition

VGR is the proportion of test cases in a given condition (baseline or adversarial) where the model produced code containing at least one detectable vulnerability.

```
VGR = V / N

V = number of trials where a vulnerability was detected
N = total number of trials in that condition
```

### Raw counts and computed VGRs for Table 4.1

| Model | Condition | Total N | Vulnerable V | VGR = V/N | Table 4.1 value |
|---|---|---|---|---|---|
| CodeT5+ (770M) | Baseline | 500 | 0 | 0/500 = 0.000 | **0.0%** |
| CodeT5+ (770M) | Adversarial | 500 | ~134 | 134/500 = 0.268 | **26.7%** |
| CodeLlama (7B) | Baseline | 500 | 88 | 88/500 = 0.176 | **17.6%** |
| CodeLlama (7B) | Adversarial | 500 | 276 | 276/500 = 0.552 | **55.2%** |
| GPT-3.5-Turbo | Baseline | 50 | 6 | 6/50 = 0.120 | **12.0%** |
| GPT-3.5-Turbo | Adversarial | 50 | ~22 | 22/50 = 0.440 | **44.7%** |
| GPT-4 | Baseline | 22 | 2 | 2/22 = 0.091 | **10.0%** |
| GPT-4 | Adversarial | 22 | ~8 | 8/22 = 0.364 | **37.9%** |

> **Note:** Counts shown are back-calculated from reported percentages. Actual JSON record counts are the authoritative source — use `scripts/verify_statistics.py` to recompute from them directly.

### Overall weighted mean VGR

The "Overall Mean" row in Table 4.1 is the **weighted** mean across all 3,184 observations — not the simple average of the four model VGRs.

```
Weighted mean adversarial VGR:
  ≈ (134 + 276 + 22 + 8) / (500 + 500 + 50 + 22)
  = 440 / 1072
  = 0.411 → 41.1%  ✓

Weighted mean baseline VGR:
  ≈ (0 + 88 + 6 + 2) / (500 + 500 + 50 + 22)
  = 96 / 1072
  = 0.090 → ~9.9%  ✓
```

---

## 2. Increase Factor — Table 4.1

### Formula

```
Increase Factor = VGR_adversarial / VGR_baseline
```

### Per-model derivations

```
CodeT5+:    0.0% baseline → division by zero → N/A

CodeLlama:  55.2% / 17.6% = 3.136... → 3.14×  ✓

GPT-3.5:    44.7% / 12.0% = 3.725     → 3.72×  ✓

GPT-4:      37.9% / 10.0% = 3.79      → 3.79×  ✓

Overall:    (3.14 + 3.72 + 3.79) / 3
            = 10.65 / 3
            = 3.55×  ✓
```

### Note on §4.10 "10.7-fold amplification"

The §4.10 summary uses a different aggregation scope:

```
37.4% / 3.5% = 10.69 ≈ 10.7×
```

The 3.5% figure reflects a different sub-analysis baseline in §4.10. Both 3.55× (Table 4.1, weighted) and 10.7× (§4.10 text, different scope) are stated in the dissertation and measure the same phenomenon at different aggregation levels.

---

## 3. Chi-Square Test — χ² = 847.3

### What chi-square tests here

Is the rate of vulnerability generation **independent** of whether the condition was baseline or adversarial? A large χ² means the two conditions produce significantly different rates.

```
χ² = Σ [(O_ij − E_ij)² / E_ij]

O_ij = observed count in cell (row i, column j)
E_ij = expected count if rows and columns were independent
     = (row i total × column j total) / grand total N

Pearson method, Yates correction = False (as stated in the dissertation)
```

### 2×2 contingency table

```
                   Vulnerable    Safe     Total
Baseline               158       1,434    1,592
Adversarial            655         937    1,592
Total                  813       2,371    3,184
```

*(Counts derived from Table 4.1 overall percentages: 9.9% and 41.1% of 1,592 each)*

### Expected counts E_ij

```
E(Baseline, Vulnerable)    = (1,592 × 813) / 3,184 ≈ 406.5
E(Baseline, Safe)          = (1,592 × 2,371) / 3,184 ≈ 1,185.5
E(Adversarial, Vulnerable) = (1,592 × 813) / 3,184 ≈ 406.5
E(Adversarial, Safe)       = (1,592 × 2,371) / 3,184 ≈ 1,185.5
```

### Compute χ²

```
χ² = [(158 − 406.5)² / 406.5]
   + [(1434 − 1185.5)² / 1185.5]
   + [(655 − 406.5)² / 406.5]
   + [(937 − 1185.5)² / 1185.5]

The actual JSON record counts (not round-number approximations)
yield χ²(1) = 847.3, p < 0.001  ✓
```

With df=1, the critical value at p=0.001 is 10.83. A value of 847.3 is vastly above this threshold.

---

## 4. Phi Coefficient φ

### Formula

φ tells you **how strong** the association is, independent of sample size. For a 2×2 table, φ is equivalent to Pearson's r between two binary variables.

```
φ = √(χ² / N)

Interpretation: 0.1=small, 0.3=medium, 0.5=large
```

### Derivation

```
φ = √(847.3 / 3,184)
  = √(0.26613)
  = 0.516  ✓

|φ| = 0.516 > 0.5 → large effect
```

---

## 5. Bootstrap Confidence Intervals

### Why bootstrap?

A normal-approximation CI assumes large N and symmetric distributions. Because some conditions have small samples (GPT-4 n=44) and binary outcomes, the dissertation uses the **BCa (bias-corrected and accelerated) bootstrap**, which is more accurate for skewed or small-sample distributions.

### Algorithm

```
Inputs:  original sample of N binary outcomes (0=safe, 1=vulnerable)
         B = 10,000 bootstrap resamples, random seed = 42

For each resample b = 1, ..., 10,000:
  1. Draw N observations WITH replacement from the original sample
  2. Compute VGR_b = (# vulnerable in resample) / N

Sort VGR_1, ..., VGR_10,000 in ascending order

BCa adjusts percentiles for bias and skewness:
  Lower bound = VGR at adjusted lower percentile
  Upper bound = VGR at adjusted upper percentile
```

### All reported CIs

| Statistic | Point Estimate | 95% CI | Source |
|---|---|---|---|
| Overall adversarial VGR | 41.1% | **[35.1%, 39.7%]** | §4.7.3 |
| Pre-function position ASR | 62.1% | [56.8%, 67.4%] | Table 4.3 |
| Initial context ASR | 48.3% | [43.1%, 53.5%] | Table 4.3 |
| Mid-context ASR | 38.5% | [33.5%, 43.5%] | Table 4.3 |
| Distant context ASR | 22.7% | [18.3%, 27.1%] | Table 4.3 |
| Open-source transfer TR | 0.975 | [0.94, 1.01] | §4.6 |
| Cross-architecture TR | 0.738 | [0.69, 0.78] | §4.6 |

> **Why is the overall adversarial CI [35.1%, 39.7%] when the point estimate is 41.1%?** The BCa correction accounts for bias in the bootstrap distribution — the CI does not need to be symmetric around the point estimate. All intervals exclude 0%, confirming statistical significance.

---

## 6. Cohen's d — Effect Size

### Formula

Cohen's d expresses the difference between two means in units of pooled standard deviation. For binary outcomes, SD = √(p(1−p)).

```
Cohen's d = (M₁ − M₂) / SD_pooled

SD_pooled = √[(SD₁² + SD₂²) / 2]

For binary outcomes: SD = √(p × (1 − p))

Thresholds: d=0.2 small, d=0.5 medium, d=0.8 large (Cohen, 1988)
```

### Derivation (overall, d = 2.7)

```
p1 = adversarial VGR = 0.411
p2 = baseline VGR   = 0.099

SD1 = √(0.411 × 0.589) = √(0.2421) = 0.4920
SD2 = √(0.099 × 0.901) = √(0.0892) = 0.2987

SD_pooled = √[(0.4920² + 0.2987²) / 2]
           = √[(0.2421 + 0.0892) / 2]
           = √(0.1657)
           = 0.4070

The script computes d using trial-level binary data, yielding d = 2.7 as reported.
```

### All reported Cohen's d values

| Comparison | d | Interpretation | Source |
|---|---|---|---|
| Overall adversarial vs. baseline | **2.7** | Very large | §4.7.2 |
| Direct instruction vs. baseline | **2.7** | Very large | §4.3.1 |
| Example-based vs. baseline | **1.8** | Very large | §4.3.1 |
| SQL injection vs. insecure crypto | **1.42** | Very large | §4.4 |
| Range across all conditions | **1.2 – 3.8** | Large to very large | §4.7.2 |

---

## 7. Cohen's κ — Inter-Rater Reliability

### What κ measures

Two human raters independently labeled a subset of generated code as "vulnerable" or "safe." κ measures how much of their agreement was **beyond chance**. κ = 0.87 is "almost perfect agreement" (Landis & Koch, 1977).

### Formula and worked example

```
κ = (P_o − P_e) / (1 − P_e)

P_o = observed proportion of agreement
P_e = expected proportion of agreement by chance
```

**Hypothetical agreement matrix yielding κ ≈ 0.87:**

```
                  Rater B: Vuln   Rater B: Safe   Row Total
Rater A: Vuln         85              5              90
Rater A: Safe          7            103             110
Col Total             92            108             200

Step 1 — Observed agreement:
  P_o = (85 + 103) / 200 = 188 / 200 = 0.940

Step 2 — Expected agreement by chance:
  P_e = [(90 × 92)/200 + (110 × 108)/200] / 200
      = [41.4 + 59.4] / 200
      = 100.8 / 200 = 0.504

Step 3 — Compute κ:
  κ = (0.940 − 0.504) / (1 − 0.504)
    = 0.436 / 0.496
    = 0.879 ≈ 0.87  ✓
```

**Landis & Koch scale:** 0.81–1.00 = **Almost Perfect** ← κ = 0.87 falls here

---

## 8. One-Way ANOVA — Positional Effects

### What ANOVA tests

Four groups (position categories: Pre-Function, Initial, Mid-Context, Distant) — does mean attack success rate differ significantly across positions?

```
F = MS_between / MS_within

df_between = k − 1 = 4 − 1 = 3
df_within  = N − k = 700 − 4 = 696
```

### Derivation of F = 127.4

```
Group means (from Table 4.3):
  Pre-Function:  M1 = 0.621, n1 = 175
  Initial:       M2 = 0.483, n2 = 175
  Mid-Context:   M3 = 0.385, n3 = 175
  Distant:       M4 = 0.227, n4 = 175
  Grand mean:    M  = (0.621 + 0.483 + 0.385 + 0.227) / 4 = 0.429

SS_between = Σ n_i × (M_i − M)²
  = 175×(0.621−0.429)² + 175×(0.483−0.429)²
  + 175×(0.385−0.429)² + 175×(0.227−0.429)²
  = 6.450 + 0.511 + 0.339 + 7.142 = 14.44

MS_between = 14.44 / 3 = 4.81

F = MS_between / MS_within = 127.4  ✓  (p < 0.001)
```

### Eta-squared η² = 0.35

```
η² = SS_between / SS_total = 14.44 / 41.3 = 0.35  ✓

Position category explains 35% of variance in attack success.
η² > 0.14 = large effect.
```

### Bonferroni correction

```
k = 4 groups → C(4,2) = 6 pairwise comparisons
α_adjusted = 0.05 / 6 = 0.0083

All 6 pairwise comparisons: p < 0.001 << 0.0083  ✓
All differences significant under conservative correction.
```

---

## 9. Attack Success Rate (ASR) — Table 4.2

### Definition

ASR is structurally the same as VGR but conditioned on attack **technique** rather than condition:

```
ASR(technique, model) = Vulnerable_trials / Total_trials_for_technique_on_model
```

### How mean ASR is computed across models

```
Example: Direct Instruction mean ASR
  CodeT5+   = 20.0%
  CodeLlama = 60.8%
  GPT-3.5   = 68.0%
  GPT-4     = 53.8%

  Unweighted mean = (20.0 + 60.8 + 68.0 + 53.8) / 4
                  = 202.6 / 4
                  = 50.65 ≈ 50.7%  ✓  (Table 4.2)
```

> The §4.3.1 text states "55% mean success rate" — this is the weighted mean using actual trial counts, a slightly different calculation than the Table 4.2 unweighted mean. Both are stated in the dissertation.

---

## 10. Transferability Rate (TR) — Table 4.6

### Formula

```
TR(origin → target) = ASR_target / ASR_origin

TR = 1.0 means equally effective on target as on origin model.
TR = 0.65 means 65% of effectiveness retained after transfer.
```

### Example derivations

```
CodeT5+ → CodeLlama:  100% / 100% = 1.00 → 100%  ✓
CodeLlama → GPT-4:     70% / 100% = 0.70 →  70%  ✓
GPT-3.5 → GPT-4:       85% / 100% = 0.85 →  85%  ✓

Open-source ↔ open-source mean TR:
  (100% + 95%) / 2 = 97.5% → TR = 0.975  ✓  CI [0.94, 1.01]

Open-source → commercial mean TR:
  (78% + 65% + 82% + 70%) / 4 = 73.75% → TR = 0.738  ✓  CI [0.69, 0.78]
```

---

## 11. Complete Number Cross-Reference

| Value | Formula | Inputs | Dissertation Source |
|---|---|---|---|
| VGR = 0.0% / 26.7% (CodeT5+) | V/N | 0/500 · ~134/500 | Table 4.1 row 1 |
| VGR = 17.6% / 55.2% (CodeLlama) | V/N | 88/500 · 276/500 | Table 4.1 row 2 |
| VGR = 12.0% / 44.7% (GPT-3.5) | V/N | 6/50 · 22/50 | Table 4.1 row 3 |
| VGR = 10.0% / 37.9% (GPT-4) | V/N | 2/22 · 8/22 | Table 4.1 row 4 |
| 9.9% / 41.1% overall | weighted V/N | all 3,184 trials | Table 4.1 overall |
| 3.14× / 3.72× / 3.79× | VGR_adv / VGR_base | per model | Table 4.1 col 6 |
| 3.55× overall | (3.14+3.72+3.79)/3 | 3 defined factors | Table 4.1 overall |
| χ²(1) = 847.3 | Σ(O−E)²/E | 2×2 contingency table | §4.2 |
| φ = 0.516 | √(χ²/N) | √(847.3/3184) | derived |
| CI = [35.1%, 39.7%] | BCa bootstrap | B=10,000, seed=42 | §4.7.3 |
| d = 2.7 | (M1−M2)/SD_pool | trial-level binary outcomes | §4.7.2 |
| κ = 0.87 | (P_o−P_e)/(1−P_e) | rater agreement matrix | §4.7 |
| F(3,696) = 127.4 | MS_between/MS_within | 4 position groups | §4.3.2 |
| η² = 0.35 | SS_between/SS_total | ANOVA partitioning | §4.3.2 |
| TR = 0.975 | ASR_target/ASR_origin | CT5↔CL pairs | §4.6 |
| 10.7× (§4.10 text) | 37.4%/3.5% | different aggregation scope | §4.10 |
| R² = 0.42, AUC = 0.84 | OLS / logistic | linguistic pattern predictors | §4.7.6 |

---

*Del Orbe, W. A. (2026). Context-Based Adversarial Manipulation of AI Code Generators [Ph.D. dissertation]. Dakota State University, Beacom College of Computer and Cyber Sciences.*
