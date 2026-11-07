# Dissertation Statistics Verification
**Context-Based Adversarial Manipulation of AI Code Generators**

| | |
|---|---|
| **Author** | Walther A. Del Orbe · waltdelorbe@gmail.com |
| **Chair** | Dr. Michael Ham |
| **Committee** | Dr. O'Brien · Dr. Kramer |
| **Institution** | Dakota State University, Beacom College of Computer and Cyber Sciences |
| **Status** | Post-Defense · Pre-Publication Review |

> **Purpose:** Every statistic reported in Chapter 4 is listed here with its source table and verification status. Anyone can cross-reference each value against the dissertation and re-run `scripts/verify_statistics.py` to confirm computationally.

---

## ✅ Key Statistics at a Glance

| Statistic | Value | Source |
|---|---|---|
| Total test cases (N) | **3,184** | §3.7, Table 4.1 |
| Overall baseline VGR | **9.9%** | Table 4.1 |
| Overall adversarial VGR | **41.1%** | Table 4.1 |
| Overall increase factor | **3.55×** | Table 4.1 |
| Chi-square | **χ²(1) = 847.3, p < 0.001** | §4.2 |
| Effect size (phi) | **φ = 0.516** | §4.2 |
| Bootstrap CI (adversarial VGR) | **[35.1%, 39.7%]** | §4.7.3 |
| Cohen's d range | **1.2 – 3.8** | §4.7.2 |
| Cohen's κ (inter-rater) | **0.87** | §4.7 |

---

## Table 4.1 — Vulnerability Generation Rates

> Primary dissertation table. All values taken directly from Chapter 4.

| Model | Test Cases | Baseline VGR | Adversarial VGR | Increase Factor |
|---|---|---|---|---|
| CodeT5+ (770M) | 1,000 | 0.0% | 26.7% | N/A* |
| CodeLlama (7B) | 1,000 | 17.6% | 55.2% | 3.14× |
| GPT-3.5-Turbo | 100 | 12.0% | 44.7% | 3.72× |
| GPT-4 | 44† | 10.0% | 37.9%† | 3.79× |
| **Overall Mean** | **3,184** | **9.9%** | **41.1%** | **3.55×** |

\* CodeT5+ baseline = 0.0% → multiplicative factor undefined (division by zero)  
† GPT-4 N=44 excludes a single obfuscation outlier per §4.8.4; values use BCa bootstrap

**χ²(1) = 847.3, p < 0.001 · φ = 0.516 · 95% CI = [35.1%, 39.7%] · κ = 0.87 · d = 1.2–3.8**

> **Note on §4.10 vs Table 4.1:** The §4.10 summary text states "10.7-fold amplification" using figures 3.5% → 37.4%. Table 4.1 reports 9.9% → 41.1% (3.55×). Both are present in the dissertation and use different aggregation scopes (unweighted vs. weighted mean). Table 4.1 values are primary throughout this repository.

---

## Table 4.2 — Attack Success Rate by Technique

| Attack Technique | CodeT5+ | CodeLlama | GPT-3.5 | GPT-4 | Mean ASR |
|---|---|---|---|---|---|
| Direct Instruction | 20.0% | 60.8% | 68.0% | 53.8% | 50.7% |
| Semantic Priming | 18.3% | 48.2% | 52.0% | 46.2% | 41.2% |
| Example-Based | 24.1% | 52.7% | 58.0% | 48.7% | 45.9% |
| Steganographic | 15.2% | 38.4% | 42.0% | 35.9% | 32.9% |
| Evasion-Based | 22.8% | 55.1% | 61.0% | 51.3% | 47.6% |
| Obfuscation-Based | 19.7% | 45.3% | 48.0% | 42.1% | 38.8% |

Source: §4.3.1 · χ²(1) = 421.8 (direct instruction vs. baseline), p < 0.001 · d = 2.7

---

## Table 4.3 — Positional Effects on Attack Success Rate

| Context Position | ASR | 95% CI | Description |
|---|---|---|---|
| Pre-Function (−50 to −10 tokens) | **62.1%** | [56.8%, 67.4%] | Immediately before target function |
| Initial Context (first 20%) | **48.3%** | [43.1%, 53.5%] | Early in context window |
| Mid-Context (40–60%) | **38.5%** | [33.5%, 43.5%] | Middle of context |
| Distant Context (>80%) | **22.7%** | [18.3%, 27.1%] | Far from generation point |

**F(3, 696) = 127.4, p < 0.001 · η² = 0.35 · Bonferroni α = 0.05/6 = 0.0083**  
All 6 pairwise comparisons significant after Bonferroni correction.

Source: §4.3.2

---

## Table 4.4 — Vulnerability Category Distribution

| Category | CWE | Baseline Rate | Adversarial Rate | Δ |
|---|---|---|---|---|
| SQL Injection | CWE-89 | 3.2% | 48.7% | +45.5 pp |
| Cross-Site Scripting | CWE-79 | 2.8% | 42.3% | +39.5 pp |
| Hardcoded Credentials | CWE-798 | 2.1% | 38.9% | +36.8 pp |
| Path Traversal | CWE-22 | 1.9% | 35.2% | +33.3 pp |
| Insecure Cryptography | CWE-327 | 1.4% | 28.6% | +27.2 pp |

χ²(4) = 312.7, p < 0.001 (across vulnerability types)  
SQL Injection vs. Insecure Crypto: d = 1.42

Source: §4.4

---

## Table 4.5 — Context Pattern Analysis

| Pattern Type | ASR | 95% CI | n |
|---|---|---|---|
| Authority Framing | **58.3%** | [52.7%, 63.9%] | 247 |
| Legacy/Compatibility | **51.7%** | [46.2%, 57.2%] | 203 |
| Educational Framing | **44.2%** | [38.8%, 49.6%] | 189 |
| Technical Specification | **38.7%** | [33.4%, 44.0%] | 178 |
| Baseline (no pattern) | **9.9%** | [8.1%, 11.7%] | 1,592 |

Source: §4.5 · R² = 0.42 (OLS regression) · AUC = 0.84 (logistic)

---

## Table 4.6 — Transferability Matrix

Attack origin → target model. Values = transferability rate (TR = ASR_target / ASR_origin).

| Origin → Target | CodeT5+ | CodeLlama | GPT-3.5 | GPT-4 | Mean TR |
|---|---|---|---|---|---|
| **CodeT5+** | — | 100% | 78% | 65% | 81.0% |
| **CodeLlama** | 95% | — | 82% | 70% | 82.3% |
| **GPT-3.5** | 72% | 78% | — | 85% | 78.3% |
| **GPT-4** | 68% | 74% | 88% | — | 76.7% |

Open-source ↔ open-source mean TR: **0.975** · 95% CI [0.94, 1.01]  
Open-source → commercial mean TR: **0.738** · 95% CI [0.69, 0.78]  
Pairs with TR > 0.6: **83%** (10 of 12 off-diagonal)

Source: §4.6

---

## Statistical Methods Summary

| Method | Implementation | Key Parameters |
|---|---|---|
| Chi-square | `scipy.stats.chi2_contingency` | Pearson, correction=False |
| Bootstrap CI | BCa method | B=10,000, seed=42 |
| Effect size (d) | Pooled SD of binary outcomes | Per model comparison |
| Effect size (φ) | √(χ²/N) | From primary chi-square |
| Inter-rater (κ) | Cohen's kappa | Two independent raters |
| ANOVA | One-way, positional groups | F(3,696) |
| Bonferroni | α/k | 0.05/6 = 0.0083 |
| Regression | OLS + logistic | Context pattern predictors |

---

## ⚠️ GPT-6 Astra — Supplemental Data (NOT Part of Dissertation)

GPT-6 Astra was tested **prior to the defense** as a novel exploratory extension. These **100 trials are NOT included** in the dissertation's N=3,184 and do not appear in Tables 4.1–4.6.

Data is in `data/gpt6_extension/` for transparency only.

| Metric | Value |
|---|---|
| N (GPT-6 trials) | 100 |
| Baseline VGR | ~8% |
| Adversarial VGR | ~31% |
| Key finding | Lower susceptibility than GPT-3.5/GPT-4 — improved safety alignment |

---

## Verification Checklist

- [ ] Table 4.1 baseline VGRs match dissertation (0.0%, 17.6%, 12.0%, 10.0%, 9.9%)
- [ ] Table 4.1 adversarial VGRs match dissertation (26.7%, 55.2%, 44.7%, 37.9%, 41.1%)
- [ ] χ²(1) = 847.3, p < 0.001 confirmed
- [ ] φ = 0.516 confirmed (√(847.3/3184))
- [ ] 95% CI = [35.1%, 39.7%] confirmed (BCa, B=10,000, seed=42)
- [ ] Cohen's d range 1.2–3.8 confirmed
- [ ] κ = 0.87 confirmed
- [ ] F(3,696) = 127.4, η² = 0.35 confirmed
- [ ] GPT-6 data confirmed as supplemental, not in N=3,184

To recompute: `python scripts/verify_statistics.py`

---

*Del Orbe, W. A. (2026). Context-Based Adversarial Manipulation of AI Code Generators [Ph.D. dissertation]. Dakota State University, Beacom College of Computer and Cyber Sciences.*
