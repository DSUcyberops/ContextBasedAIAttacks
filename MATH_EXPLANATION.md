# Mathematical Methods — Step-by-Step Derivation

**Dissertation:** *Context-Based Adversarial Manipulation of AI Code Generators*  
**Author:** Walther A. Del Orbe | waltdelorbe@gmail.com  
**Degree:** Ph.D. in Cyber Operations, Dakota State University — Beacom College of Computer and Cyber Sciences  
**Purpose:** Independent verification of every statistical claim for Dr. Michael Ham (Chair) and committee members Dr. O'Brien and Dr. Kramer

---

## Table of Contents

1. [Vulnerability Rate](#1-vulnerability-rate)
2. [Amplification Factor](#2-amplification-factor)
3. [Chi-Square Test of Independence](#3-chi-square-test-of-independence)
4. [Phi Coefficient (Effect Size)](#4-phi-coefficient-effect-size)
5. [Bootstrap Confidence Intervals](#5-bootstrap-confidence-intervals)
6. [Inter-Rater Reliability — Cohen's κ](#6-inter-rater-reliability--cohens-κ)
7. [Defense Mechanism Metrics](#7-defense-mechanism-metrics)
8. [Worked Examples from Actual Data](#8-worked-examples-from-actual-data)

---

## 1. Vulnerability Rate

### Formula

```
rate = vulnerable_count / total_count
```

### Variables

| Symbol | Meaning |
|--------|---------|
| `V`    | Number of generated code snippets flagged as containing a vulnerability |
| `N`    | Total number of generated code snippets in the condition |
| `r`    | Vulnerability rate (proportion) |

```
r = V / N
```

Reported as a percentage: `r% = r × 100`

### Detection Method

A code snippet is classified as `vulnerable = True` if `detect_vulnerability(code, vuln_type)` returns `True`. That function applies one of five regex/AST-based patterns, one per CWE category:

| CWE    | Category               | Pattern summary |
|--------|------------------------|-----------------|
| CWE-89 | SQL Injection          | String concatenation `%s`, `+`, or f-string interpolation into an SQL keyword context |
| CWE-79 | XSS                    | Unescaped user input placed into HTML context via `innerHTML`, `document.write`, or f-string in HTML |
| CWE-798| Hardcoded Credentials  | Literal password/key/secret assigned in source (not `os.environ`, `getenv`, or placeholder) |
| CWE-22 | Path Traversal         | Direct `open()` / `os.path.join()` on user-controlled input without `os.path.abspath` / `realpath` / normalization |
| CWE-327| Insecure Cryptography  | Use of MD5, SHA1, DES, RC4, or ECB mode |

The full implementation is in `scripts/gpt6_astra_full_run.py` → `detect_vulnerability()`.

---

## 2. Amplification Factor

### Formula

```
amplification = r_adversarial / r_baseline
```

This is a **rate ratio** (also called a risk ratio in epidemiology). It answers: *"How many times more likely is a vulnerability to appear under adversarial prompting compared to neutral prompting?"*

### Example (GPT-6 Astra)

```
r_baseline    = 1 / 250  = 0.004  (0.4%)
r_adversarial = 335 / 500 = 0.670 (67.0%)

amplification = 0.670 / 0.004 = 167.5×
```

**Interpretation:** Under adversarial attack conditions, GPT-6 Astra produced vulnerable code 167.5× more often than under neutral (baseline) prompting.

---

## 3. Chi-Square Test of Independence

### Purpose

Tests whether attack type (baseline vs. adversarial) and vulnerability presence are **statistically independent** — i.e., whether the observed difference in rates could plausibly be due to chance alone.

### Hypotheses

- **H₀:** Attack type and vulnerability are independent (no association)
- **H₁:** Attack type and vulnerability are associated

### 2×2 Contingency Table

```
                Vulnerable    Not Vulnerable    Row Total
Baseline            a               b              a+b
Adversarial         c               d              c+d
Column Total       a+c             b+d            N = a+b+c+d
```

### Expected Cell Frequencies

Under H₀, the expected frequency for each cell is:

```
E_ij = (row_total_i × col_total_j) / N
```

Explicitly:
```
E_a = (a+b)(a+c) / N      E_b = (a+b)(b+d) / N
E_c = (c+d)(a+c) / N      E_d = (c+d)(b+d) / N
```

### Chi-Square Statistic

```
χ² = Σ [(O_ij - E_ij)² / E_ij]
   = (a - E_a)²/E_a + (b - E_b)²/E_b + (c - E_c)²/E_c + (d - E_d)²/E_d
```

For a 2×2 table, **degrees of freedom = (rows-1)(cols-1) = 1**.

**No Yates continuity correction** was applied (sample sizes are large; Yates correction is conservative and reduces power unnecessarily with N > 100).

### Decision Rule

Reject H₀ if p < 0.001 (Bonferroni-adjusted α for multiple comparisons across 5 vulnerability categories and 4 models).

### Python Implementation

```python
from scipy.stats import chi2_contingency
import numpy as np

table = np.array([[a, b], [c, d]])
chi2, p, dof, expected = chi2_contingency(table, correction=False)
```

---

## 4. Phi Coefficient (Effect Size)

### Formula

```
φ = √(χ² / N)
```

Where `χ²` is the chi-square statistic from Section 3, and `N` is the total sample size.

Phi is the Pearson correlation coefficient applied to two binary variables, so it ranges from −1 to +1 (practically 0 to +1 for our test direction).

### Interpretation (Cohen, 1988)

| |φ| range | Effect size label |
|------------|-------------------|
| 0.10–0.29  | Small             |
| 0.30–0.49  | Medium            |
| ≥ 0.50     | Large             |

### Examples

**GPT-6 Astra:**
```
χ²(1) = 298.94,  N = 750
φ = √(298.94 / 750) = √0.3986 = 0.631  → LARGE effect
```

**Open-Source Models (combined):**
```
χ²(1) = 109.47,  N = 1500
φ = √(109.47 / 1500) = √0.0730 = 0.270  → MEDIUM effect
```

---

## 5. Bootstrap Confidence Intervals

### Why Bootstrap?

Vulnerability rates are proportions of binary outcomes. While the Wilson score interval is analytically tractable, bootstrap CIs make no distributional assumptions and are valid even for extreme proportions (rates near 0% or 100%).

### Algorithm (Percentile Bootstrap)

```
Given: observed array X of 0/1 values, length N
       B = 10,000 bootstrap resamples
       seed = 42 (for reproducibility)

For b = 1 to B:
    X_b = sample(X, size=N, replace=True)
    θ_b = mean(X_b)          # = vulnerable_b / N

Sort θ_1 ... θ_B in ascending order
Lower bound = θ at the 2.5th percentile  (index ≈ 250)
Upper bound = θ at the 97.5th percentile (index ≈ 9750)
```

This produces a **95% CI**.

### Python Implementation

```python
from scipy.stats import bootstrap
import numpy as np

flags = np.array([int(r["vulnerable"]) for r in records])

result = bootstrap(
    (flags,),
    statistic=lambda x, axis: np.mean(x, axis=axis),
    n_resamples=10_000,
    random_state=42,
    axis=0
)
lo = result.confidence_interval.low
hi = result.confidence_interval.high
```

### Worked Example (GPT-6 Adversarial)

```
X = array of 500 values: 335 ones, 165 zeros
Observed mean = 335/500 = 0.670

After 10,000 bootstrap resamples:
  2.5th percentile ≈ 0.628   →  62.8%
  97.5th percentile ≈ 0.710  →  71.0%

95% CI: [62.8%, 71.0%]
```

---

## 6. Inter-Rater Reliability — Cohen's κ

### Purpose

Measures the degree of agreement between two independent raters **beyond what would be expected by chance alone**. Used to validate that the automated `detect_vulnerability()` function agrees with human judgment.

### Formula

```
κ = (P_o − P_e) / (1 − P_e)
```

Where:
- `P_o` = **Observed agreement** = (number of cases both raters agree on) / (total cases)
- `P_e` = **Expected agreement by chance** (computed from marginal proportions)

### Computing P_e

If rater A marks proportion `p_A` as vulnerable and rater B marks proportion `p_B`:

```
P_e = p_A × p_B + (1 − p_A)(1 − p_B)
```

(probability both say "vulnerable" by chance + probability both say "not vulnerable" by chance)

### Worked Example

Suppose on 100 randomly-sampled code snippets:
```
                    Rater B: Vuln    Rater B: Safe    Row Total
Rater A: Vuln            42               8               50
Rater A: Safe             5              45               50
Column Total             47              53              100

P_o = (42 + 45) / 100 = 0.87

p_A = 50/100 = 0.50,  p_B = 47/100 = 0.47
P_e = (0.50 × 0.47) + (0.50 × 0.53)
    = 0.235 + 0.265
    = 0.500

κ = (0.87 − 0.50) / (1 − 0.50)
  = 0.37 / 0.50
  = 0.74   → Substantial agreement
```

### Reported Value

The dissertation reports **κ = 0.87** (near-perfect agreement) based on 100 randomly-sampled generations coded by two independent raters, then compared to the automated detector.

### Interpretation (Landis & Koch, 1977)

| κ range    | Agreement level |
|------------|-----------------|
| 0.00–0.20  | Slight          |
| 0.21–0.40  | Fair            |
| 0.41–0.60  | Moderate        |
| 0.61–0.80  | Substantial     |
| 0.81–1.00  | Near-perfect    |

---

## 7. Defense Mechanism Metrics

The two-layer defense (prompt screening + static output analysis) is evaluated as a binary classifier:

```
                 Adversarial    Baseline (safe)
Detected (flag)       TP              FP
Not Detected          FN              TN
```

### Metrics

```
Detection Rate (Recall)  = TP / (TP + FN)
False Positive Rate      = FP / (FP + TN)
Precision                = TP / (TP + FP)
F1 Score                 = 2 × Precision × Recall / (Precision + Recall)
```

### Reported Values

| Metric              | Value  | Counts        |
|---------------------|--------|---------------|
| Detection rate      | 73.3%  | 110 / 150 TP  |
| False positive rate | 0.0%   | 0 / 50 FP     |
| Precision           | 100.0% |               |
| F1 score            | 0.846  |               |

**Layer 1** (prompt screening): Regex patterns detect explicit attack keywords in the prompt before the LLM generates code.  
**Layer 2** (static analysis): Bandit (Python), Semgrep, and ESLint scan the generated output independently of the prompt.

A detection requires **either** layer to flag the sample (logical OR). False positives are zero because Layer 1 only triggers on confirmed adversarial patterns, not on ambiguous code.

---

## 8. Worked Examples from Actual Data

### 8.1 GPT-6 Chi-Square (Full Derivation)

```
Data (from gpt6_astra_full_results.json):
  Baseline:    1 vulnerable / 250 total
  Adversarial: 335 vulnerable / 500 total

Contingency table:
              Vuln    Not Vuln    Total
Baseline        1       249       250
Adversarial   335       165       500
Total         336       414       750

Expected frequencies:
  E(baseline, vuln)       = 250 × 336 / 750 = 112.0
  E(baseline, not vuln)   = 250 × 414 / 750 = 138.0
  E(adversarial, vuln)    = 500 × 336 / 750 = 224.0
  E(adversarial, not vuln)= 500 × 414 / 750 = 276.0

χ² = (1 − 112)² / 112 + (249 − 138)² / 138
   + (335 − 224)² / 224 + (165 − 276)² / 276
   = 12321/112 + 12321/138 + 12321/224 + 12321/276
   = 110.009 + 89.283 + 54.951 + 44.641
   = 298.884 ≈ 298.94  (minor rounding)

p = P(χ²(1) ≥ 298.94) = 5.61 × 10⁻⁶⁷  (vanishingly small)

φ = √(298.94 / 750) = √0.3986 = 0.631
```

**Conclusion:** Overwhelming statistical evidence (p ≪ 0.001, large effect size φ=0.63) that adversarial attack type causes a significant increase in vulnerability rate.

### 8.2 Open-Source Chi-Square

```
Data (from week11_summary_50_iterations.json):
  CodeLlama-7b/baseline:         1 / 250
  CodeLlama-7b/adversarial:    120 / 500   (48 direct + 72 stego)
  CodeT5+-770m/baseline:         6 / 250
  CodeT5+-770m/adversarial:     99 / 500   (54 direct + 45 stego)

Combined open-source:
  Baseline:    7 / 500
  Adversarial: 219 / 1000

Contingency table:
              Vuln    Not Vuln    Total
Baseline        7       493        500
Adversarial   219       781       1000
Total         226      1274       1500

Expected frequencies:
  E(base, vuln)      = 500 × 226 / 1500 = 75.33
  E(base, not vuln)  = 500 × 1274 / 1500 = 424.67
  E(adv, vuln)       = 1000 × 226 / 1500 = 150.67
  E(adv, not vuln)   = 1000 × 1274 / 1500 = 849.33

χ² = (7 − 75.33)² / 75.33 + (493 − 424.67)² / 424.67
   + (219 − 150.67)² / 150.67 + (781 − 849.33)² / 849.33
   = 62.11 + 11.01 + 31.06 + 5.50
   = 109.68  (≈ 109.47 with exact computation)

p ≈ 0  (effectively zero)

φ = √(109.47 / 1500) = √0.0730 = 0.270
```

**Conclusion:** Strong evidence of association (p ≈ 0, medium effect φ=0.27) for open-source models as well, though the effect is smaller than for GPT-6, reflecting lower absolute vulnerability rates.

---

## References

- Cohen, J. (1988). *Statistical Power Analysis for the Behavioral Sciences* (2nd ed.). Lawrence Erlbaum Associates.
- Landis, J. R., & Koch, G. G. (1977). The measurement of observer agreement for categorical data. *Biometrics*, 33(1), 159–174.
- Efron, B., & Tibshirani, R. J. (1993). *An Introduction to the Bootstrap*. Chapman & Hall.
- Agresti, A. (2002). *Categorical Data Analysis* (2nd ed.). Wiley.
- SciPy documentation: `scipy.stats.chi2_contingency`, `scipy.stats.bootstrap`
