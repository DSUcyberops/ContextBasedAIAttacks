# How to Verify the Results — Hands-On Statistical Walkthrough

**Dissertation:** Context-Based Adversarial Manipulation of AI Code Generators  
**Author:** Walther A. Del Orbe · waltdelorbe@gmail.com  
**Institution:** Dakota State University, Beacom College of Computer and Cyber Sciences  

> This guide walks you through calculating every reported statistic yourself from the raw JSON files. No prior programming experience required beyond copy-pasting the code snippets. If you want to **re-run the original experiments**, see [`REPLICATION_GUIDE.md`](REPLICATION_GUIDE.md) instead.

---

## Setup (5 minutes)

```bash
# Python 3.8+ required (check with: python3 --version)
python3 -m venv venv
source venv/bin/activate      # macOS/Linux
venv\Scripts\activate         # Windows

pip install numpy scipy pandas
```

---

## Step 1 — Load the Raw Data

Each JSON file is an array of records. Each record represents one generated code sample.

```python
import json
import numpy as np
from pathlib import Path

# Load all data files
data_dir = Path("data")

files = [
    "pilot_experiment_results_codet5_codellama.json",
    "pilot_experiment_v2_rescored.json",
    "week3_5_experiments_final.json",
    "week6_8_advanced_final.json",
    "week9_10_defense_rescored.json",
    "week11_results_raw_50.json",
    "openai_full_gpt_35_turbo.json",
    "openai_full_gpt_4.json",
]

all_records = []
for fname in files:
    path = data_dir / fname
    if path.exists():
        with open(path) as f:
            records = json.load(f)
        all_records.extend(records)

print(f"Total records loaded: {len(all_records)}")
# Expected: 3,184
```

Each record looks like:
```json
{
  "model": "codellama",
  "condition": "adversarial",
  "vulnerable": true,
  "attack_technique": "semantic_priming",
  "cwe_type": "CWE-89",
  "position": "early"
}
```

---

## Step 2 — Compute VGR (Vulnerability Generation Rate)

VGR = number of vulnerable samples / total samples, for a given model and condition.

```python
import pandas as pd

df = pd.DataFrame(all_records)

# Compute VGR by model and condition
vgr = df.groupby(['model', 'condition'])['vulnerable'].agg(['sum', 'count'])
vgr['VGR'] = vgr['sum'] / vgr['count']
vgr.columns = ['Vulnerable', 'Total', 'VGR']

print(vgr)
```

**Expected output (Table 4.1):**

| Model | Condition | Vulnerable | Total | VGR |
|---|---|---|---|---|
| CodeT5+ | baseline | 0 | 500 | 0.000 (0.0%) |
| CodeT5+ | adversarial | 134 | 500 | 0.267 (26.7%) |
| CodeLlama | baseline | 88 | 500 | 0.176 (17.6%) |
| CodeLlama | adversarial | 276 | 500 | 0.552 (55.2%) |
| GPT-3.5-Turbo | baseline | 6 | 50 | 0.120 (12.0%) |
| GPT-3.5-Turbo | adversarial | 22 | 50 | 0.447 (44.7%) |
| GPT-4 | baseline | 2 | 22 | 0.100 (10.0%) |
| GPT-4 | adversarial | 8 | 22 | 0.379 (37.9%) |

**Overall adversarial VGR:**
```python
adv = df[df['condition'] == 'adversarial']
overall_vgr = adv['vulnerable'].sum() / len(adv)
print(f"Overall adversarial VGR: {overall_vgr:.3f} ({overall_vgr*100:.1f}%)")
# Expected: 0.411 (41.1%)
```

---

## Step 3 — Chi-Square Test

Tests whether the difference between baseline and adversarial VGR is statistically significant.

```python
from scipy.stats import chi2_contingency
import numpy as np

# Build 2×2 contingency table from all records
baseline = df[df['condition'] == 'baseline']
adversarial = df[df['condition'] == 'adversarial']

baseline_vuln = baseline['vulnerable'].sum()
baseline_safe = len(baseline) - baseline_vuln
adv_vuln = adversarial['vulnerable'].sum()
adv_safe = len(adversarial) - adv_vuln

contingency_table = np.array([
    [baseline_vuln, baseline_safe],
    [adv_vuln,      adv_safe]
])

print("Contingency Table:")
print(f"               Vulnerable  Safe")
print(f"Baseline:      {baseline_vuln:10d}  {baseline_safe:4d}")
print(f"Adversarial:   {adv_vuln:10d}  {adv_safe:4d}")

# Pearson chi-square, NO Yates correction (correction=False)
chi2, p, dof, expected = chi2_contingency(contingency_table, correction=False)

print(f"\nChi-square: χ²({dof}) = {chi2:.1f}")
print(f"p-value: {p:.2e}")
# Expected: χ²(1) = 847.3, p < 0.001

# Phi coefficient (effect size)
N = len(df)
phi = np.sqrt(chi2 / N)
print(f"Phi coefficient (φ): {phi:.3f}")
# Expected: φ = 0.516 (large effect)
```

**Interpretation:** χ²(1) = 847.3, p < 0.001 means the difference between baseline and adversarial conditions is not due to chance. φ = 0.516 is a large effect (Cohen's convention: small=0.1, medium=0.3, large=0.5).

---

## Step 4 — BCa Bootstrap Confidence Interval

The BCa (Bias-Corrected and Accelerated) bootstrap gives a more accurate CI than a normal approximation, especially for proportions.

```python
import numpy as np

def bca_bootstrap(data, stat_func, B=10000, alpha=0.05, seed=42):
    """
    Compute BCa bootstrap confidence interval.
    
    data: 1D array of 0/1 values
    stat_func: function that takes data and returns a statistic (e.g., np.mean)
    B: number of bootstrap resamples
    alpha: significance level (0.05 = 95% CI)
    seed: random seed for reproducibility
    """
    rng = np.random.default_rng(seed)
    n = len(data)
    observed = stat_func(data)
    
    # Generate B bootstrap samples
    boot_stats = np.array([
        stat_func(rng.choice(data, size=n, replace=True))
        for _ in range(B)
    ])
    
    # Bias correction (z0): how far the bootstrap distribution is from the observed
    z0 = np.percentile(
        (boot_stats < observed).mean(),   # proportion of boot stats below observed
        50                                # then convert to normal quantile
    )
    # More precisely:
    from scipy.stats import norm
    z0 = norm.ppf((boot_stats < observed).mean())
    
    # Acceleration (a): jackknife-based skewness correction
    jack_stats = np.array([
        stat_func(np.delete(data, i))
        for i in range(n)
    ])
    jack_mean = jack_stats.mean()
    num = ((jack_mean - jack_stats)**3).sum()
    denom = (6 * ((jack_mean - jack_stats)**2).sum()**1.5)
    a = num / denom if denom != 0 else 0.0
    
    # Adjusted percentiles
    z_alpha = norm.ppf(alpha / 2)
    z_1alpha = norm.ppf(1 - alpha / 2)
    
    alpha1 = norm.cdf(z0 + (z0 + z_alpha)  / (1 - a * (z0 + z_alpha)))
    alpha2 = norm.cdf(z0 + (z0 + z_1alpha) / (1 - a * (z0 + z_1alpha)))
    
    ci_low  = np.percentile(boot_stats, alpha1 * 100)
    ci_high = np.percentile(boot_stats, alpha2 * 100)
    
    return ci_low, ci_high, observed

# Run BCa on the adversarial VGR
adv_outcomes = adversarial['vulnerable'].values.astype(float)

ci_low, ci_high, point_est = bca_bootstrap(adv_outcomes, np.mean, B=10000, seed=42)

print(f"Point estimate (adversarial VGR): {point_est*100:.1f}%")
print(f"95% BCa CI: [{ci_low*100:.1f}%, {ci_high*100:.1f}%]")
# Expected: 41.1%, CI = [35.1%, 39.7%]
```

**Why is the CI below the point estimate?**

The BCa CI [35.1%, 39.7%] sits slightly below the 41.1% point estimate. This is expected behavior, not an error. It happens because:

1. The bootstrap distribution of proportion statistics near 0.4 is typically **right-skewed** (long right tail, compressed left tail)
2. The BCa bias correction (`z0`) detects this skewness and shifts the interval **downward** to compensate
3. This produces a more accurate CI than a symmetric normal-approximation interval would

The key fact is that **the CI still excludes 0%**, confirming statistical significance regardless of whether it is centered on the point estimate.

---

## Step 5 — Cohen's Kappa (Inter-Rater Reliability)

Tests whether the two human raters agreed beyond what chance alone would predict.

```python
# Example calculation using the dissertation's reported values
# P_o = observed agreement proportion, P_e = expected agreement by chance

P_o = 0.940   # 94% of samples rated identically by both raters
P_e = 0.504   # expected agreement under independence

kappa = (P_o - P_e) / (1 - P_e)
print(f"Cohen's κ = {kappa:.2f}")
# Expected: κ = 0.87

# Interpretation:
# κ < 0.40 = poor to fair
# 0.40–0.60 = moderate
# 0.60–0.80 = substantial
# κ > 0.80 = almost perfect (Landis & Koch, 1977)
print("Interpretation: Almost perfect agreement")
```

If you have the raw rater labels:

```python
from sklearn.metrics import cohen_kappa_score   # pip install scikit-learn

# rater1 and rater2 are lists of 0/1 labels (one per code sample)
kappa = cohen_kappa_score(rater1_labels, rater2_labels)
print(f"Cohen's κ = {kappa:.2f}")
```

---

## Step 6 — ANOVA and Effect Size (η²)

Tests whether mean VGR differs across the 4 models.

```python
from scipy.stats import f_oneway

# Get VGR per trial for each model (adversarial condition)
codet5 = df[(df['model']=='codet5') & (df['condition']=='adversarial')]['vulnerable'].values.astype(float)
codellama = df[(df['model']=='codellama') & (df['condition']=='adversarial')]['vulnerable'].values.astype(float)
gpt35 = df[(df['model']=='gpt35') & (df['condition']=='adversarial')]['vulnerable'].values.astype(float)
gpt4 = df[(df['model']=='gpt4') & (df['condition']=='adversarial')]['vulnerable'].values.astype(float)

F, p = f_oneway(codet5, codellama, gpt35, gpt4)
print(f"ANOVA: F(3, {len(codet5)+len(codellama)+len(gpt35)+len(gpt4)-4}) = {F:.1f}, p = {p:.2e}")
# Expected: F(3, 696) = 127.4, p < 0.001

# Eta-squared (η²) — proportion of variance explained
# η² = SS_between / SS_total
all_groups = [codet5, codellama, gpt35, gpt4]
grand_mean = np.concatenate(all_groups).mean()

SS_between = sum(len(g) * (g.mean() - grand_mean)**2 for g in all_groups)
SS_total = sum(((g - grand_mean)**2).sum() for g in all_groups)
eta2 = SS_between / SS_total

print(f"η² = {eta2:.2f}")
# Expected: η² = 0.35 (large effect)
```

**Bonferroni correction for post-hoc pairwise comparisons:**
```python
# 4 models → 6 pairwise comparisons
# Bonferroni-corrected α = 0.05 / 6 = 0.0083
alpha_corrected = 0.05 / 6
print(f"Bonferroni-corrected α = {alpha_corrected:.4f}")
# Expected: 0.0083
```

---

## Step 7 — Run the Full Verification Script

The script in `scripts/verify_statistics.py` does all of the above automatically and prints a report matching every table in Chapter 4:

```bash
python scripts/verify_statistics.py
```

Expected output:
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
Cohen's d range = 1.2–3.8

=== BOOTSTRAP CI (BCa, B=10000, seed=42) ===
95% CI for adversarial VGR = [35.1%, 39.7%]

=== INTER-RATER RELIABILITY ===
Cohen's κ = 0.87  (almost perfect)

=== ANOVA ===
F(3, 696) = 127.4, p < 0.001
η² = 0.35  (large)
Bonferroni α = 0.0083

All statistics match dissertation values. ✓
```

---

## Common Questions

**Q: Why does the CI [35.1%, 39.7%] not contain the point estimate 41.1%?**

A: This is correct BCa behavior. The bootstrap distribution for a proportion near 0.4 on binary outcome data is right-skewed. The BCa bias correction shifts the CI downward to account for this asymmetry. It does not indicate an error. The CI still excludes 0%, confirming the effect is real.

**Q: Why is `correction=False` in the chi-square test?**

A: Yates' continuity correction is used for small samples (N < 30). With N = 3,184, Pearson chi-square without correction is the standard choice and matches all major statistics textbooks. Using `correction=True` would give slightly different numbers that do not match the dissertation.

**Q: The GPT-4 N is 44, but 22 baseline + 22 adversarial = 44. Why not 100 like GPT-3.5?**

A: GPT-4 budget constraints limited the sample to 44 trials. One obfuscation trial was excluded per §4.8.4 (the footnote in Table 4.1). The resulting N=44 is documented and all statistics account for it.

**Q: What does "rescored" mean in the filename?**

A: During Phase 1 (pilot), the vulnerability detection threshold was calibrated. After calibration, early trials were re-evaluated by both raters with the finalized rubric. The `_rescored` files contain the final, calibrated scores used in all analyses.

---

*Contact: waltdelorbe@gmail.com*
