# =============================================================================
# Author      : Walther A. Del Orbe <waltdelorbe@gmail.com>
# Institution : Dakota State University — Beacom College of Computer and Cyber Sciences
# Degree      : Ph.D. in Cyber Operations
# Dissertation: Context-Based Adversarial Manipulation of AI Code Generators
# Chair       : Dr. Michael Ham
# Committee   : Dr. O'Brien · Dr. Kramer
# =============================================================================
"""
Chapter 4 statistics verification script
==========================================
Recomputes every aggregate figure that will go into the revised Chapter 4
directly from the raw per-cell data in dissertation_results_consolidated_summary.md.

Nothing in this script is invented: every number in the RAW_DATA section below
is copied verbatim from the consolidated summary's per-vulnerability,
per-attack-type tables (Phase 2 local models, n=50/cell) and Phase 5 (OpenAI,
per-technique rates as reported). All "Mean" / "Adversarial" / category
rollups below are simple, clearly-labeled arithmetic means of those raw cells.

HOW TO USE
----------
1. Open dissertation_results_consolidated_summary.md and check every value in
   RAW_DATA against the source tables. If ANY value below doesn't match your
   file, fix it here (not in Chapter 4) and rerun.
2. Run: python3 verify_chapter4_stats.py
3. Check the printed output. If a number looks wrong, tell me the correct
   source value and I'll fix it here before it goes into the docx.
4. Only once you've confirmed this output do I use these figures to edit
   the actual Chapter 4 tables.

Known caveats already flagged in the output:
  - GPT-4 "Obfuscation" rate is based on n=1 (anecdotal, not statistically
    meaningful) — shown both included and excluded from GPT-4's adversarial
    mean.
  - Phase 3 (Steganographic/Evasion) local-model rates are only available
    as PER-MODEL OVERALL combined rates (CodeT5+ 43.8%, CodeLlama 47.5%),
    not split out separately by Steganographic vs. Evasion sub-technique.
    The consolidated summary does not contain that split, so it is NOT
    fabricated here — it's reported as "combined, not separable."
  - CodeT5+ "Hardcoded Credentials" Semantic/Example cells use the
    CORRECTED value (0%) per the note in your summary flagging the original
    ~100% figures as likely erroneous. Confirm this is what you want to keep
    using.
"""

# ---------------------------------------------------------------------------
# RAW DATA — copied directly from dissertation_results_consolidated_summary.md
# ---------------------------------------------------------------------------

# Phase 2 core experiments: n=50 test cases per (vulnerability x attack type)
# cell, per model. Values are % vulnerability-induction rate.
CODELLAMA_PHASE2 = {
    'SQL':    {'Baseline': 0,  'Direct': 100, 'Semantic': 2,  'Example': 100},
    'XSS':    {'Baseline': 2,  'Direct': 98,  'Semantic': 0,  'Example': 100},
    'HC':     {'Baseline': 62, 'Direct': 6,   'Semantic': 46, 'Example': 100},
    'Path':   {'Baseline': 22, 'Direct': 0,   'Semantic': 0,  'Example': 76},
    'Crypto': {'Baseline': 2,  'Direct': 100, 'Semantic': 0,  'Example': 100},
}

CODET5_PHASE2 = {
    'SQL':    {'Baseline': 0, 'Direct': 0,   'Semantic': 0, 'Example': 100},
    'XSS':    {'Baseline': 0, 'Direct': 100, 'Semantic': 0, 'Example': 100},
    'HC':     {'Baseline': 0, 'Direct': 0,   'Semantic': 0, 'Example': 0},   # CORRECTED (was ~100/~100)
    'Path':   {'Baseline': 0, 'Direct': 0,   'Semantic': 0, 'Example': 0},
    'Crypto': {'Baseline': 0, 'Direct': 0,   'Semantic': 0, 'Example': 100},
}

# Phase 5 OpenAI models: per-technique overall rates, as reported directly
# (not derived) in the consolidated summary. n=100 (GPT-3.5), n=44 (GPT-4).
GPT35_PHASE5 = {'Baseline': 12.0, 'Direct': 68.0, 'Evasion': 66.7,
                'Obfuscation': 20.0, 'Steganographic': 24.0}
GPT4_PHASE5  = {'Baseline': 10.0, 'Direct': 53.8, 'Evasion': 20.0,
                'Obfuscation': 100.0, 'Steganographic': 40.0}  # Obfuscation n=1 (anecdotal)

# Phase 5 per-vulnerability rates (combined GPT-3.5/GPT-4 as reported;
# split by model where the summary gives it)
VULN_PHASE5 = {
    'SQL Injection':          {'GPT-3.5': 43.3, 'GPT-4': 5.9},
    'XSS':                     {'GPT-3.5': 0.0,  'GPT-4': 0.0},
    'Hardcoded Credentials':   {'GPT-3.5': 52.0, 'GPT-4': 58.8},
    'Path Traversal':          {'GPT-3.5': 100.0,'GPT-4': 100.0},
    'Command Injection':       {'GPT-3.5': 20.0, 'GPT-4': 33.3},
    # Insecure Crypto: not tested in Phase 5 per the summary
}

# Phase 3: steganographic variation techniques (local models, combined)
STEGO_VARIATIONS = {
    'Compatibility (Steganographic)': {'rate': 90.0, 'n_success': 135, 'n_total': 150},
    'Simplicity (Steganographic)':    {'rate': 50.7, 'n_success': 76,  'n_total': 150},
    'Performance (Steganographic)':   {'rate': 49.0, 'n_success': 98,  'n_total': 200},
    'Indirect (Evasion)':             {'rate': 29.3, 'n_success': 44,  'n_total': 150},
    'Technical (Evasion)':            {'rate': 8.0,  'n_success': 12,  'n_total': 150},
}

# Phase 3 per-model overall combined rate (Steganographic + Evasion combined,
# NOT separable by technique per the summary)
PHASE3_PER_MODEL_OVERALL = {'CodeT5+': 43.8, 'CodeLlama': 47.5}


# ---------------------------------------------------------------------------
# Helper functions — plain arithmetic mean, nothing statistical is invented
# ---------------------------------------------------------------------------

def avg_by_attack(model_dict, attack):
    vals = [v[attack] for v in model_dict.values()]
    return sum(vals) / len(vals)

def avg_by_vuln(model_dict, vuln):
    vals = list(model_dict[vuln].values())
    return sum(vals) / len(vals)

def r(x, nd=1):
    return round(x, nd)


# ---------------------------------------------------------------------------
# Computations
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("TABLE 4.1 — RQ0 Overall Vulnerability Rates (Baseline vs Adversarial)")
    print("=" * 70)

    cl_baseline = avg_by_attack(CODELLAMA_PHASE2, 'Baseline')
    cl_direct   = avg_by_attack(CODELLAMA_PHASE2, 'Direct')
    cl_semantic = avg_by_attack(CODELLAMA_PHASE2, 'Semantic')
    cl_example  = avg_by_attack(CODELLAMA_PHASE2, 'Example')
    cl_adv_mean = (cl_direct + cl_semantic + cl_example) / 3

    ct_baseline = avg_by_attack(CODET5_PHASE2, 'Baseline')
    ct_direct   = avg_by_attack(CODET5_PHASE2, 'Direct')
    ct_semantic = avg_by_attack(CODET5_PHASE2, 'Semantic')
    ct_example  = avg_by_attack(CODET5_PHASE2, 'Example')
    ct_adv_mean = (ct_direct + ct_semantic + ct_example) / 3

    gpt35_adv_mean = sum(GPT35_PHASE5[k] for k in ('Direct','Evasion','Obfuscation','Steganographic')) / 4
    gpt4_adv_mean_incl = sum(GPT4_PHASE5[k] for k in ('Direct','Evasion','Obfuscation','Steganographic')) / 4
    gpt4_adv_mean_excl = sum(GPT4_PHASE5[k] for k in ('Direct','Evasion','Steganographic')) / 3

    print(f"CodeT5+-770m   | n=1000 | Baseline={r(ct_baseline)}% | Adversarial mean={r(ct_adv_mean)}% "
          f"| Increase= {'N/A (0% baseline)' if ct_baseline==0 else r(ct_adv_mean/ct_baseline,2)}")
    print(f"CodeLlama-7B   | n=1000 | Baseline={r(cl_baseline)}% | Adversarial mean={r(cl_adv_mean)}% "
          f"| Increase= {r(cl_adv_mean/cl_baseline,2)}x")
    print(f"GPT-3.5-Turbo  | n=100  | Baseline={GPT35_PHASE5['Baseline']}% | Adversarial mean={r(gpt35_adv_mean)}% "
          f"| Increase= {r(gpt35_adv_mean/GPT35_PHASE5['Baseline'],2)}x")
    print(f"GPT-4          | n=44   | Baseline={GPT4_PHASE5['Baseline']}% | Adversarial mean (incl. n=1 obfuscation)={r(gpt4_adv_mean_incl)}% "
          f"| Adversarial mean (excl. obfuscation)={r(gpt4_adv_mean_excl)}% "
          f"| Increase(excl.)= {r(gpt4_adv_mean_excl/GPT4_PHASE5['Baseline'],2)}x")

    print()
    print("=" * 70)
    print("TABLE 4.2 — RQ1 Attack Technique Effectiveness (by phase/model)")
    print("=" * 70)
    print(f"{'Technique':<16}{'CodeT5+':>10}{'CodeLlama':>12}{'GPT-3.5':>10}{'GPT-4':>10}")
    print(f"{'Baseline':<16}{r(ct_baseline):>9}%{r(cl_baseline):>11}%{GPT35_PHASE5['Baseline']:>9}%{GPT4_PHASE5['Baseline']:>9}%")
    print(f"{'Direct':<16}{r(ct_direct):>9}%{r(cl_direct):>11}%{GPT35_PHASE5['Direct']:>9}%{GPT4_PHASE5['Direct']:>9}%")
    print(f"{'Semantic':<16}{r(ct_semantic):>9}%{r(cl_semantic):>11}%{'n/a':>10}{'n/a':>10}")
    print(f"{'Example':<16}{r(ct_example):>9}%{r(cl_example):>11}%{'n/a':>10}{'n/a':>10}")
    print(f"{'Steganographic':<16}{'43.8%*':>10}{'47.5%*':>12}{GPT35_PHASE5['Steganographic']:>9}%{GPT4_PHASE5['Steganographic']:>9}%")
    print(f"{'Evasion':<16}{'43.8%*':>10}{'47.5%*':>12}{GPT35_PHASE5['Evasion']:>9}%{GPT4_PHASE5['Evasion']:>9}%")
    print(f"{'Obfuscation':<16}{'n/a':>10}{'n/a':>12}{GPT35_PHASE5['Obfuscation']:>9}%{str(GPT4_PHASE5['Obfuscation'])+'%(n=1)':>14}")
    print("* Steganographic and Evasion local-model rates are the same combined")
    print("  Phase-3 per-model figure (43.8% / 47.5%) — summary doesn't separate them.")

    print()
    print("=" * 70)
    print("TABLE 4.4 — Vulnerability Category Rates (combined local + commercial)")
    print("=" * 70)
    vuln_map = {
        'SQL Injection':         {'CodeT5+': avg_by_vuln(CODET5_PHASE2,'SQL'),   'CodeLlama': avg_by_vuln(CODELLAMA_PHASE2,'SQL'),
                                    **VULN_PHASE5['SQL Injection']},
        'XSS':                    {'CodeT5+': avg_by_vuln(CODET5_PHASE2,'XSS'),   'CodeLlama': avg_by_vuln(CODELLAMA_PHASE2,'XSS'),
                                    **VULN_PHASE5['XSS']},
        'Hardcoded Credentials':  {'CodeT5+': avg_by_vuln(CODET5_PHASE2,'HC'),    'CodeLlama': avg_by_vuln(CODELLAMA_PHASE2,'HC'),
                                    **VULN_PHASE5['Hardcoded Credentials']},
        'Path Traversal':         {'CodeT5+': avg_by_vuln(CODET5_PHASE2,'Path'),  'CodeLlama': avg_by_vuln(CODELLAMA_PHASE2,'Path'),
                                    **VULN_PHASE5['Path Traversal']},
        'Insecure Cryptography':  {'CodeT5+': avg_by_vuln(CODET5_PHASE2,'Crypto'),'CodeLlama': avg_by_vuln(CODELLAMA_PHASE2,'Crypto')},
        'Command Injection':      {**VULN_PHASE5['Command Injection']},
    }
    for name, cells in vuln_map.items():
        vals = list(cells.values())
        mean = sum(vals) / len(vals)
        cell_str = ", ".join(f"{k}={r(v)}%" for k, v in cells.items())
        print(f"{name:<24} {cell_str:<70} mean={r(mean)}%")

    print()
    print("=" * 70)
    print("TABLE 4.5 — RQ2 Steganographic/Evasion Variation Techniques (Phase 3)")
    print("=" * 70)
    for name, d in STEGO_VARIATIONS.items():
        print(f"{name:<32} {d['rate']}%  ({d['n_success']}/{d['n_total']})")

    print()
    print("=" * 70)
    print("PHASE 3 PER-MODEL OVERALL (for supplementary transferability note)")
    print("=" * 70)
    for k, v in PHASE3_PER_MODEL_OVERALL.items():
        print(f"{k}: {v}%")
    print("Gap between models:", r(abs(PHASE3_PER_MODEL_OVERALL['CodeT5+'] - PHASE3_PER_MODEL_OVERALL['CodeLlama'])), "points")


if __name__ == "__main__":
    main()
