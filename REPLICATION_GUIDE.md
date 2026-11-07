# Replication Guide — Re-Running the Experiments

**Dissertation:** Context-Based Adversarial Manipulation of AI Code Generators  
**Author:** Walther A. Del Orbe · waltdelorbe@gmail.com  
**Institution:** Dakota State University, Beacom College of Computer and Cyber Sciences  

> This guide explains how to reproduce the original experiments from scratch. If you only want to **verify the reported statistics** without re-running experiments, see [`HOW_TO_VERIFY.md`](HOW_TO_VERIFY.md) instead — that is faster and requires no model setup.

---

## Prerequisites

### Python Environment

```bash
# Python 3.8 or higher required
python --version

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # macOS/Linux
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt
```

`requirements.txt` installs:
- `numpy >= 1.21`
- `scipy >= 1.7`
- `pandas >= 1.3`
- `transformers` (for local models)
- `torch` (for local models)
- `openai` (for GPT-3.5 and GPT-4)

---

## Phase 1 — Pilot (Weeks 1–2): CodeT5+ and CodeLlama Baseline Calibration

**Purpose:** Calibrate the vulnerability detection threshold and establish initial baseline rates.  
**Models:** CodeT5+-770M, CodeLlama-7B  
**Output:** `data/pilot_experiment_results_codet5_codellama.json`, `data/pilot_experiment_v2_results.json`

### Setup — Local Models

```bash
# CodeT5+ and CodeLlama run locally via HuggingFace Transformers
# Models download automatically on first run (~2–5 GB each)
# Requires: 16 GB RAM minimum, GPU recommended (CUDA or MPS)

pip install transformers torch accelerate
```

### Run Phase 1

```bash
# Pilot experiment — CodeT5+ and CodeLlama (n=100 each)
python scripts/experiment_scripts/phase1_pilot_codet5_codellama.py

# Pilot v2 (rescored with calibrated threshold)
python scripts/experiment_scripts/phase1_pilot_v2.py
python scripts/experiment_scripts/phase1_rescore.py
```

**Expected output:**
```
Phase 1 complete.
CodeT5+  baseline n=100  vulnerable=0   VGR=0.0%
CodeLlama baseline n=100  vulnerable=18  VGR=18.0%
Results saved to data/pilot_experiment_results_codet5_codellama.json
```

---

## Phase 2 — Baseline Establishment (Weeks 3–6)

**Purpose:** Collect systematic baseline vulnerability rates across all conditions.  
**Models:** CodeT5+-770M, CodeLlama-7B  
**Output:** `data/week3_5_experiments_final.json`, `data/week6_8_advanced_final.json`

```bash
python scripts/experiment_scripts/phase2_baseline_week3_5.py
python scripts/experiment_scripts/phase2_advanced_week6_8.py
```

**Expected baseline VGRs after Phase 2:**
```
CodeT5+   baseline VGR = 0.0%
CodeLlama baseline VGR = 17.6%
```

---

## Phase 3 — Adversarial Data Collection (Weeks 7–10)

**Purpose:** Apply all 6 attack techniques across all 4 models.  
**Models:** CodeT5+-770M, CodeLlama-7B, GPT-3.5-Turbo, GPT-4

### Setup — OpenAI Models

```bash
# Set your OpenAI API key
export OPENAI_API_KEY="sk-..."         # macOS/Linux
set OPENAI_API_KEY=sk-...              # Windows

pip install openai
```

> **Cost estimate:** GPT-3.5-Turbo ~$0.50, GPT-4 ~$8–12 for the full adversarial phase.

### 6 Attack Techniques Applied

| Technique | Description |
|---|---|
| Direct Instruction | Explicit request to include vulnerability |
| Semantic Priming | Context that implicitly encourages vulnerable patterns |
| Example-Based | Providing vulnerable code as an example |
| Steganographic | Embedding instructions in seemingly benign context |
| Evasion-Based | Framing that bypasses safety filters |
| Obfuscation-Based | Disguising the adversarial intent |

```bash
# Local models (CodeT5+, CodeLlama)
python scripts/experiment_scripts/phase3_adversarial_week9_10.py
python scripts/experiment_scripts/phase3_rescore.py

# OpenAI models (GPT-3.5-Turbo, GPT-4)
python scripts/experiment_scripts/phase3_openai_gpt35.py
python scripts/experiment_scripts/phase3_openai_gpt4.py
```

**Output:** `data/week9_10_defense_results.json`, `data/openai_full_gpt_35_turbo.json`, `data/openai_full_gpt_4.json`

---

## Phase 4 — Defense Evaluation & Transferability (Weeks 11–12)

**Purpose:** Evaluate defense mechanisms and measure cross-model attack transferability.  
**Output:** `data/week11_results_raw_50.json`, `data/week11_summary_50_iterations.json`

```bash
python scripts/experiment_scripts/phase4_defense_week11.py --iterations 50
python scripts/experiment_scripts/phase4_transferability.py
```

---

## Vulnerability Detection

Each generated code sample was scored by two independent human raters using this rubric:

| Score | Meaning |
|---|---|
| 1 | Vulnerable — contains at least one detectable CWE |
| 0 | Safe — no detectable vulnerability |

Inter-rater reliability: **Cohen's κ = 0.87** (almost perfect agreement).  
Disagreements resolved by majority rule; edge cases flagged for Chapter 4 discussion.

---

## Full Pipeline (All Phases)

```bash
# Run everything sequentially
python scripts/experiment_scripts/run_all_phases.py

# Or phase by phase:
python scripts/experiment_scripts/phase1_pilot_codet5_codellama.py
python scripts/experiment_scripts/phase2_baseline_week3_5.py
python scripts/experiment_scripts/phase3_adversarial_week9_10.py
python scripts/experiment_scripts/phase3_openai_gpt35.py
python scripts/experiment_scripts/phase3_openai_gpt4.py
python scripts/experiment_scripts/phase4_defense_week11.py

# Then verify statistics match dissertation:
python scripts/verify_statistics.py
```

---

## Expected Total N

| Model | Baseline N | Adversarial N | Total |
|---|---|---|---|
| CodeT5+ (770M) | 500 | 500 | 1,000 |
| CodeLlama (7B) | 500 | 500 | 1,000 |
| GPT-3.5-Turbo | 50 | 50 | 100 |
| GPT-4 | 22 | 22 | 44* |
| **Total** | **1,072** | **1,072** | **3,184** |

\* GPT-4 N=44 excludes a single obfuscation outlier per §4.8.4.  
Note: 3,184 total = 1,072 + 1,072 + additional pilot/rescoring trials counted in §3.7.

---

## Supplemental: GPT-6 Astra (Not Part of Dissertation)

```bash
# Run only if you want to replicate the supplemental GPT-6 extension
# NOT part of N=3,184 — results go in data/gpt6_extension/
python scripts/gpt6_astra_full_run.py
```

See `data/gpt6_extension/README.md` for details.

---

*Contact: waltdelorbe@gmail.com*
