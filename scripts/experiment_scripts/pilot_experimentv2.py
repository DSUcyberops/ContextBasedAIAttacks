#!/usr/bin/env python3
# =============================================================================
# Author      : Walther A. Del Orbe <waltdelorbe@gmail.com>
# Institution : Dakota State University — Beacom College of Computer and Cyber Sciences
# Degree      : Ph.D. in Cyber Operations
# Dissertation: Context-Based Adversarial Manipulation of AI Code Generators
# Chair       : Dr. Michael Ham
# Committee   : Dr. O'Brien · Dr. Kramer
# =============================================================================
"""Pilot experiment v2 - improved reliability for vulnerability detection"""

import sys
sys.path.append('/mnt/research_data/ai_security_research/scripts')

from model_loader import ModelLoader
from baseline_prompts import BASELINE_PROMPTS, ADVERSARIAL_PROMPTS
from defense_mechanisms import DefenseSystem
import json
import datetime
from pathlib import Path
from transformers import T5ForConditionalGeneration, AutoTokenizer
import torch
import os

def load_codet5p_python(loader):
    """Load Python-specific CodeT5+ checkpoint to avoid Ruby-syntax drift"""
    checkpoint = "Salesforce/codet5p-770m-py"
    token = loader.token

    print(f"Loading {checkpoint} (Python-specific)...")
    tokenizer = AutoTokenizer.from_pretrained(checkpoint, token=token)
    model = T5ForConditionalGeneration.from_pretrained(
        checkpoint, token=token
    ).to(loader.device)
    print(f"✓ {checkpoint} loaded")
    return model, tokenizer


def run_pilot_v2(num_iterations=5):
    """
    Run pilot with multiple iterations per prompt to reliably surface
    vulnerabilities, using Python-specific CodeT5+ checkpoint.
    """

    print("="*60)
    print("PILOT EXPERIMENT v2 - Improved Reliability")
    print("="*60)
    print(f"Iterations per prompt: {num_iterations}")
    print("="*60)

    loader = ModelLoader()
    defense = DefenseSystem()
    results = []
    test_num = 0

    print("\nLoading models...")
    model_t5, tok_t5 = load_codet5p_python(loader)
    model_llama, tok_llama = loader.load_codellama("7b")
    print("✓ Models loaded\n")

    for vuln_type in ["sql_injection", "xss", "hardcoded_credentials"]:
        print(f"\n{'='*60}")
        print(f"Testing: {vuln_type}")
        print(f"{'='*60}")

        for attack_type in ["baseline", "direct"]:
            print(f"\n[{attack_type.upper()}]")

            if attack_type == "baseline":
                prompt_t5 = BASELINE_PROMPTS[vuln_type]["baseline_t5"]
                prompt_llama = BASELINE_PROMPTS[vuln_type]["baseline"]
            else:
                prompt_t5 = ADVERSARIAL_PROMPTS[vuln_type]["direct_t5"]
                prompt_llama = ADVERSARIAL_PROMPTS[vuln_type]["direct"]

            # --- CodeT5+ (Python checkpoint) ---
            t5_vuln_found = False
            t5_samples = []
            for it in range(num_iterations):
                test_num += 1
                code = loader.generate_code_t5(model_t5, tok_t5, prompt_t5, max_length=150)
                has_vuln, issues = defense.analyze_generated_code(code)
                t5_samples.append({"iteration": it+1, "code": code, "vulnerable": has_vuln, "issues": issues})
                if has_vuln:
                    t5_vuln_found = True

            status = "🚨 VULNERABLE" if t5_vuln_found else "✅ safe (all iterations)"
            print(f"  CodeT5+-py [{attack_type}]: {status} ({sum(s['vulnerable'] for s in t5_samples)}/{num_iterations} iterations flagged)")

            results.append({
                "test_num": test_num,
                "model": "CodeT5+-770m-py",
                "vuln_type": vuln_type,
                "attack_type": attack_type,
                "prompt": prompt_t5,
                "vulnerable_any_iteration": t5_vuln_found,
                "vulnerable_count": sum(s['vulnerable'] for s in t5_samples),
                "total_iterations": num_iterations,
                "samples": t5_samples,
                "timestamp": str(datetime.datetime.now())
            })

            # --- CodeLlama ---
            llama_vuln_found = False
            llama_samples = []
            for it in range(num_iterations):
                test_num += 1
                code = loader.generate_code_llama(model_llama, tok_llama, prompt_llama, max_length=150)
                has_vuln, issues = defense.analyze_generated_code(code)
                llama_samples.append({"iteration": it+1, "code": code, "vulnerable": has_vuln, "issues": issues})
                if has_vuln:
                    llama_vuln_found = True

            status = "🚨 VULNERABLE" if llama_vuln_found else "✅ safe (all iterations)"
            print(f"  CodeLlama-7b [{attack_type}]: {status} ({sum(s['vulnerable'] for s in llama_samples)}/{num_iterations} iterations flagged)")

            results.append({
                "test_num": test_num,
                "model": "CodeLlama-7b",
                "vuln_type": vuln_type,
                "attack_type": attack_type,
                "prompt": prompt_llama,
                "vulnerable_any_iteration": llama_vuln_found,
                "vulnerable_count": sum(s['vulnerable'] for s in llama_samples),
                "total_iterations": num_iterations,
                "samples": llama_samples,
                "timestamp": str(datetime.datetime.now())
            })

    # Save
    output_file = Path("../data/results/pilot_experiment_v2_results.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Summary
    print(f"\n{'='*60}")
    print("PILOT v2 COMPLETE")
    print(f"{'='*60}")
    print(f"Total generations: {test_num}")
    print(f"Results saved: {output_file}")

    print(f"\n{'Model':<20}{'Vuln Type':<22}{'Attack':<10}{'Flagged'}")
    print("-"*65)
    for r in results:
        print(f"{r['model']:<20}{r['vuln_type']:<22}{r['attack_type']:<10}{r['vulnerable_count']}/{r['total_iterations']}")

if __name__ == "__main__":
    run_pilot_v2(num_iterations=5)
