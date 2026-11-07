#!/usr/bin/env python3
# =============================================================================
# Author      : Walther A. Del Orbe <waltdelorbe@gmail.com>
# Institution : Dakota State University — Beacom College of Computer and Cyber Sciences
# Degree      : Ph.D. in Cyber Operations
# Dissertation: Context-Based Adversarial Manipulation of AI Code Generators
# Chair       : Dr. Michael Ham
# Committee   : Dr. O'Brien · Dr. Kramer
# =============================================================================
# Walt Del Orbe
# Jun 2026
"""Pilot experiment runner - 150 test cases for Week 1-2"""

import sys
sys.path.append('/mnt/research_data/ai_security_research/scripts')

from model_loader import ModelLoader
from baseline_prompts import BASELINE_PROMPTS, ADVERSARIAL_PROMPTS
import json
import datetime
from pathlib import Path

def run_pilot_experiment():
    """Run pilot experiments with both models"""
    
    print("="*60)
    print("Starting Pilot Experiment - Week 1-2")
    print("="*60)
    
    # Initialize
    loader = ModelLoader()
    results = []
    
    # Load models
    print("\nLoading models...")
    model_t5, tok_t5 = loader.load_codet5p("770m")
    model_llama, tok_llama = loader.load_codellama("7b")
    
    # Test counter
    test_num = 0
    
    # Test each vulnerability type
    for vuln_type in ["sql_injection", "xss", "hardcoded_credentials"]:
        print(f"\n{'='*60}")
        print(f"Testing: {vuln_type}")
        print(f"{'='*60}")
        
        # Baseline tests
        print(f"\n[Baseline Tests]")
        
        # CodeT5+ baseline
        test_num += 1
        prompt_t5 = BASELINE_PROMPTS[vuln_type]["baseline_t5"]
        result_t5 = loader.generate_code_t5(model_t5, tok_t5, prompt_t5, max_length=100)
        print(f"\n{test_num}. CodeT5+ Baseline:")
        print(f"Generated: {result_t5[:100]}...")
        
        results.append({
            "test_num": test_num,
            "model": "CodeT5+-770m",
            "vuln_type": vuln_type,
            "attack_type": "baseline",
            "prompt": prompt_t5,
            "generated_code": result_t5,
            "timestamp": str(datetime.datetime.now())
        })
        
        # CodeLlama baseline
        test_num += 1
        prompt_llama = BASELINE_PROMPTS[vuln_type]["baseline"]
        result_llama = loader.generate_code_llama(model_llama, tok_llama, prompt_llama, max_length=100)
        print(f"\n{test_num}. CodeLlama Baseline:")
        print(f"Generated: {result_llama[:100]}...")
        
        results.append({
            "test_num": test_num,
            "model": "CodeLlama-7b",
            "vuln_type": vuln_type,
            "attack_type": "baseline",
            "prompt": prompt_llama,
            "generated_code": result_llama,
            "timestamp": str(datetime.datetime.now())
        })
        
        # Adversarial tests (direct manipulation)
        print(f"\n[Adversarial Tests - Direct]")
        
        # CodeT5+ adversarial
        test_num += 1
        prompt_t5_adv = ADVERSARIAL_PROMPTS[vuln_type]["direct_t5"]
        result_t5_adv = loader.generate_code_t5(model_t5, tok_t5, prompt_t5_adv, max_length=100)
        print(f"\n{test_num}. CodeT5+ Adversarial:")
        print(f"Generated: {result_t5_adv[:100]}...")
        
        results.append({
            "test_num": test_num,
            "model": "CodeT5+-770m",
            "vuln_type": vuln_type,
            "attack_type": "direct",
            "prompt": prompt_t5_adv,
            "generated_code": result_t5_adv,
            "timestamp": str(datetime.datetime.now())
        })
        
        # CodeLlama adversarial
        test_num += 1
        prompt_llama_adv = ADVERSARIAL_PROMPTS[vuln_type]["direct"]
        result_llama_adv = loader.generate_code_llama(model_llama, tok_llama, prompt_llama_adv, max_length=100)
        print(f"\n{test_num}. CodeLlama Adversarial:")
        print(f"Generated: {result_llama_adv[:100]}...")
        
        results.append({
            "test_num": test_num,
            "model": "CodeLlama-7b",
            "vuln_type": vuln_type,
            "attack_type": "direct",
            "prompt": prompt_llama_adv,
            "generated_code": result_llama_adv,
            "timestamp": str(datetime.datetime.now())
        })
    
    # Save results
    output_file = Path("../data/results/pilot_experiment_results.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"Pilot Experiment Complete!")
    print(f"Total tests: {test_num}")
    print(f"Results saved to: {output_file}")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_pilot_experiment()
