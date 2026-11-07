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
#jun 2026
"""Analyze pilot experiment results"""

import json
from pathlib import Path

def analyze_results():
    """Analyze pilot experiment results"""
    
    results_file = Path("../data/results/pilot_experiment_results.json")
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    print("="*60)
    print("PILOT EXPERIMENT ANALYSIS")
    print("="*60)
    
    # Summary statistics
    print(f"\nTotal tests: {len(results)}")
    
    # Group by model
    models = {}
    for result in results:
        model = result['model']
        if model not in models:
            models[model] = {'baseline': 0, 'adversarial': 0}
        
        if result['attack_type'] == 'baseline':
            models[model]['baseline'] += 1
        else:
            models[model]['adversarial'] += 1
    
    print("\nTests by Model:")
    for model, counts in models.items():
        print(f"  {model}:")
        print(f"    Baseline: {counts['baseline']}")
        print(f"    Adversarial: {counts['adversarial']}")
    
    # Show sample results
    print("\n" + "="*60)
    print("SAMPLE RESULTS")
    print("="*60)
    
    for vuln_type in ["sql_injection", "xss", "hardcoded_credentials"]:
        print(f"\n--- {vuln_type.upper()} ---")
        
        vuln_results = [r for r in results if r['vuln_type'] == vuln_type]
        
        for result in vuln_results[:4]:  # Show first 4 for each type
            print(f"\nTest #{result['test_num']}")
            print(f"Model: {result['model']}")
            print(f"Type: {result['attack_type']}")
            print(f"Prompt: {result['prompt'][:60]}...")
            print(f"Generated (first 150 chars):")
            print(f"{result['generated_code'][:150]}...")
            print("-" * 40)
    
    print("\n" + "="*60)
    print("Analysis complete!")
    print("="*60)
    print("\nNext steps:")
    print("1. Review generated code for vulnerabilities")
    print("2. Compare baseline vs adversarial outputs")
    print("3. Document which attacks were successful")
    print("4. Refine prompts for main experiments (Week 3-5)")

if __name__ == "__main__":
    analyze_results()
