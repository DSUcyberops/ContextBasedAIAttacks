#!/usr/bin/env python3
# =============================================================================
# Author      : Walther A. Del Orbe <waltdelorbe@gmail.com>
# Institution : Dakota State University — Beacom College of Computer and Cyber Sciences
# Degree      : Ph.D. in Cyber Operations
# Dissertation: Context-Based Adversarial Manipulation of AI Code Generators
# Chair       : Dr. Michael Ham
# Committee   : Dr. O'Brien · Dr. Kramer
# =============================================================================
"""
Week 3-5 Core Experiments
Target: 1,000+ test cases across 4 models and 5 vulnerability types
"""

import sys
sys.path.append('/mnt/research_data/ai_security_research/scripts')

from model_loader import ModelLoader
from expanded_prompts import BASELINE_PROMPTS, ADVERSARIAL_PROMPTS
import json
import datetime
from pathlib import Path
import os

def run_week3_5_experiments(num_iterations=50):
    """
    Run comprehensive experiments
    
    Args:
        num_iterations: Number of iterations per test configuration
                       50 iterations = 50 x 40 test configs = 2,000 tests
    """
    
    print("="*60)
    print("WEEK 3-5 CORE EXPERIMENTS")
    print("="*60)
    print(f"Models: CodeT5+ 770M, CodeLlama 7B")
    print(f"Vulnerability types: 5")
    print(f"Attack techniques: 3 (direct, semantic, example)")
    print(f"Iterations per config: {num_iterations}")
    print(f"Estimated total tests: {2 * 5 * 4 * num_iterations}")
    print("="*60)
    
    # Initialize
    loader = ModelLoader()
    results = []
    test_num = 0
    
    # Load models (only free models for now)
    print("\nLoading models...")
    model_t5, tok_t5 = loader.load_codet5p("770m")
    model_llama, tok_llama = loader.load_codellama("7b")
    print("✓ Models loaded\n")
    
    # Test configurations
    vuln_types = ["sql_injection", "xss", "hardcoded_credentials", 
                  "path_traversal", "insecure_crypto"]
    attack_types = ["baseline", "direct", "semantic", "example"]
    
    # Run experiments
    for vuln_type in vuln_types:
        print(f"\n{'='*60}")
        print(f"Testing: {vuln_type.upper()}")
        print(f"{'='*60}")
        
        for attack_type in attack_types:
            print(f"\n[{attack_type.upper()}]")
            
            # Get prompts
            if attack_type == "baseline":
                prompt_t5 = BASELINE_PROMPTS[vuln_type]["baseline_t5"]
                prompt_llama = BASELINE_PROMPTS[vuln_type]["baseline"]
            else:
                prompt_t5 = ADVERSARIAL_PROMPTS[vuln_type][f"{attack_type}_t5"]
                prompt_llama = ADVERSARIAL_PROMPTS[vuln_type][attack_type]
            
            # Run iterations
            for iteration in range(num_iterations):
                # CodeT5+ test
                test_num += 1
                try:
                    result_t5 = loader.generate_code_t5(model_t5, tok_t5, prompt_t5, max_length=150)
                    
                    results.append({
                        "test_num": test_num,
                        "model": "CodeT5+-770m",
                        "vuln_type": vuln_type,
                        "attack_type": attack_type,
                        "iteration": iteration + 1,
                        "prompt": prompt_t5,
                        "generated_code": result_t5,
                        "timestamp": str(datetime.datetime.now())
                    })
                    
                    if iteration == 0:  # Show first result only
                        print(f"  CodeT5+ #{test_num}: {result_t5[:60]}...")
                
                except Exception as e:
                    print(f"  ✗ CodeT5+ error: {e}")
                
                # CodeLlama test
                test_num += 1
                try:
                    result_llama = loader.generate_code_llama(model_llama, tok_llama, prompt_llama, max_length=150)
                    
                    results.append({
                        "test_num": test_num,
                        "model": "CodeLlama-7b",
                        "vuln_type": vuln_type,
                        "attack_type": attack_type,
                        "iteration": iteration + 1,
                        "prompt": prompt_llama,
                        "generated_code": result_llama,
                        "timestamp": str(datetime.datetime.now())
                    })
                    
                    if iteration == 0:  # Show first result only
                        print(f"  CodeLlama #{test_num}: {result_llama[:60]}...")
                
                except Exception as e:
                    print(f"  ✗ CodeLlama error: {e}")
                
                # Progress indicator
                if (iteration + 1) % 10 == 0:
                    print(f"  ... {iteration + 1}/{num_iterations} iterations complete")
            
            # Save intermediate results
            if test_num % 100 == 0:
                output_file = Path("../data/results/week3_5_experiments_final.json")
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"  💾 Checkpoint saved: {len(results)} tests")
    
    # Save final results
    output_file = Path("../data/results/week3_5_experiments_final.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Summary statistics
    print(f"\n{'='*60}")
    print("WEEK 3-5 EXPERIMENTS COMPLETE!")
    print(f"{'='*60}")
    print(f"Total tests: {test_num}")
    print(f"Results saved: {output_file}")
    print(f"\nBreakdown:")
    print(f"  CodeT5+ tests: {len([r for r in results if 'CodeT5' in r['model']])}")
    print(f"  CodeLlama tests: {len([r for r in results if 'CodeLlama' in r['model']])}")
    print(f"  Vulnerability types: {len(vuln_types)}")
    print(f"  Attack techniques: {len(attack_types)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    # Run with 50 iterations = 2,000 total tests
    # Adjust this number based on your timeline:
    # 25 iterations = 1,000 tests (~2-3 hours)
    # 50 iterations = 2,000 tests (~4-6 hours)
    # 100 iterations = 4,000 tests (~8-12 hours)
    
    run_week3_5_experiments(num_iterations=50)
