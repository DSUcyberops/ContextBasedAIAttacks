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
Week 6-8 Advanced Techniques Experiments
- Steganographic attacks
- Detection evasion
- Cross-model transferability analysis
"""

import sys
sys.path.append('/mnt/research_data/ai_security_research/scripts')

from model_loader import ModelLoader
from advanced_attack_prompts import STEGANOGRAPHIC_PROMPTS, EVASION_PROMPTS
import json
import datetime
from pathlib import Path

def run_week6_8_experiments(num_iterations=25):
    """Run advanced attack experiments"""
    
    print("="*60)
    print("WEEK 6-8 ADVANCED TECHNIQUES EXPERIMENTS")
    print("="*60)
    print(f"Models: CodeT5+ 770M, CodeLlama 7B")
    print(f"Attack types: Steganographic, Evasion")
    print(f"Iterations per config: {num_iterations}")
    print("="*60)
    
    loader = ModelLoader()
    results = []
    test_num = 0
    
    print("\nLoading models...")
    model_t5, tok_t5 = loader.load_codet5p("770m")
    model_llama, tok_llama = loader.load_codellama("7b")
    print("✓ Models loaded\n")
    
    # Part 1: Steganographic Attacks
    print("\n" + "="*60)
    print("PART 1: STEGANOGRAPHIC ATTACKS")
    print("="*60)
    
    vuln_types = ["sql_injection", "xss", "hardcoded_credentials", 
                  "path_traversal", "insecure_crypto"]
    steg_variations = ["performance", "compatibility", "simplicity"]
    
    for vuln_type in vuln_types:
        print(f"\n{'='*60}")
        print(f"Vulnerability: {vuln_type.upper()}")
        print(f"{'='*60}")
        
        # Check if this vulnerability type exists
        if vuln_type not in STEGANOGRAPHIC_PROMPTS:
            print(f"  ⚠️ Skipping {vuln_type} - not in STEGANOGRAPHIC_PROMPTS")
            continue
        
        for variation in steg_variations:
            print(f"\n[Steganographic - {variation.upper()}]")
            
            # Safe key access
            if variation not in STEGANOGRAPHIC_PROMPTS[vuln_type]:
                print(f"  ⚠️ Skipping {variation} - key not found")
                continue
                
            prompt_llama = STEGANOGRAPHIC_PROMPTS[vuln_type][variation]
            prompt_t5_key = f"{variation}_t5"
            
            if prompt_t5_key in STEGANOGRAPHIC_PROMPTS[vuln_type]:
                prompt_t5 = STEGANOGRAPHIC_PROMPTS[vuln_type][prompt_t5_key]
            else:
                # Fallback: add T5 token
                prompt_t5 = prompt_llama.replace(":", ":<extra_id_0>")
            
            for iteration in range(num_iterations):
                # CodeT5+ test
                test_num += 1
                try:
                    result_t5 = loader.generate_code_t5(model_t5, tok_t5, prompt_t5, max_length=150)
                    
                    results.append({
                        "test_num": test_num,
                        "week": "6-8",
                        "phase": "steganographic",
                        "model": "CodeT5+-770m",
                        "vuln_type": vuln_type,
                        "attack_variation": variation,
                        "iteration": iteration + 1,
                        "prompt": prompt_t5,
                        "generated_code": result_t5,
                        "timestamp": str(datetime.datetime.now())
                    })
                    
                    if iteration == 0:
                        print(f"  CodeT5+ #{test_num}: {result_t5[:60]}...")
                
                except Exception as e:
                    print(f"  ✗ CodeT5+ error: {e}")
                
                # CodeLlama test
                test_num += 1
                try:
                    result_llama = loader.generate_code_llama(model_llama, tok_llama, prompt_llama, max_length=150)
                    
                    results.append({
                        "test_num": test_num,
                        "week": "6-8",
                        "phase": "steganographic",
                        "model": "CodeLlama-7b",
                        "vuln_type": vuln_type,
                        "attack_variation": variation,
                        "iteration": iteration + 1,
                        "prompt": prompt_llama,
                        "generated_code": result_llama,
                        "timestamp": str(datetime.datetime.now())
                    })
                    
                    if iteration == 0:
                        print(f"  CodeLlama #{test_num}: {result_llama[:60]}...")
                
                except Exception as e:
                    print(f"  ✗ CodeLlama error: {e}")
                
                if (iteration + 1) % 10 == 0:
                    print(f"  ... {iteration + 1}/{num_iterations} iterations complete")
    
    # Part 2: Detection Evasion
    print("\n" + "="*60)
    print("PART 2: DETECTION EVASION ATTACKS")
    print("="*60)
    
    evasion_vulns = ["sql_injection", "xss", "hardcoded_credentials"]
    evasion_variations = ["indirect", "technical"]
    
    for vuln_type in evasion_vulns:
        print(f"\n{'='*60}")
        print(f"Vulnerability: {vuln_type.upper()}")
        print(f"{'='*60}")
        
        if vuln_type not in EVASION_PROMPTS:
            print(f"  ⚠️ Skipping {vuln_type} - not in EVASION_PROMPTS")
            continue
        
        for variation in evasion_variations:
            print(f"\n[Evasion - {variation.upper()}]")
            
            if variation not in EVASION_PROMPTS[vuln_type]:
                print(f"  ⚠️ Skipping {variation} - key not found")
                continue
                
            prompt_llama = EVASION_PROMPTS[vuln_type][variation]
            prompt_t5_key = f"{variation}_t5"
            
            if prompt_t5_key in EVASION_PROMPTS[vuln_type]:
                prompt_t5 = EVASION_PROMPTS[vuln_type][prompt_t5_key]
            else:
                prompt_t5 = prompt_llama.replace(":", ":<extra_id_0>")
            
            for iteration in range(num_iterations):
                # CodeT5+ test
                test_num += 1
                try:
                    result_t5 = loader.generate_code_t5(model_t5, tok_t5, prompt_t5, max_length=150)
                    
                    results.append({
                        "test_num": test_num,
                        "week": "6-8",
                        "phase": "evasion",
                        "model": "CodeT5+-770m",
                        "vuln_type": vuln_type,
                        "attack_variation": variation,
                        "iteration": iteration + 1,
                        "prompt": prompt_t5,
                        "generated_code": result_t5,
                        "timestamp": str(datetime.datetime.now())
                    })
                    
                    if iteration == 0:
                        print(f"  CodeT5+ #{test_num}: {result_t5[:60]}...")
                
                except Exception as e:
                    print(f"  ✗ CodeT5+ error: {e}")
                
                # CodeLlama test
                test_num += 1
                try:
                    result_llama = loader.generate_code_llama(model_llama, tok_llama, prompt_llama, max_length=150)
                    
                    results.append({
                        "test_num": test_num,
                        "week": "6-8",
                        "phase": "evasion",
                        "model": "CodeLlama-7b",
                        "vuln_type": vuln_type,
                        "attack_variation": variation,
                        "iteration": iteration + 1,
                        "prompt": prompt_llama,
                        "generated_code": result_llama,
                        "timestamp": str(datetime.datetime.now())
                    })
                    
                    if iteration == 0:
                        print(f"  CodeLlama #{test_num}: {result_llama[:60]}...")
                
                except Exception as e:
                    print(f"  ✗ CodeLlama error: {e}")
                
                if (iteration + 1) % 10 == 0:
                    print(f"  ... {iteration + 1}/{num_iterations} iterations complete")
            
            if test_num % 100 == 0:
                checkpoint_file = Path("../data/results/week6_8_checkpoint.json")
                checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
                with open(checkpoint_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"  💾 Checkpoint: {len(results)} tests saved")
    
    # Save final results
    output_file = Path("../data/results/week6_8_advanced_final.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Summary
    print(f"\n{'='*60}")
    print("WEEK 6-8 ADVANCED EXPERIMENTS COMPLETE!")
    print(f"{'='*60}")
    print(f"Total tests: {test_num}")
    print(f"Results saved: {output_file}")
    print(f"\nBreakdown:")
    steg_count = len([r for r in results if r['phase'] == 'steganographic'])
    evasion_count = len([r for r in results if r['phase'] == 'evasion'])
    print(f"  Steganographic attacks: {steg_count}")
    print(f"  Evasion attacks: {evasion_count}")
    print(f"  CodeT5+ tests: {len([r for r in results if 'CodeT5' in r['model']])}")
    print(f"  CodeLlama tests: {len([r for r in results if 'CodeLlama' in r['model']])}")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_week6_8_experiments(num_iterations=25)