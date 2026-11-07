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
# June 2026, dSU
"""Model loader utility for AI security research"""

import os
import torch
from transformers import T5ForConditionalGeneration, AutoTokenizer, AutoModelForCausalLM
from typing import Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ModelLoader:
    """Load and manage AI code generation models"""
    
    def __init__(self):
        self.token = os.getenv('HF_TOKEN')
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.models = {}
        self.tokenizers = {}
        logger.info(f"Using device: {self.device}")
    
    def load_codet5p(self, model_size: str = "770m") -> Tuple:
        """Load CodeT5+ model (Python-specific checkpoint)"""
        checkpoint = f"Salesforce/codet5p-{model_size}-py"
        
        if checkpoint in self.models:
            logger.info(f"Using cached {checkpoint}")
            return self.models[checkpoint], self.tokenizers[checkpoint]
        
        logger.info(f"Loading {checkpoint}...")
        
        tokenizer = AutoTokenizer.from_pretrained(checkpoint, token=self.token)
        model = T5ForConditionalGeneration.from_pretrained(
            checkpoint, 
            token=self.token
        ).to(self.device)
        
        self.models[checkpoint] = model
        self.tokenizers[checkpoint] = tokenizer
        
        logger.info(f"Loaded {checkpoint}")
        return model, tokenizer
    
    def load_codellama(self, model_size: str = "7b") -> Tuple:
        """Load CodeLlama model"""
        checkpoint = f"codellama/CodeLlama-{model_size}-Python-hf"
        
        if checkpoint in self.models:
            logger.info(f"Using cached {checkpoint}")
            return self.models[checkpoint], self.tokenizers[checkpoint]
        
        logger.info(f"Loading {checkpoint}...")
        
        tokenizer = AutoTokenizer.from_pretrained(checkpoint, token=self.token)
        model = AutoModelForCausalLM.from_pretrained(
            checkpoint,
            token=self.token
        ).to(self.device)
        
        self.models[checkpoint] = model
        self.tokenizers[checkpoint] = tokenizer
        
        logger.info(f"Loaded {checkpoint}")
        return model, tokenizer
    
    def generate_code_t5(self, model, tokenizer, prompt: str, max_length: int = 150) -> str:
        """Generate code from CodeT5+"""
        inputs = tokenizer.encode(prompt, return_tensors="pt").to(self.device)
        outputs = model.generate(inputs, max_length=max_length)
        return tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    def generate_code_llama(self, model, tokenizer, prompt: str, max_length: int = 150) -> str:
        """Generate code from CodeLlama"""
        inputs = tokenizer(prompt, return_tensors="pt").to(self.device)
        outputs = model.generate(
            inputs.input_ids,
            max_length=max_length,
            temperature=0.2,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
        return tokenizer.decode(outputs[0], skip_special_tokens=True)

if __name__ == "__main__":
    loader = ModelLoader()
    
    print("\nTesting CodeT5+ 770M")
    print("="*60)
    model_t5, tok_t5 = loader.load_codet5p("770m")
    prompt_t5 = "def validate_input(data):<extra_id_0>"
    result_t5 = loader.generate_code_t5(model_t5, tok_t5, prompt_t5)
    print(f"Prompt: {prompt_t5}")
    print(f"Generated: {result_t5}")
    
    print("\nTesting CodeLlama 7B")
    print("="*60)
    model_llama, tok_llama = loader.load_codellama("7b")
    prompt_llama = "def validate_input(data):"
    result_llama = loader.generate_code_llama(model_llama, tok_llama, prompt_llama)
    print(f"Prompt: {prompt_llama}")
    print(f"Generated: {result_llama}")
