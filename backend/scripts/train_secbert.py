#!/usr/bin/env python3
"""
train_secbert.py — autoMITRE Nano AI Pipeline v1
================================================
Fine-tunes Jackaduma/SecBERT on the MITRE TRAM (Security-TTP-Mapping) dataset.
Specifically optimized for Apple Silicon (M1/M2/M3) using MPS.

Output:
  - Fine-tuned SecBERT model for Multi-Label Technique Classification
  - Saved to: backend/models/secbert_tram
"""

import os
import ast
import json
import torch
import numpy as np
from datasets import load_dataset
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    TrainingArguments, 
    Trainer
)
from sklearn.preprocessing import MultiLabelBinarizer

# Configure MPS (Apple Silicon GPU)
device = "mps" if torch.backends.mps.is_available() else "cpu"
print(f"Using device: {device}")

# Preprocessing Constants
MODEL_NAME = "jackaduma/SecBERT"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "secbert_tram")

def main():
    print(f"1. Loading TRAM dataset (tumeteor/Security-TTP-Mapping) from HuggingFace...")
    dataset = load_dataset('tumeteor/Security-TTP-Mapping')
    
    # Extract unique labels and parse stringified lists
    print("2. Parsing Multi-Label techniques...")
    mlb = MultiLabelBinarizer()
    
    def parse_labels(examples):
        # Convert "['T1059', 'T1110']" back to an actual python list
        parsed_labels = [ast.literal_eval(label_str) for label_str in examples['labels']]
        return {"parsed_labels": parsed_labels}
    
    dataset = dataset.map(parse_labels, batched=True)
    
    # Fit the label binarizer on the training set
    mlb.fit(dataset['train']['parsed_labels'])
    num_labels = len(mlb.classes_)
    print(f"   Detected {num_labels} unique ATT&CK techniques.")
    
    # Save the classes mapping for prediction later
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "label_classes.json"), "w") as f:
        json.dump(list(mlb.classes_), f)
        
    def encode_labels(examples):
        labels_matrix = mlb.transform(examples['parsed_labels'])
        # HuggingFace multi-label classification expects float targets
        return {"encoded_labels": labels_matrix.astype(np.float32).tolist()}

    dataset = dataset.map(encode_labels, batched=True)
    
    print(f"3. Loading AutoTokenizer for {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    
    def tokenize(examples):
        return tokenizer(examples['text1'], padding="max_length", truncation=True, max_length=128)
    
    print("4. Tokenizing dataset...")
    tokenized_dataset = dataset.map(tokenize, batched=True)
    
    # Remove old 'labels' (the stringified one) and rename 'encoded_labels' to 'labels' as required by Trainer
    tokenized_dataset = tokenized_dataset.remove_columns(["labels"])
    tokenized_dataset = tokenized_dataset.rename_column("encoded_labels", "labels")
    tokenized_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'labels'])
    
    print(f"5. Loading Sequence Classification Model (Num Labels: {num_labels})...")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, 
        num_labels=num_labels, 
        problem_type="multi_label_classification"
    )
    
    print("6. Configuring Trainer for MPS Optimization...")
    # Strict 8GB Apple Silicon Memory Optimizations:
    # 1. Batch size low (8)
    # 2. Max steps explicitly bounded (to keep training short for this test, but thorough enough)
    # 3. No fp16/bf16 required as MPS handles memory efficiency via metal dynamically sometimes causing precision issues if forced
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        eval_strategy="steps",
        eval_steps=200,
        save_strategy="no",
        learning_rate=3e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        num_train_epochs=2, # Keep short for 8GB Mac (approx 30 mins)
        weight_decay=0.01,
        report_to="none" # Disable W&B logging
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset['train'],
        eval_dataset=tokenized_dataset['validation'],
        processing_class=tokenizer
    )
    
    print("7. ⭐ Commencing SecBERT Fine-Tuning... (This will take approx 30-45 minutes on M1)")
    trainer.train()
    
    print(f"8. Saving final optimized model to {OUTPUT_DIR}...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("✅ SecBERT Fine-Tuning Complete. Stage 1 Nano Pipeline is ready.")

if __name__ == "__main__":
    main()
