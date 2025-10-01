#!/usr/bin/env python3
"""
Create preprocessed training data by applying Lambda preprocessing to raw network logs.
This creates the training dataset that SageMaker will use.
"""

import pandas as pd
import json
import sys
import os

# Add src to path for imports
sys.path.append('src')

import importlib.util
spec = importlib.util.spec_from_file_location("preprocess", "src/lambda/preprocess.py")
preprocess_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preprocess_module)


def create_processed_training_data():
    """Create preprocessed training data from raw network logs."""
    print("Loading raw network logs...")
    
    # Load raw data
    raw_df = pd.read_csv("data/raw/network_logs.csv")
    print(f"Loaded {len(raw_df)} raw records with {len(raw_df.columns)} columns")
    
    # Apply preprocessing to each record
    print("Applying Lambda preprocessing function...")
    processed_records = []
    
    for i, row in raw_df.iterrows():
        try:
            # Convert row to dict and preprocess
            record_dict = row.to_dict()
            result = preprocess_module.handler(record_dict, None)
            
            # Extract features and preserve label
            features = result["features"]
            features["label"] = record_dict.get("label", "unknown")
            processed_records.append(features)
            
            if (i + 1) % 500 == 0:
                print(f"  Processed {i + 1} records...")
                
        except Exception as e:
            print(f"Error processing record {i}: {e}")
            continue
    
    # Create processed DataFrame
    processed_df = pd.DataFrame(processed_records)
    print(f"Created processed dataset: {len(processed_df)} records, {len(processed_df.columns)} features")
    
    # Show label distribution
    print("\nLabel distribution:")
    print(processed_df['label'].value_counts())
    
    # Show sample features
    print(f"\nSample processed features:")
    print(processed_df.head(3))
    
    print(f"\nFeature columns:")
    feature_cols = [col for col in processed_df.columns if col != 'label']
    print(f"  {len(feature_cols)} features: {feature_cols[:10]}{'...' if len(feature_cols) > 10 else ''}")
    
    # Save processed data
    os.makedirs("data/train", exist_ok=True)
    processed_file = "data/train/processed_network_logs.csv"
    processed_df.to_csv(processed_file, index=False)
    print(f"\nProcessed training data saved to: {processed_file}")
    
    # Also create a smaller sample for quick testing
    sample_df = processed_df.sample(n=min(500, len(processed_df)), random_state=42)
    sample_file = "data/train/sample_processed_logs.csv"
    sample_df.to_csv(sample_file, index=False)
    print(f"Sample dataset saved to: {sample_file}")
    
    return processed_file


if __name__ == "__main__":
    create_processed_training_data()