#!/usr/bin/env python3

"""
Self-contained SageMaker Processing Job for Cyber Threat Detection Training
Installs its own dependencies
"""

import subprocess
import sys
import os
import json

def install_dependencies():
    """Install required dependencies"""
    print("🔧 Installing dependencies...")
    
    packages = [
        'pandas==1.5.3',
        'numpy==1.24.3', 
        'scikit-learn==1.2.2',
        'xgboost==1.7.5'
    ]
    
    for package in packages:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
    
    print("✅ Dependencies installed successfully")

def main():
    """Main processing function"""
    print("🚀 Starting SageMaker Processing Job for Cyber Threat Detection")
    
    # Install dependencies first
    install_dependencies()
    
    # Now import the packages
    import pandas as pd
    import numpy as np
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.utils.class_weight import compute_class_weight
    import xgboost as xgb
    
    # Processing job paths
    input_path = "/opt/ml/processing/input"
    output_path = "/opt/ml/processing/output"
    model_path = "/opt/ml/processing/model"
    
    # Create output directories
    os.makedirs(output_path, exist_ok=True)
    os.makedirs(model_path, exist_ok=True)
    
    print(f"📁 Input path: {input_path}")
    print(f"📁 Output path: {output_path}")
    print(f"📁 Model path: {model_path}")
    
    # Find and load training data
    data_files = []
    for root, dirs, files in os.walk(input_path):
        for file in files:
            if file.endswith('.csv'):
                data_files.append(os.path.join(root, file))
    
    if not data_files:
        raise FileNotFoundError(f"No CSV files found in {input_path}")
    
    print(f"📊 Found {len(data_files)} data files: {data_files}")
    
    # Load the first CSV file
    df = pd.read_csv(data_files[0])
    print(f"📈 Loaded dataset with shape: {df.shape}")
    print(f"📋 Columns: {list(df.columns)}")
    
    # Check for target column
    target_column = 'label'
    if target_column not in df.columns:
        print(f"❌ Target column '{target_column}' not found. Available columns: {list(df.columns)}")
        sys.exit(1)
    
    # Prepare features and target
    X = df.drop(columns=[target_column])
    y = df[target_column]
    
    print(f"🎯 Target distribution:")
    print(y.value_counts())
    
    # Handle infinite and NaN values
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    
    print(f"✅ Cleaned features: {X.shape}")
    
    # Split the data
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"📊 Training set: {X_train.shape}")
    print(f"📊 Validation set: {X_val.shape}")
    
    # Compute class weights for imbalanced data
    classes = np.unique(y_train)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
    weight_dict = dict(zip(classes, class_weights))
    
    print(f"⚖️ Class weights: {weight_dict}")
    
    # Create sample weights
    sample_weights = np.array([weight_dict[label] for label in y_train])
    
    # Train XGBoost model
    print("🤖 Training XGBoost model...")
    
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train, sample_weight=sample_weights)
    
    # Make predictions
    y_pred = model.predict(X_val)
    
    # Calculate metrics
    report = classification_report(y_val, y_pred, output_dict=True)
    
    print("📊 Classification Report:")
    print(classification_report(y_val, y_pred))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("🎯 Top 10 Most Important Features:")
    print(feature_importance.head(10))
    
    # Save model
    model_file = os.path.join(model_path, "xgb_model.json")
    model.save_model(model_file)
    print(f"💾 Model saved to: {model_file}")
    
    # Save metrics
    metrics = {
        'classification_report': report,
        'feature_importance': feature_importance.to_dict('records'),
        'training_samples': len(X_train),
        'validation_samples': len(X_val),
        'accuracy': float(report['accuracy']),
        'classes': list(classes)
    }
    
    metrics_file = os.path.join(output_path, "metrics.json")
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    print(f"📈 Metrics saved to: {metrics_file}")
    
    # Save feature importance as CSV
    importance_file = os.path.join(output_path, "feature_importance.csv")
    feature_importance.to_csv(importance_file, index=False)
    
    print(f"🎯 Feature importance saved to: {importance_file}")
    
    # Save confusion matrix
    cm = confusion_matrix(y_val, y_pred)
    cm_df = pd.DataFrame(cm, index=classes, columns=classes)
    cm_file = os.path.join(output_path, "confusion_matrix.csv")
    cm_df.to_csv(cm_file)
    
    print(f"🔍 Confusion matrix saved to: {cm_file}")
    
    print("✅ Processing job completed successfully!")
    print(f"🎯 Final validation accuracy: {report['accuracy']:.4f}")

if __name__ == "__main__":
    main()