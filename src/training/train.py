# Enhanced training script for cyber threat detection with XGBoost
import argparse
import os
import json
import sys
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NumpyEncoder(json.JSONEncoder):
    """JSON encoder that handles numpy types."""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)


def preprocess_raw_data_if_needed(df):
    """
    Apply Lambda preprocessing to raw data if it hasn't been preprocessed yet.
    """
    # Check if data needs preprocessing (has raw log fields)
    raw_fields = ['source_ip', 'destination_ip', 'protocol', 'timestamp']
    needs_preprocessing = any(field in df.columns for field in raw_fields)
    
    if not needs_preprocessing:
        logger.info("Data appears to already be preprocessed")
        return df
    
    logger.info("Raw data detected, applying preprocessing...")
    
    # Import preprocessing function
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("preprocess", 
            os.path.join(os.path.dirname(__file__), "..", "lambda", "preprocess.py"))
        preprocess_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preprocess_module)
        
        processed_records = []
        for _, row in df.iterrows():
            try:
                result = preprocess_module.handler(row.to_dict(), None)
                features = result["features"]
                # Preserve original label
                features["label"] = row.get("label", "unknown")
                processed_records.append(features)
            except Exception as e:
                logger.warning(f"Error preprocessing record: {e}")
                continue
        
        processed_df = pd.DataFrame(processed_records)
        logger.info(f"Preprocessing complete: {len(processed_df)} records, {len(processed_df.columns)} features")
        return processed_df
        
    except Exception as e:
        logger.error(f"Failed to preprocess data: {e}")
        return df

def parse_args():
    parser = argparse.ArgumentParser(description="Train cyber threat detection model")
    # Data locations
    parser.add_argument("--train", type=str, default=os.environ.get("SM_CHANNEL_TRAIN"),
                       help="Training data directory")
    parser.add_argument("--model-dir", type=str, default=os.environ.get("SM_MODEL_DIR", "/opt/ml/model"),
                       help="Model output directory")
    parser.add_argument("--output-data-dir", type=str, default=os.environ.get("SM_OUTPUT_DATA_DIR", "/opt/ml/output/data"),
                       help="Output data directory for metrics")
    
    # Training parameters
    parser.add_argument("--target", type=str, default="label", help="Target column name")
    parser.add_argument("--test-size", type=float, default=0.2, help="Validation set size")
    parser.add_argument("--random-state", type=int, default=42, help="Random state for reproducibility")
    parser.add_argument("--preprocess-raw", action="store_true", 
                       help="Apply Lambda preprocessing to raw data")
    
    # XGBoost hyperparameters - optimized for threat detection
    parser.add_argument("--max-depth", type=int, default=6, help="Maximum tree depth")
    parser.add_argument("--n-estimators", type=int, default=300, help="Number of trees")
    parser.add_argument("--learning-rate", type=float, default=0.1, help="Learning rate")
    parser.add_argument("--subsample", type=float, default=0.8, help="Subsample ratio")
    parser.add_argument("--colsample-bytree", type=float, default=0.8, help="Feature subsample ratio")
    parser.add_argument("--scale-pos-weight", type=float, default=None, 
                       help="Scale positive weight (for imbalanced classes)")
    parser.add_argument("--use-class-weights", action="store_true",
                       help="Automatically balance class weights")
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    logger.info("Starting cyber threat detection model training...")
    logger.info(f"Training data location: {args.train}")
    
    # Load training data
    csv_files = []
    if args.train and os.path.isdir(args.train):
        csv_files = [os.path.join(args.train, f) for f in os.listdir(args.train) 
                    if f.lower().endswith(".csv")]
    
    if not csv_files:
        raise FileNotFoundError("No training CSV files found in train channel")
    
    logger.info(f"Found {len(csv_files)} CSV file(s): {[os.path.basename(f) for f in csv_files]}")
    
    # Load all CSV files if multiple exist
    dfs = []
    for csv_file in csv_files:
        logger.info(f"Loading {csv_file}...")
        df_temp = pd.read_csv(csv_file)
        dfs.append(df_temp)
    
    df = pd.concat(dfs, ignore_index=True) if len(dfs) > 1 else dfs[0]
    logger.info(f"Loaded dataset: {len(df)} rows, {len(df.columns)} columns")
    
    # Apply preprocessing if needed
    if args.preprocess_raw:
        df = preprocess_raw_data_if_needed(df)
    
    # Validate target column
    if args.target not in df.columns:
        logger.error(f"Available columns: {list(df.columns)}")
        raise ValueError(f"Target column '{args.target}' not found in training data")
    
    # Prepare features and target
    X = df.drop(columns=[args.target])
    y = df[args.target]
    
    # Handle non-numeric features (encode if necessary)
    categorical_columns = X.select_dtypes(include=['object']).columns
    if len(categorical_columns) > 0:
        logger.info(f"Encoding categorical columns: {list(categorical_columns)}")
        for col in categorical_columns:
            X[col] = LabelEncoder().fit_transform(X[col].astype(str))
    
    # Handle infinite and NaN values
    logger.info("Checking for infinite and NaN values...")
    
    # Replace infinite values with large but finite numbers
    X = X.replace([np.inf, -np.inf], [1e6, -1e6])
    
    # Fill NaN values with appropriate defaults
    numeric_columns = X.select_dtypes(include=[np.number]).columns
    X[numeric_columns] = X[numeric_columns].fillna(0)
    
    # Log any remaining issues
    inf_count = np.isinf(X.select_dtypes(include=[np.number])).sum().sum()
    nan_count = X.isnull().sum().sum()
    logger.info(f"After cleaning: {inf_count} infinite values, {nan_count} NaN values")
    
    # Encode target labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # Log class distribution
    class_counts = pd.Series(y_encoded).value_counts().sort_index()
    class_names = label_encoder.classes_
    logger.info("Class distribution:")
    for i, count in class_counts.items():
        logger.info(f"  {class_names[i]}: {count} samples ({count/len(y_encoded)*100:.1f}%)")
    
    # Split data
    X_train, X_val, y_train, y_val = train_test_split(
        X, y_encoded, test_size=args.test_size, random_state=args.random_state, 
        stratify=y_encoded
    )
    
    logger.info(f"Training set: {len(X_train)} samples")
    logger.info(f"Validation set: {len(X_val)} samples")
    
    # Compute class weights for imbalanced data
    sample_weights = None
    if args.use_class_weights:
        class_weights = compute_class_weight(
            'balanced', 
            classes=np.unique(y_encoded), 
            y=y_train
        )
        class_weight_dict = dict(zip(np.unique(y_encoded), class_weights))
        sample_weights = np.array([class_weight_dict[label] for label in y_train])
        logger.info(f"Computed class weights: {class_weight_dict}")
    
    # Configure XGBoost parameters
    xgb_params = {
        'max_depth': args.max_depth,
        'n_estimators': args.n_estimators,
        'learning_rate': args.learning_rate,
        'subsample': args.subsample,
        'colsample_bytree': args.colsample_bytree,
        'n_jobs': -1,
        'eval_metric': 'mlogloss' if len(np.unique(y_encoded)) > 2 else 'logloss',
        'tree_method': 'hist',
        'random_state': args.random_state
    }
    
    # Handle class imbalance
    if args.scale_pos_weight:
        xgb_params['scale_pos_weight'] = args.scale_pos_weight
    elif len(np.unique(y_encoded)) == 2:  # Binary classification
        neg_count = np.sum(y_train == 0)
        pos_count = np.sum(y_train == 1) 
        xgb_params['scale_pos_weight'] = neg_count / pos_count
        logger.info(f"Auto-computed scale_pos_weight: {xgb_params['scale_pos_weight']:.3f}")
    
    logger.info(f"XGBoost parameters: {xgb_params}")
    
    # Train model
    model = xgb.XGBClassifier(**xgb_params)
    
    logger.info("Training model...")
    eval_set = [(X_train, y_train), (X_val, y_val)]
    
    # Fit with early stopping
    fit_params = {
        'sample_weight': sample_weights,
        'eval_set': eval_set,
        'verbose': False
    }
    
    # Add early stopping if available (depends on XGBoost version)
    try:
        model.fit(X_train, y_train, **fit_params)
    except Exception as e:
        logger.warning(f"Training with eval_set failed: {e}")
        # Fallback to simple training
        model.fit(X_train, y_train, sample_weight=sample_weights)
    
    # Make predictions
    logger.info("Evaluating model...")
    train_preds = model.predict(X_train)
    val_preds = model.predict(X_val)
    val_probs = model.predict_proba(X_val)
    
    # Compute metrics
    train_report = classification_report(y_train, train_preds, 
                                       target_names=class_names, output_dict=True)
    val_report = classification_report(y_val, val_preds, 
                                     target_names=class_names, output_dict=True)
    
    # Compute confusion matrix
    val_cm = confusion_matrix(y_val, val_preds)
    
    # Compute AUC for multi-class (if applicable)
    val_auc = None
    if len(np.unique(y_encoded)) == 2:
        val_auc = roc_auc_score(y_val, val_probs[:, 1])
    elif len(np.unique(y_encoded)) > 2:
        val_auc = roc_auc_score(y_val, val_probs, multi_class='ovr', average='weighted')
    
    # Feature importance (convert to Python float for JSON serialization)
    feature_importance = {col: float(imp) for col, imp in zip(X.columns, model.feature_importances_)}
    top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Log results
    logger.info(f"Training accuracy: {train_report['accuracy']:.4f}")
    logger.info(f"Validation accuracy: {val_report['accuracy']:.4f}")
    if val_auc:
        logger.info(f"Validation AUC: {val_auc:.4f}")
    
    logger.info("Top 10 most important features:")
    for feature, importance in top_features:
        logger.info(f"  {feature}: {importance:.4f}")
    
    # Save model
    os.makedirs(args.model_dir, exist_ok=True)
    model_path = os.path.join(args.model_dir, "xgb_model.json")
    model.save_model(model_path)
    logger.info(f"Model saved to: {model_path}")
    
    # Save label encoder
    label_encoder_path = os.path.join(args.model_dir, "label_encoder.json")
    with open(label_encoder_path, 'w') as f:
        json.dump({
            'classes': label_encoder.classes_.tolist(),
            'class_mapping': {str(i): cls for i, cls in enumerate(label_encoder.classes_)}
        }, f)
    
    # Prepare comprehensive metrics output
    metrics = {
        'training_report': train_report,
        'validation_report': val_report,
        'confusion_matrix': val_cm.tolist(),
        'feature_importance': feature_importance,
        'top_features': dict(top_features),
        'model_params': xgb_params,
        'class_names': class_names.tolist(),
        'training_samples': len(X_train),
        'validation_samples': len(X_val),
        'num_features': len(X.columns)
    }
    
    if val_auc:
        metrics['validation_auc'] = val_auc
    
    # Save metrics
    os.makedirs(args.output_data_dir, exist_ok=True)
    metrics_path = os.path.join(args.output_data_dir, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2, cls=NumpyEncoder)
    logger.info(f"Metrics saved to: {metrics_path}")
    
    # Save detailed evaluation report
    eval_report_path = os.path.join(args.output_data_dir, "evaluation_report.txt")
    with open(eval_report_path, 'w') as f:
        f.write("Cyber Threat Detection Model Training Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Dataset: {len(df)} total samples\n")
        f.write(f"Features: {len(X.columns)}\n")
        f.write(f"Classes: {len(class_names)}\n\n")
        
        f.write("Class Distribution:\n")
        for i, count in class_counts.items():
            f.write(f"  {class_names[i]}: {count} samples ({count/len(y_encoded)*100:.1f}%)\n")
        f.write("\n")
        
        f.write(f"Training Accuracy: {train_report['accuracy']:.4f}\n")
        f.write(f"Validation Accuracy: {val_report['accuracy']:.4f}\n")
        if val_auc:
            f.write(f"Validation AUC: {val_auc:.4f}\n")
        f.write("\n")
        
        f.write("Per-Class Validation Results:\n")
        for class_name in class_names:
            if class_name in val_report:
                precision = val_report[class_name]['precision']
                recall = val_report[class_name]['recall']
                f1 = val_report[class_name]['f1-score']
                support = val_report[class_name]['support']
                f.write(f"  {class_name}: P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}, Support={support}\n")
        
        f.write("\nTop 10 Features:\n")
        for feature, importance in top_features:
            f.write(f"  {feature}: {importance:.4f}\n")
    
    logger.info(f"Training completed successfully!")
    logger.info(f"Evaluation report saved to: {eval_report_path}")


if __name__ == "__main__":
    main()
