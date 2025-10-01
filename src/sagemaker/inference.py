#!/usr/bin/env python3

"""
Custom inference script for XGBoost SageMaker endpoint
Handles model loading and prediction for cyber threat detection
"""

import os
import json
import joblib
import xgboost as xgb
import numpy as np
import pandas as pd


def model_fn(model_dir):
    """
    Load the XGBoost model from the model directory.
    This function is called by SageMaker when the endpoint starts.
    """
    print(f"Loading model from: {model_dir}")
    
    # Find the model file
    model_files = [f for f in os.listdir(model_dir) if f.endswith(('.json', '.model', '.pkl'))]
    
    if not model_files:
        raise RuntimeError(f"No model files found in {model_dir}")
    
    model_path = os.path.join(model_dir, model_files[0])
    print(f"Found model file: {model_path}")
    
    try:
        # Load XGBoost model
        model = xgb.XGBClassifier()
        model.load_model(model_path)
        print("✅ XGBoost model loaded successfully")
        return model
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        # Try alternative loading methods
        try:
            model = xgb.Booster()
            model.load_model(model_path)
            print("✅ XGBoost Booster loaded successfully")
            return model
        except Exception as e2:
            print(f"❌ All loading methods failed: {e2}")
            raise e2


def input_fn(request_body, request_content_type):
    """
    Parse input data for prediction.
    SageMaker calls this function to deserialize the input data.
    """
    print(f"Content type: {request_content_type}")
    print(f"Request body type: {type(request_body)}")
    
    if request_content_type == 'application/json':
        # Parse JSON input
        input_data = json.loads(request_body)
        print(f"Parsed JSON input: {input_data}")
        
        if 'instances' in input_data:
            # Multiple instances format
            return np.array(input_data['instances'])
        elif 'features' in input_data:
            # Single instance with named features
            return np.array([list(input_data['features'].values())])
        else:
            # Direct array format
            return np.array(input_data)
            
    elif request_content_type == 'text/csv':
        # Parse CSV input
        from io import StringIO
        input_data = pd.read_csv(StringIO(request_body), header=None)
        return input_data.values
        
    else:
        raise ValueError(f"Unsupported content type: {request_content_type}")


def predict_fn(input_data, model):
    """
    Make predictions using the loaded model.
    SageMaker calls this function for each prediction request.
    """
    print(f"Input data shape: {input_data.shape}")
    print(f"Input data type: {type(input_data)}")
    
    try:
        # Ensure input is in the right format
        if len(input_data.shape) == 1:
            input_data = input_data.reshape(1, -1)
        
        # Make predictions
        if hasattr(model, 'predict_proba'):
            # XGBClassifier
            predictions = model.predict(input_data)
            probabilities = model.predict_proba(input_data)
        else:
            # XGBoost Booster
            dmatrix = xgb.DMatrix(input_data)
            probabilities = model.predict(dmatrix)
            predictions = np.argmax(probabilities, axis=1)
        
        print(f"Predictions shape: {predictions.shape}")
        print(f"Probabilities shape: {probabilities.shape}")
        
        return {
            'predictions': predictions.tolist(),
            'probabilities': probabilities.tolist()
        }
        
    except Exception as e:
        print(f"❌ Prediction failed: {e}")
        return {
            'error': str(e),
            'predictions': [],
            'probabilities': []
        }


def output_fn(prediction, accept):
    """
    Serialize the prediction result.
    SageMaker calls this function to format the output.
    """
    print(f"Accept type: {accept}")
    
    if accept == 'application/json':
        return json.dumps(prediction), accept
    elif accept == 'text/csv':
        # Convert to CSV format
        if 'predictions' in prediction:
            import io
            output = io.StringIO()
            pd.DataFrame({
                'prediction': prediction['predictions'],
                'probability': [max(probs) for probs in prediction['probabilities']]
            }).to_csv(output, index=False)
            return output.getvalue(), accept
        else:
            return json.dumps(prediction), 'application/json'
    else:
        return json.dumps(prediction), 'application/json'


# Threat type mapping (matches training labels)
THREAT_TYPES = [
    'normal',
    'dos_attack', 
    'port_scan',
    'sql_injection',
    'brute_force',
    'data_exfiltration'
]

def interpret_prediction(prediction_result):
    """
    Convert raw predictions to threat information
    """
    try:
        predictions = prediction_result['predictions']
        probabilities = prediction_result['probabilities']
        
        results = []
        for pred, probs in zip(predictions, probabilities):
            threat_type = THREAT_TYPES[min(int(pred), len(THREAT_TYPES)-1)]
            confidence = max(probs)
            
            result = {
                'threat_detected': threat_type != 'normal',
                'threat_type': threat_type,
                'confidence': float(confidence),
                'raw_prediction': int(pred),
                'all_probabilities': {THREAT_TYPES[i]: float(prob) for i, prob in enumerate(probs)}
            }
            results.append(result)
        
        return results
        
    except Exception as e:
        return [{'error': str(e), 'threat_detected': False, 'threat_type': 'unknown', 'confidence': 0.0}]