#!/usr/bin/env python3

"""
Simplified Lambda Function for Cyber Threat Detection using SageMaker Batch Transform
This version avoids pandas/numpy to reduce compatibility issues
"""

import json
import boto3
import os
import tempfile
import time
from datetime import datetime
import urllib.parse
import uuid
import csv
import io


def extract_features(log_entry):
    """
    Extract the same 36 features used during training
    Uses only built-in Python functions to avoid dependencies
    """
    
    def safe_int(value, default=0):
        try:
            return int(float(value)) if value else default
        except (ValueError, TypeError):
            return default
    
    def safe_float(value, default=0.0):
        try:
            return float(value) if value else default
        except (ValueError, TypeError):
            return default
    
    def hash_ip(ip):
        if not ip:
            return 0
        return hash(ip) % (2**31)
    
    # Extract basic fields
    source_ip = log_entry.get('source_ip', '')
    dest_ip = log_entry.get('dest_ip', '')
    source_port = safe_int(log_entry.get('source_port', 0))
    dest_port = safe_int(log_entry.get('dest_port', 0))
    protocol = log_entry.get('protocol', 'tcp')
    bytes_in = safe_int(log_entry.get('bytes_in', 0))
    bytes_out = safe_int(log_entry.get('bytes_out', 0))
    
    # Extract timestamp
    timestamp = log_entry.get('timestamp', datetime.now().isoformat())
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except:
        dt = datetime.now()
    
    # URI and User Agent for web analysis
    uri = log_entry.get('uri', '')
    user_agent = log_entry.get('user_agent', '')
    
    # Feature extraction (matching training features exactly)
    features = {}
    
    # 1. Basic network features
    features['source_ip_hash'] = hash_ip(source_ip)
    features['dest_ip_hash'] = hash_ip(dest_ip)
    features['source_port'] = source_port
    features['dest_port'] = dest_port
    features['bytes_in'] = bytes_in
    features['bytes_out'] = bytes_out
    features['total_bytes'] = bytes_in + bytes_out
    features['bytes_ratio'] = bytes_out / max(bytes_in, 1) if bytes_in > 0 else 0
    
    # 2. Protocol analysis
    features['protocol_numeric'] = {'tcp': 6, 'udp': 17, 'icmp': 1}.get(protocol.lower(), 0)
    
    # 3. Time-based features
    features['hour_of_day'] = dt.hour
    features['day_of_week'] = dt.weekday()
    features['is_business_hours'] = 1 if 9 <= dt.hour <= 17 and dt.weekday() < 5 else 0
    features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
    
    # 4. Port categorization
    features['is_well_known_port'] = 1 if dest_port <= 1024 else 0
    features['is_high_port'] = 1 if dest_port >= 49152 else 0
    features['is_web_port'] = 1 if dest_port in [80, 443, 8080, 8443] else 0
    features['is_ssh_port'] = 1 if dest_port == 22 else 0
    features['is_database_port'] = 1 if dest_port in [3306, 5432, 1433, 1521] else 0
    features['is_high_risk_port'] = 1 if dest_port in [23, 135, 139, 445, 1433, 3389] else 0
    
    # 5. IP analysis
    features['source_is_private'] = 1 if source_ip.startswith(('10.', '192.168.', '172.')) else 0
    features['dest_is_private'] = 1 if dest_ip.startswith(('10.', '192.168.', '172.')) else 0
    features['source_is_internal'] = features['source_is_private']
    features['dest_is_internal'] = features['dest_is_private']
    features['is_external_connection'] = 1 if features['source_is_private'] and not features['dest_is_private'] else 0
    
    # 6. Traffic analysis
    features['traffic_symmetry'] = min(bytes_in, bytes_out) / max(bytes_in, bytes_out, 1)
    features['is_high_volume'] = 1 if (bytes_in + bytes_out) > 1000000 else 0
    features['is_low_volume'] = 1 if (bytes_in + bytes_out) < 1000 else 0
    features['is_upload_heavy'] = 1 if bytes_out > bytes_in * 2 else 0
    features['is_download_heavy'] = 1 if bytes_in > bytes_out * 2 else 0
    
    # 7. Attack detection patterns
    features['potential_dos'] = 1 if bytes_in < 100 and source_port > 1024 else 0
    features['potential_sql_injection'] = 1 if any(x in uri.lower() for x in ['select', 'union', 'drop', 'insert', "'", '"']) else 0
    features['potential_xss'] = 1 if any(x in uri.lower() for x in ['<script', 'javascript:', 'onerror=']) else 0
    features['suspicious_user_agent'] = 1 if any(x in user_agent.lower() for x in ['bot', 'crawler', 'scanner', 'nmap']) else 0
    
    # 8. Connection patterns (simplified for now)
    features['repeated_connections'] = 0
    features['has_failed_attempts'] = 0
    
    # 9. Geolocation risk
    features['ip_geolocation_risk'] = 1 if not features['dest_is_private'] else 0
    
    # 10. Port categorization
    port_categories = {
        'web': [80, 443, 8080, 8443],
        'mail': [25, 110, 143, 993, 995],
        'database': [3306, 5432, 1433, 1521],
        'remote': [22, 23, 3389, 5900],
        'file': [21, 22, 445, 2049]
    }
    
    features['port_category'] = 0
    for category, ports in port_categories.items():
        if dest_port in ports:
            features['port_category'] = hash(category) % 100
            break
    
    return features


def create_batch_transform_input(features_list):
    """
    Create input CSV for SageMaker Batch Transform using built-in csv module
    """
    # Feature names in correct order (matching training)
    feature_names = [
        'source_ip_hash', 'dest_ip_hash', 'source_port', 'dest_port', 'bytes_in', 'bytes_out',
        'total_bytes', 'bytes_ratio', 'protocol_numeric', 'hour_of_day', 'day_of_week',
        'is_business_hours', 'is_weekend', 'is_well_known_port', 'is_high_port', 'is_web_port',
        'is_ssh_port', 'is_database_port', 'is_high_risk_port', 'source_is_private',
        'dest_is_private', 'source_is_internal', 'dest_is_internal', 'is_external_connection',
        'traffic_symmetry', 'is_high_volume', 'is_low_volume', 'is_upload_heavy', 'is_download_heavy',
        'potential_dos', 'potential_sql_injection', 'potential_xss', 'suspicious_user_agent',
        'repeated_connections', 'has_failed_attempts', 'ip_geolocation_risk', 'port_category'
    ]
    
    # Create CSV content using built-in csv module
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write data rows (no headers for SageMaker)
    for features in features_list:
        row = []
        for name in feature_names:
            row.append(features.get(name, 0))
        writer.writerow(row)
    
    return output.getvalue()


def run_sagemaker_batch_transform(input_data, job_name):
    """
    Run SageMaker Batch Transform job for inference
    """
    print(f"🚀 Starting SageMaker Batch Transform: {job_name}")
    
    # Configuration
    account_id = os.environ.get('AWS_ACCOUNT_ID')
    if not account_id:
        raise ValueError("AWS_ACCOUNT_ID environment variable is required")
    
    region = 'us-east-1'
    model_name = os.environ.get('SAGEMAKER_MODEL_NAME', 'cyber-threat-detector-model')  # Use latest model
    role_arn = f'arn:aws:iam::{account_id}:role/CyberThreatDetectionSageMakerRole'
    
    # S3 paths
    input_bucket = os.environ.get('S3_PROCESSED_DATA_BUCKET', f'cyber-threat-processed-data-{account_id}')
    output_bucket = os.environ.get('S3_MODEL_ARTIFACTS_BUCKET', f'cyber-threat-model-artifacts-{account_id}')
    
    input_key = f'batch-transform-input/{job_name}.csv'
    output_prefix = f'batch-transform-output/{job_name}/'
    
    # Upload input data to S3
    s3_client = boto3.client('s3')
    
    print(f"📤 Uploading input data to s3://{input_bucket}/{input_key}")
    s3_client.put_object(
        Bucket=input_bucket,
        Key=input_key,
        Body=input_data,
        ContentType='text/csv'
    )
    
    # Create batch transform job
    sm_client = boto3.client('sagemaker', region_name=region)
    
    try:
        response = sm_client.create_transform_job(
            TransformJobName=job_name,
            ModelName=model_name,
            TransformInput={
                'DataSource': {
                    'S3DataSource': {
                        'S3DataType': 'S3Prefix',
                        'S3Uri': f's3://{input_bucket}/{input_key}'
                    }
                },
                'ContentType': 'text/csv',
                'SplitType': 'Line'
            },
            TransformOutput={
                'S3OutputPath': f's3://{output_bucket}/{output_prefix}',
                'AssembleWith': 'Line'
            },
            TransformResources={
                'InstanceType': 'ml.t2.medium',  # Use available quota
                'InstanceCount': 1
            }
        )
        
        print(f"✅ Batch transform job created: {response['TransformJobArn']}")
        
        # Wait for completion (with timeout)
        max_wait_time = 300  # 5 minutes
        wait_time = 0
        
        while wait_time < max_wait_time:
            status_response = sm_client.describe_transform_job(TransformJobName=job_name)
            status = status_response['TransformJobStatus']
            
            print(f"⏱️  Transform job status: {status}")
            
            if status == 'Completed':
                print("✅ Batch transform completed successfully!")
                
                # Download results
                output_key = f"{output_prefix}{job_name}.csv.out"
                
                try:
                    result_obj = s3_client.get_object(Bucket=output_bucket, Key=output_key)
                    result_data = result_obj['Body'].read().decode('utf-8')
                    
                    print(f"📥 Downloaded results: {len(result_data)} bytes")
                    return result_data.strip().split('\n')
                    
                except Exception as e:
                    print(f"⚠️  Failed to download results: {e}")
                    return None
                    
            elif status == 'Failed':
                failure_reason = status_response.get('FailureReason', 'Unknown error')
                print(f"❌ Batch transform failed: {failure_reason}")
                return None
            
            # Wait before checking again
            time.sleep(10)
            wait_time += 10
        
        print("⏰ Batch transform timed out")
        return None
        
    except Exception as e:
        print(f"❌ Failed to create batch transform job: {e}")
        return None


def interpret_results(raw_results):
    """
    Convert SageMaker batch transform results to threat information
    """
    threat_types = ['normal', 'dos_attack', 'port_scan', 'sql_injection', 'brute_force', 'data_exfiltration']
    
    interpreted_results = []
    
    for result_line in raw_results:
        try:
            # Parse the result (format depends on your model output)
            if result_line.strip():
                # Assuming the result is a class prediction (0-5)
                prediction = int(float(result_line.strip()))
                threat_type = threat_types[min(prediction, len(threat_types)-1)]
                
                result = {
                    'threat_detected': threat_type != 'normal',
                    'threat_type': threat_type,
                    'raw_prediction': prediction,
                    'confidence': 1.0  # Batch transform doesn't return probabilities by default
                }
                
                interpreted_results.append(result)
                
        except Exception as e:
            print(f"⚠️  Error interpreting result '{result_line}': {e}")
            interpreted_results.append({
                'threat_detected': False,
                'threat_type': 'unknown',
                'confidence': 0.0,
                'error': str(e)
            })
    
    return interpreted_results


def send_alert(threat_info, log_entry):
    """Send alert via SNS if threat detected"""
    if not threat_info['threat_detected']:
        return
    
    try:
        sns_client = boto3.client('sns')
        topic_arn = os.environ.get('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:YOUR_AWS_ACCOUNT_ID:cyber-threat-alerts')
        
        # Create alert message
        message = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'THREAT_DETECTED_SAGEMAKER',
            'threat_type': threat_info['threat_type'],
            'confidence': threat_info['confidence'],
            'source_ip': log_entry.get('source_ip', 'unknown'),
            'dest_ip': log_entry.get('dest_ip', 'unknown'),
            'dest_port': log_entry.get('dest_port', 'unknown'),
            'details': threat_info
        }
        
        # Send notification
        response = sns_client.publish(
            TopicArn=topic_arn,
            Subject=f'🚨 SageMaker Threat Detected: {threat_info["threat_type"].upper()}',
            Message=json.dumps(message, indent=2)
        )
        
        print(f"✅ Alert sent: {response['MessageId']}")
        
    except Exception as e:
        print(f"❌ Failed to send alert: {e}")


def lambda_handler(event, context):
    """
    Main Lambda handler using SageMaker Batch Transform for inference
    Simplified version without pandas/numpy dependencies
    """
    
    print(f"🔍 Processing event with SageMaker: {json.dumps(event, default=str)}")
    
    results = []
    
    try:
        log_entries = []
        
        # Handle S3 event
        if 'Records' in event:
            for record in event['Records']:
                if 's3' in record:
                    # S3 event - process uploaded file
                    bucket = record['s3']['bucket']['name']
                    key = urllib.parse.unquote_plus(record['s3']['object']['key'])
                    
                    print(f"📁 Processing S3 file: s3://{bucket}/{key}")
                    
                    # Download and process file
                    s3_client = boto3.client('s3')
                    
                    # Download file to temp location
                    local_path = f"/tmp/{os.path.basename(key)}"
                    s3_client.download_file(bucket, key, local_path)
                    
                    # Process file (assuming CSV format)
                    if key.endswith('.csv'):
                        with open(local_path, 'r') as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                log_entries.append(row)
                    
                    # Clean up temp file
                    os.remove(local_path)
                    
        else:
            # Direct invocation with log data
            log_entries = event.get('log_entries', [event])
        
        print(f"📊 Processing {len(log_entries)} log entries")
        
        # Extract features for all log entries
        features_list = []
        for log_entry in log_entries:
            features = extract_features(log_entry)
            features_list.append(features)
        
        # Create batch transform input
        batch_input = create_batch_transform_input(features_list)
        
        # Generate unique job name
        job_name = f"threat-detection-{int(datetime.now().timestamp())}-{uuid.uuid4().hex[:8]}"
        
        # Run SageMaker batch transform
        batch_results = run_sagemaker_batch_transform(batch_input, job_name)
        
        if batch_results:
            # Interpret results
            threat_results = interpret_results(batch_results)
            
            # Combine with original log entries and send alerts
            for i, (log_entry, threat_info) in enumerate(zip(log_entries, threat_results)):
                # Send alert if threat detected
                send_alert(threat_info, log_entry)
                
                results.append({
                    'log_entry': log_entry,
                    'features': features_list[i] if i < len(features_list) else {},
                    'prediction': threat_info
                })
        else:
            print("❌ SageMaker batch transform failed")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': 'SageMaker batch transform failed',
                    'message': 'Threat detection could not be completed',
                    'job_name': job_name
                })
            }
        
        print(f"✅ Processed {len(results)} log entries via SageMaker")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Processed {len(results)} log entries via SageMaker Batch Transform',
                'results': results,
                'threats_detected': sum(1 for r in results if r['prediction']['threat_detected']),
                'sagemaker_job_name': job_name
            }, default=str)
        }
        
    except Exception as e:
        print(f"❌ Lambda execution failed: {e}")
        import traceback
        traceback.print_exc()
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'SageMaker threat detection failed'
            })
        }