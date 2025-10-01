#!/usr/bin/env python3

"""
Launch SageMaker Processing Job for Cyber Threat Detection Training
"""

import boto3
import os
import sagemaker
from sagemaker.processing import ProcessingInput, ProcessingOutput
from sagemaker.sklearn.processing import SKLearnProcessor
import time
from datetime import datetime

def main():
    """Launch the processing job"""
    print("🚀 Launching SageMaker Processing Job for Cyber Threat Detection")
    
    # AWS Configuration
    region = 'us-east-1'
    account_id = os.environ.get('AWS_ACCOUNT_ID', 'YOUR_AWS_ACCOUNT_ID')
    
    # S3 Configuration
    raw_bucket = f'cyber-threat-detection-raw-data-{account_id}'
    processed_bucket = f'cyber-threat-detection-processed-data-{account_id}'
    model_bucket = f'cyber-threat-detection-model-artifacts-{account_id}'
    
    # IAM Role
    role_arn = f'arn:aws:iam::{account_id}:role/CyberThreatDetectionSageMakerRole'
    
    # Job Configuration
    job_name = f'cyber-threat-processing-{int(time.time())}'
    
    print(f"🏷️  Job Name: {job_name}")
    print(f"🎯 Instance: ml.t3.large")
    print(f"📦 Buckets: {processed_bucket}")
    
    # Initialize SageMaker session
    sagemaker_session = sagemaker.Session()
    
    # Create SKLearn processor (includes pandas, numpy, sklearn, xgboost)
    processor = SKLearnProcessor(
        framework_version='0.23-1',
        role=role_arn,
        instance_type='ml.t3.large',
        instance_count=1,
        base_job_name='cyber-threat-processing',
        sagemaker_session=sagemaker_session
    )
    
    print("✅ Processor created successfully")
    
    # Define input and output channels
    inputs = [
        ProcessingInput(
            source=f's3://{processed_bucket}/train/processed_network_logs.csv',
            destination='/opt/ml/processing/input',
            input_name='training-data'
        )
    ]
    
    outputs = [
        ProcessingOutput(
            source='/opt/ml/processing/output',
            destination=f's3://{model_bucket}/processing-output',
            output_name='metrics'
        ),
        ProcessingOutput(
            source='/opt/ml/processing/model',
            destination=f's3://{model_bucket}/model',
            output_name='model'
        )
    ]
    
    print("📋 Input/Output channels configured")
    
    # Submit the processing job
    print("🎬 Starting processing job...")
    print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        processor.run(
            code='src/processing/process_train.py',
            inputs=inputs,
            outputs=outputs,
            arguments=['--job-name', job_name]
        )
        
        print("✅ Processing job submitted successfully!")
        print(f"🔍 Monitor progress at: https://console.aws.amazon.com/sagemaker/home?region={region}#/processing-jobs/{job_name}")
        
        # Get job details
        sm_client = boto3.client('sagemaker', region_name=region)
        
        print("\n📊 Job Status:")
        while True:
            response = sm_client.describe_processing_job(ProcessingJobName=job_name)
            status = response['ProcessingJobStatus']
            
            print(f"⏱️  {datetime.now().strftime('%H:%M:%S')} - Status: {status}")
            
            if status in ['Completed', 'Failed', 'Stopped']:
                break
                
            time.sleep(30)  # Check every 30 seconds
        
        if status == 'Completed':
            print("🎉 Processing job completed successfully!")
            
            # Download results
            print("📥 Downloading results...")
            
            # List outputs
            print("📋 Output artifacts:")
            print(f"  📈 Metrics: s3://{model_bucket}/processing-output/")
            print(f"  🤖 Model: s3://{model_bucket}/model/")
            
            # Download key files
            s3 = boto3.client('s3')
            
            try:
                # Download metrics
                s3.download_file(
                    model_bucket, 
                    'processing-output/metrics.json', 
                    'artifacts/processing_metrics.json'
                )
                print("✅ Downloaded metrics.json")
                
                # Download feature importance
                s3.download_file(
                    model_bucket, 
                    'processing-output/feature_importance.csv', 
                    'artifacts/feature_importance.csv'
                )
                print("✅ Downloaded feature_importance.csv")
                
                # Download model
                s3.download_file(
                    model_bucket, 
                    'model/xgb_model.json', 
                    'artifacts/xgb_model.json'
                )
                print("✅ Downloaded xgb_model.json")
                
            except Exception as e:
                print(f"⚠️  Download error (files may still be uploading): {e}")
                print("🔄 You can download manually from S3 console")
                
        else:
            print(f"❌ Processing job failed with status: {status}")
            
            # Get failure reason
            if 'FailureReason' in response:
                print(f"💥 Failure reason: {response['FailureReason']}")
                
    except Exception as e:
        print(f"❌ Error submitting processing job: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    if success:
        print("\n🎯 Next steps:")
        print("1. Check artifacts/ directory for downloaded results")
        print("2. Review metrics.json for model performance")
        print("3. Examine feature_importance.csv for insights")
        print("4. Deploy model for real-time inference")
    else:
        print("\n❌ Job failed. Check logs for details.")