#!/usr/bin/env python3

"""
Deploy large Lambda function via S3 upload
This approach handles larger packages by uploading to S3 first
"""

import os
import boto3
from pathlib import Path
import time


def upload_to_s3_and_deploy(zip_path, function_name, region='us-east-1'):
    """
    Upload Lambda package to S3 and then update Lambda function from S3
    """
    print(f"📤 Uploading large Lambda package via S3...")
    
    # Configuration
    account_id = os.environ.get('AWS_ACCOUNT_ID')
    if not account_id:
        raise ValueError("AWS_ACCOUNT_ID environment variable is required")
    
    bucket_name = os.environ.get('S3_MODEL_ARTIFACTS_BUCKET', f'cyber-threat-model-artifacts-{account_id}')
    s3_key = f'lambda-deployments/{function_name}-{int(time.time())}.zip'
    
    # Upload to S3
    s3_client = boto3.client('s3', region_name=region)
    lambda_client = boto3.client('lambda', region_name=region)
    
    try:
        print(f"📤 Uploading to s3://{bucket_name}/{s3_key}")
        
        with open(zip_path, 'rb') as f:
            s3_client.upload_fileobj(
                f, 
                bucket_name, 
                s3_key,
                ExtraArgs={'ContentType': 'application/zip'}
            )
        
        print(f"✅ Upload to S3 completed")
        
        # Update Lambda function from S3
        print(f"🚀 Updating Lambda function from S3...")
        
        response = lambda_client.update_function_code(
            FunctionName=function_name,
            S3Bucket=bucket_name,
            S3Key=s3_key
        )
        
        print(f"✅ Lambda function updated successfully!")
        print(f"   Function ARN: {response['FunctionArn']}")
        print(f"   Runtime: {response['Runtime']}")
        print(f"   Code size: {response['CodeSize']} bytes")
        print(f"   Last modified: {response['LastModified']}")
        
        # Clean up S3 object after successful deployment
        print(f"🧹 Cleaning up S3 deployment artifact...")
        s3_client.delete_object(Bucket=bucket_name, Key=s3_key)
        print(f"✅ S3 cleanup completed")
        
        return response
        
    except Exception as e:
        print(f"❌ Failed to deploy via S3: {e}")
        return None


def main():
    """Main deployment function"""
    
    # Configuration
    project_root = Path(__file__).parent.parent
    zip_path = project_root / 'build' / 'lambda_deployment.zip'
    function_name = 'cyber-threat-detector-sagemaker'
    
    # Check if deployment package exists
    if not zip_path.exists():
        print(f"❌ Deployment package not found: {zip_path}")
        print("   Run the main deployment script first to build the package.")
        return
    
    print(f"🚀 Deploying Lambda function via S3...")
    print(f"   Package: {zip_path}")
    print(f"   Function: {function_name}")
    
    # Upload and deploy
    result = upload_to_s3_and_deploy(str(zip_path), function_name)
    
    if result:
        print(f"✅ Lambda deployment completed successfully!")
        print(f"   You can now test the Lambda function.")
    else:
        print(f"❌ Lambda deployment failed")


if __name__ == '__main__':
    main()