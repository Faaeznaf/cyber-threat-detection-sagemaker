#!/usr/bin/env python3

"""
Deploy Lambda function with dependencies properly packaged
This script creates a deployment package with all required dependencies
"""

import os
import sys
import subprocess
import zipfile
import tempfile
import shutil
from pathlib import Path
import boto3


def build_lambda_package(lambda_function_path, requirements_path, output_dir):
    """
    Build a Lambda deployment package with dependencies
    """
    print(f"📦 Building Lambda package for {lambda_function_path}")
    
    # Create temporary directory for building
    with tempfile.TemporaryDirectory() as temp_dir:
        package_dir = os.path.join(temp_dir, 'package')
        os.makedirs(package_dir)
        
        # Install dependencies to package directory
        print(f"📥 Installing dependencies from {requirements_path}")
        
        pip_command = [
            sys.executable, '-m', 'pip', 'install',
            '-r', requirements_path,
            '-t', package_dir,
            '--no-deps',  # Avoid conflicts
            '--platform', 'linux_x86_64',
            '--implementation', 'cp',
            '--python-version', '3.9',
            '--only-binary=:all:'
        ]
        
        try:
            result = subprocess.run(pip_command, capture_output=True, text=True, check=True)
            print(f"✅ Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
            
            # Try fallback without platform-specific flags
            print("🔄 Retrying with fallback method...")
            pip_fallback = [
                sys.executable, '-m', 'pip', 'install',
                '-r', requirements_path,
                '-t', package_dir
            ]
            subprocess.run(pip_fallback, check=True)
        
        # Copy Lambda function code
        print(f"📋 Copying Lambda function code")
        lambda_filename = os.path.basename(lambda_function_path)
        shutil.copy2(lambda_function_path, os.path.join(package_dir, 'lambda_function.py'))
        
        # Create deployment zip
        zip_path = os.path.join(output_dir, 'lambda_deployment.zip')
        
        print(f"🗜️  Creating deployment package: {zip_path}")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(package_dir):
                # Skip __pycache__ directories
                dirs[:] = [d for d in dirs if d != '__pycache__']
                
                for file in files:
                    if not file.endswith('.pyc'):
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, package_dir)
                        zf.write(file_path, arcname)
        
        # Check size
        size_mb = os.path.getsize(zip_path) / (1024 * 1024)
        print(f"📊 Package size: {size_mb:.2f} MB")
        
        if size_mb > 50:
            print("⚠️  Warning: Package size is large. Consider optimizing dependencies.")
        
        return zip_path


def update_lambda_function(function_name, zip_path, region='us-east-1'):
    """
    Update existing Lambda function with new deployment package
    """
    print(f"🚀 Updating Lambda function: {function_name}")
    
    lambda_client = boto3.client('lambda', region_name=region)
    
    try:
        # Read the zip file
        with open(zip_path, 'rb') as f:
            zip_content = f.read()
        
        # Update function code
        response = lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_content
        )
        
        print(f"✅ Lambda function updated successfully")
        print(f"   Function ARN: {response['FunctionArn']}")
        print(f"   Runtime: {response['Runtime']}")
        print(f"   Code size: {response['CodeSize']} bytes")
        
        return response
        
    except Exception as e:
        print(f"❌ Failed to update Lambda function: {e}")
        return None


def main():
    """Main deployment function"""
    
    # Configuration
    project_root = Path(__file__).parent.parent
    lambda_function_path = project_root / 'src' / 'lambda' / 'threat_detector_sagemaker_simple.py'
    requirements_path = project_root / 'requirements-lambda-simple.txt'
    output_dir = project_root / 'build'
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Validate files exist
    if not lambda_function_path.exists():
        print(f"❌ Lambda function not found: {lambda_function_path}")
        return
    
    if not requirements_path.exists():
        print(f"❌ Requirements file not found: {requirements_path}")
        return
    
    print("🔧 Deploying Lambda function with dependencies...")
    print(f"   Lambda function: {lambda_function_path}")
    print(f"   Requirements: {requirements_path}")
    print(f"   Output directory: {output_dir}")
    
    # Build package
    zip_path = build_lambda_package(
        str(lambda_function_path),
        str(requirements_path),
        str(output_dir)
    )
    
    if not zip_path or not os.path.exists(zip_path):
        print("❌ Failed to create deployment package")
        return
    
    # Update Lambda function
    function_name = 'cyber-threat-detector-sagemaker'
    result = update_lambda_function(function_name, zip_path)
    
    if result:
        print(f"✅ Deployment completed successfully!")
        print(f"   You can now test the Lambda function with proper dependencies.")
    else:
        print(f"❌ Deployment failed")


if __name__ == '__main__':
    main()