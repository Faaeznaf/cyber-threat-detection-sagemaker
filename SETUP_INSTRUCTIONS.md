# Setup Instructions

## 🚀 Quick Start Guide

This guide will help you configure the cyber threat detection pipeline with your own AWS account.

## Prerequisites

- AWS Account with appropriate permissions
- Python 3.9 or later
- AWS CLI installed and configured

## 1. Environment Setup

### Clone and Configure Environment Variables

```bash
# Copy the environment template
cp .env.template .env
```

Edit the `.env` file and replace the following values:

```bash
# Replace with your actual AWS account ID (12-digit number)
AWS_ACCOUNT_ID=123456789012

# Customize bucket names if desired (optional)
S3_RAW_DATA_BUCKET=cyber-threat-detection-raw-data-123456789012
S3_PROCESSED_DATA_BUCKET=cyber-threat-detection-processed-data-123456789012
S3_MODEL_ARTIFACTS_BUCKET=cyber-threat-detection-model-artifacts-123456789012

# Customize resource names if desired (optional)
SAGEMAKER_MODEL_NAME=cyber-threat-detector-model
LAMBDA_FUNCTION_NAME=cyber-threat-detector-sagemaker
```

### Install Dependencies

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # On Windows
# source .venv/bin/activate  # On Linux/Mac

# Install requirements
pip install -r requirements.txt
```

## 2. AWS Infrastructure Setup

### Create S3 Buckets

```bash
# Set environment variables from your .env file
$env:AWS_ACCOUNT_ID = "123456789012"  # Replace with your account ID

# Create S3 buckets
aws s3 mb s3://cyber-threat-detection-raw-data-${AWS_ACCOUNT_ID}
aws s3 mb s3://cyber-threat-detection-processed-data-${AWS_ACCOUNT_ID}
aws s3 mb s3://cyber-threat-detection-model-artifacts-${AWS_ACCOUNT_ID}

# Enable versioning (recommended)
aws s3api put-bucket-versioning --bucket cyber-threat-detection-raw-data-${AWS_ACCOUNT_ID} --versioning-configuration Status=Enabled
aws s3api put-bucket-versioning --bucket cyber-threat-detection-processed-data-${AWS_ACCOUNT_ID} --versioning-configuration Status=Enabled
aws s3api put-bucket-versioning --bucket cyber-threat-detection-model-artifacts-${AWS_ACCOUNT_ID} --versioning-configuration Status=Enabled
```

### Create IAM Role for SageMaker

```bash
# Create trust policy
aws iam create-role \
  --role-name CyberThreatDetectionSageMakerRole \
  --assume-role-policy-document file://aws/sagemaker-trust-policy.json

# Attach permissions policy
aws iam put-role-policy \
  --role-name CyberThreatDetectionSageMakerRole \
  --policy-name CyberThreatDetectionSageMakerPolicy \
  --policy-document file://aws/sagemaker-permissions-policy.json

# Attach AWS managed policies
aws iam attach-role-policy \
  --role-name CyberThreatDetectionSageMakerRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonSageMakerFullAccess
```

**Note:** Before running the IAM commands, update the `aws/sagemaker-permissions-policy.json` file to replace `YOUR_AWS_ACCOUNT_ID` with your actual AWS account ID.

### Create SNS Topic for Alerts

```bash
# Create SNS topic
aws sns create-topic --name cyber-threat-alerts

# Subscribe to email notifications (optional)
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:${AWS_ACCOUNT_ID}:cyber-threat-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com
```

## 3. Upload Sample Data

```bash
# Upload sample network logs
python scripts/generate_threat_data.py
aws s3 cp data/raw/network_logs.csv s3://cyber-threat-detection-raw-data-${AWS_ACCOUNT_ID}/
```

## 4. Test the Pipeline

### Run Data Processing

```bash
# Create processed training data
python scripts/create_processed_training_data.py

# Upload processed data
aws s3 cp data/train/processed_network_logs.csv s3://cyber-threat-detection-processed-data-${AWS_ACCOUNT_ID}/train/
```

### Train the Model

```bash
# Run training script locally (for testing)
python -m src.training.train \
  --train ./data/train \
  --model-dir ./artifacts/model \
  --output-data-dir ./artifacts/output

# Or run SageMaker processing job (requires proper AWS setup)
python scripts/run_processing_job.py
```

## 5. Deploy Lambda Function

### Prepare Lambda Package

```bash
# Build deployment package
python scripts/deploy_lambda_with_deps.py
```

### Create Lambda Function

```bash
# Create Lambda function (adjust role ARN with your account ID)
aws lambda create-function \
  --function-name cyber-threat-detector-sagemaker \
  --runtime python3.9 \
  --role arn:aws:iam::${AWS_ACCOUNT_ID}:role/CyberThreatDetectionSageMakerRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://build/lambda_deployment.zip \
  --timeout 300 \
  --memory-size 512

# Set environment variables for Lambda
aws lambda update-function-configuration \
  --function-name cyber-threat-detector-sagemaker \
  --environment Variables="{AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID},SAGEMAKER_MODEL_NAME=cyber-threat-detector-model,SNS_TOPIC_ARN=arn:aws:sns:us-east-1:${AWS_ACCOUNT_ID}:cyber-threat-alerts}"
```

## 6. Configure S3 Event Triggers

```bash
# Update s3-notification-config.json with your account ID
# Then configure S3 to trigger Lambda on new uploads
aws s3api put-bucket-notification-configuration \
  --bucket cyber-threat-detection-raw-data-${AWS_ACCOUNT_ID} \
  --notification-configuration file://s3-notification-config.json
```

## 7. Verification

### Test the Complete Pipeline

```bash
# Upload a test file to trigger the pipeline
python scripts/generate_threat_data.py --output test_data.csv --count 50
aws s3 cp test_data.csv s3://cyber-threat-detection-raw-data-${AWS_ACCOUNT_ID}/incoming-logs/
```

### Monitor Logs

```bash
# Watch CloudWatch logs for Lambda execution
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/cyber-threat-detector

# View specific log stream
aws logs get-log-events \
  --log-group-name /aws/lambda/cyber-threat-detector-sagemaker \
  --log-stream-name [LOG_STREAM_NAME]
```

## 🔒 Security Notes

1. **Never commit your `.env` file** - it contains sensitive information
2. **Use IAM roles with minimal permissions** - follow the principle of least privilege
3. **Enable CloudTrail** - for audit logging of API calls
4. **Use VPC endpoints** - for secure communication between services
5. **Encrypt S3 buckets** - enable server-side encryption

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Verify your AWS credentials are configured correctly
   - Check IAM roles have necessary permissions
   - Ensure resource ARNs use the correct account ID

2. **S3 Bucket Not Found**
   - Verify bucket names match your account ID
   - Check bucket exists in the correct region (us-east-1)

3. **Lambda Function Errors**
   - Check CloudWatch logs for detailed error messages
   - Verify environment variables are set correctly
   - Ensure SageMaker model exists and is accessible

4. **SageMaker Training Issues**
   - Check IAM role permissions for SageMaker
   - Verify input data format and location
   - Monitor training job status in SageMaker console

### Getting Help

1. Check AWS CloudWatch logs for detailed error messages
2. Verify all environment variables are set correctly
3. Ensure AWS credentials have appropriate permissions
4. Review the `SECURITY_CLEANUP.md` file for configuration details

## 📚 Next Steps

Once the pipeline is running:

1. **Customize the Model**: Adjust hyperparameters and features based on your data
2. **Set up Monitoring**: Configure CloudWatch alarms for system health
3. **Scale the Infrastructure**: Add auto-scaling and load balancing as needed
4. **Integrate with SIEM**: Connect alerts to your security information system

For detailed technical information, see `WARP.md` and `PROJECT_SUMMARY.md`.