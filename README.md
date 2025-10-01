# Cyber Security Threat Detection System with Amazon SageMaker

This project sets up a real-time threat detection workflow using AWS services and Amazon SageMaker.

High-level flow:
- Pre-process network log data (features: source_ip, destination_port, protocol_type) via AWS Lambda
- Train an XGBoost model in SageMaker to classify events as normal or suspicious
- Deploy a SageMaker endpoint for real-time predictions
- Orchestrate an automated SageMaker Pipeline from data prep to training, testing, and deployment
- Continuously monitor new data and raise alerts for anomalies (e.g., DoS attacks, phishing attempts)



Next steps (to be refined by your graphic details):
1) Define feature schema and preprocessing logic in Lambda
2) Implement training script (XGBoost) and data channels
3) Add evaluation step and model metrics
4) Create SageMaker Pipeline definition (processing, training, evaluation, registration, deployment)
5) Integrate alerting mechanism (e.g., SNS/CloudWatch/EventBridge)

Estimated build time: ~2–3 hours
Estimated cost: ~$1–$2 (dependent on training duration and cleanup)
