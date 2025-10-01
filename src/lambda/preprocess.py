import json
import ipaddress
import re
from typing import Any, Dict, List, Optional
from datetime import datetime
import base64

# Enhanced AWS Lambda function for preprocessing network logs with cyber threat detection features
# Extracts sophisticated features for anomaly detection and threat classification

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for preprocessing network logs for cyber threat detection.
    
    Expected input formats:
    1. Direct log record: {"source_ip": "1.2.3.4", "destination_port": 443, ...}
    2. S3 event: {"Records": [{"s3": {"bucket": {...}, "object": {...}}}]}
    3. Kinesis event: {"Records": [{"kinesis": {"data": "base64_encoded_data"}}]}
    """
    try:
        # Handle different event sources
        if "Records" in event:
            # Process S3 or Kinesis events
            processed_records = []
            for record in event["Records"]:
                if "s3" in record:
                    # S3 event - would typically fetch and process file
                    log_data = _extract_s3_log_data(record)
                elif "kinesis" in record:
                    # Kinesis event - decode base64 data
                    log_data = _extract_kinesis_log_data(record)
                else:
                    continue
                    
                if log_data:
                    features = _extract_features(log_data)
                    processed_records.append({"features": features})
            
            return {"processed_records": processed_records}
        else:
            # Direct log record processing
            features = _extract_features(event)
            return {"features": features}
            
    except Exception as e:
        print(f"Error processing event: {str(e)}")
        return {"error": str(e), "event": event}

def _extract_s3_log_data(s3_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract log data from S3 event record.
    In production, this would fetch and parse the actual S3 object.
    """
    # Placeholder - would use boto3 to fetch S3 object
    bucket = s3_record["s3"]["bucket"]["name"]
    key = s3_record["s3"]["object"]["key"]
    
    # For now, return mock data based on filename patterns
    if "firewall" in key.lower():
        return {
            "source_ip": "192.168.1.100",
            "destination_ip": "203.0.113.1",
            "destination_port": 80,
            "protocol": "TCP",
            "action": "ALLOW",
            "bytes_in": 1024,
            "bytes_out": 2048,
            "timestamp": "2024-01-01T12:00:00Z"
        }
    return None

def _extract_kinesis_log_data(kinesis_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract and decode log data from Kinesis event record.
    """
    try:
        # Decode base64 data
        data = base64.b64decode(kinesis_record["kinesis"]["data"]).decode('utf-8')
        return json.loads(data)
    except Exception as e:
        print(f"Error decoding Kinesis data: {e}")
        return None

def _extract_features(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract sophisticated features for cyber threat detection.
    """
    # Basic network features
    source_ip = record.get("source_ip", "")
    dest_ip = record.get("destination_ip", record.get("dest_ip", ""))
    dest_port = record.get("destination_port", record.get("dest_port", 0))
    protocol = record.get("protocol", "UNKNOWN").upper()
    bytes_in = record.get("bytes_in", record.get("bytes_sent", 0))
    bytes_out = record.get("bytes_out", record.get("bytes_received", 0))
    
    # Extract timestamp features
    timestamp = record.get("timestamp", datetime.utcnow().isoformat())
    time_features = _extract_time_features(timestamp)
    
    # IP-based features
    ip_features = _extract_ip_features(source_ip, dest_ip)
    
    # Port and protocol features
    port_features = _extract_port_features(dest_port, protocol)
    
    # Traffic volume features
    traffic_features = _extract_traffic_features(bytes_in, bytes_out)
    
    # Behavioral anomaly indicators
    anomaly_features = _extract_anomaly_indicators(record)
    
    # Combine all features
    features = {
        # Basic network identifiers
        "source_ip_hash": hash(source_ip) % 10000,  # Anonymized IP representation
        "dest_ip_hash": hash(dest_ip) % 10000,
        "dest_port": dest_port,
        "protocol_numeric": _encode_protocol(protocol),
        
        # Traffic characteristics
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "total_bytes": bytes_in + bytes_out,
        "bytes_ratio": _safe_ratio(bytes_out, bytes_in),
        
        # Derived features
        **time_features,
        **ip_features,
        **port_features,
        **traffic_features,
        **anomaly_features
    }
    
    return features

def _extract_time_features(timestamp_str: str) -> Dict[str, Any]:
    """
    Extract time-based features that could indicate attacks (e.g., off-hours activity).
    """
    try:
        if isinstance(timestamp_str, str):
            # Handle various timestamp formats
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            dt = datetime.utcnow()
        
        return {
            "hour_of_day": dt.hour,
            "day_of_week": dt.weekday(),
            "is_weekend": dt.weekday() >= 5,
            "is_business_hours": 9 <= dt.hour <= 17 and dt.weekday() < 5
        }
    except Exception:
        return {"hour_of_day": 12, "day_of_week": 1, "is_weekend": False, "is_business_hours": True}

def _extract_ip_features(source_ip: str, dest_ip: str) -> Dict[str, Any]:
    """
    Extract IP-based features for threat detection.
    """
    features = {
        "source_is_private": _is_private_ip(source_ip),
        "dest_is_private": _is_private_ip(dest_ip),
        "source_is_internal": _is_internal_network(source_ip),
        "dest_is_internal": _is_internal_network(dest_ip),
        "is_external_connection": False,
        "ip_geolocation_risk": _assess_ip_geolocation_risk(source_ip, dest_ip)
    }
    
    # Determine if connection is external (potential threat vector)
    features["is_external_connection"] = (
        not features["source_is_internal"] or not features["dest_is_internal"]
    )
    
    return features

def _extract_port_features(port: int, protocol: str) -> Dict[str, Any]:
    """
    Extract port and protocol features for threat detection.
    """
    # Common service ports
    well_known_ports = {80, 443, 22, 23, 21, 25, 53, 110, 143, 993, 995}
    high_risk_ports = {23, 135, 139, 445, 1433, 3389, 5432}  # Telnet, RDP, SQL, etc.
    
    return {
        "is_well_known_port": port in well_known_ports,
        "is_high_risk_port": port in high_risk_ports,
        "is_high_port": port > 1024,
        "is_web_port": port in {80, 443, 8080, 8443},
        "is_ssh_port": port == 22,
        "is_database_port": port in {1433, 3306, 5432, 27017},
        "port_category": _categorize_port(port)
    }

def _extract_traffic_features(bytes_in: int, bytes_out: int) -> Dict[str, Any]:
    """
    Extract traffic volume features that could indicate attacks.
    """
    total_bytes = bytes_in + bytes_out
    
    return {
        "is_high_volume": total_bytes > 10000,  # Potential data exfiltration
        "is_low_volume": total_bytes < 100,    # Potential reconnaissance
        "is_upload_heavy": bytes_out > bytes_in * 2,  # Potential data upload
        "is_download_heavy": bytes_in > bytes_out * 2,  # Potential data download
        "traffic_symmetry": _calculate_traffic_symmetry(bytes_in, bytes_out)
    }

def _extract_anomaly_indicators(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract features that could indicate specific types of attacks.
    """
    features = {
        "has_failed_attempts": False,
        "suspicious_user_agent": False,
        "potential_sql_injection": False,
        "potential_xss": False,
        "potential_dos": False,
        "repeated_connections": False
    }
    
    # Check for attack indicators in various fields
    action = record.get("action", "")
    if isinstance(action, str):
        action = action.upper()
    else:
        action = ""
        
    request_uri = record.get("request_uri", "")
    if not isinstance(request_uri, str) or str(request_uri).lower() == 'nan':
        request_uri = ""
        
    user_agent = record.get("user_agent", "")
    if not isinstance(user_agent, str) or str(user_agent).lower() == 'nan':
        user_agent = ""
    
    # Failed connection attempts
    features["has_failed_attempts"] = action in {"DENY", "DROP", "REJECT"}
    
    # Suspicious patterns in request URI (if available)
    if request_uri:
        features["potential_sql_injection"] = _detect_sql_injection(request_uri)
        features["potential_xss"] = _detect_xss(request_uri)
    
    # Suspicious user agents
    if user_agent:
        features["suspicious_user_agent"] = _detect_suspicious_user_agent(user_agent)
    
    # High connection frequency (would need session state in real implementation)
    connection_count = record.get("connection_count", 1)
    features["repeated_connections"] = connection_count > 10
    features["potential_dos"] = connection_count > 50
    
    return features

# Helper functions

def _is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is in private range.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

def _is_internal_network(ip_str: str) -> bool:
    """
    Check if IP is in internal network range (customize for your organization).
    """
    internal_ranges = [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "192.168.0.0/16",
        "127.0.0.0/8"
    ]
    
    try:
        ip = ipaddress.ip_address(ip_str)
        for range_str in internal_ranges:
            if ip in ipaddress.ip_network(range_str):
                return True
        return False
    except ValueError:
        return False

def _assess_ip_geolocation_risk(source_ip: str, dest_ip: str) -> int:
    """
    Assess geolocation-based risk (simplified - would use real geolocation service).
    """
    # In production, integrate with IP geolocation service
    # For now, assign risk based on IP patterns
    high_risk_patterns = ["10.0.", "172.16.", "192.168."]  # Mock high-risk ranges
    
    risk_score = 0
    if any(pattern in source_ip for pattern in high_risk_patterns):
        risk_score += 1
    if any(pattern in dest_ip for pattern in high_risk_patterns):
        risk_score += 1
        
    return risk_score

def _encode_protocol(protocol: str) -> int:
    """
    Convert protocol string to numeric encoding.
    """
    protocol_map = {
        "TCP": 1,
        "UDP": 2,
        "ICMP": 3,
        "HTTP": 4,
        "HTTPS": 5,
        "UNKNOWN": 0
    }
    return protocol_map.get(protocol, 0)

def _categorize_port(port: int) -> int:
    """
    Categorize port into risk categories.
    """
    if port < 1024:
        return 1  # System/well-known ports
    elif port < 49152:
        return 2  # Registered ports
    else:
        return 3  # Dynamic/private ports

def _safe_ratio(numerator: float, denominator: float) -> float:
    """
    Calculate ratio safely, avoiding division by zero and infinite values.
    """
    if denominator == 0:
        return 0.0 if numerator == 0 else 1000.0  # Cap at large but finite value
    ratio = numerator / denominator
    # Cap extremely large ratios
    return min(ratio, 1000.0)

def _calculate_traffic_symmetry(bytes_in: int, bytes_out: int) -> float:
    """
    Calculate traffic symmetry (0 = perfectly asymmetric, 1 = perfectly symmetric).
    """
    total = bytes_in + bytes_out
    if total == 0:
        return 1.0
    
    difference = abs(bytes_in - bytes_out)
    return 1.0 - (difference / total)

def _detect_sql_injection(uri: str) -> bool:
    """
    Simple SQL injection detection.
    """
    sql_patterns = [
        r"union.*select",
        r"\'\ or\ \'1\'=\'1",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from"
    ]
    
    uri_lower = uri.lower()
    return any(re.search(pattern, uri_lower) for pattern in sql_patterns)

def _detect_xss(uri: str) -> bool:
    """
    Simple XSS detection.
    """
    xss_patterns = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*="
    ]
    
    uri_lower = uri.lower()
    return any(re.search(pattern, uri_lower) for pattern in xss_patterns)

def _detect_suspicious_user_agent(user_agent: str) -> bool:
    """
    Detect suspicious user agents.
    """
    suspicious_patterns = [
        "sqlmap",
        "nmap",
        "masscan",
        "nikto",
        "dirbuster",
        "curl",  # Could be legitimate, but often used in attacks
        "wget"
    ]
    
    ua_lower = user_agent.lower()
    return any(pattern in ua_lower for pattern in suspicious_patterns)
