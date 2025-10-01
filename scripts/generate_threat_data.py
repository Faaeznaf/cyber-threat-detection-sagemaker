#!/usr/bin/env python3
"""
Generate realistic network log data for cyber threat detection training.
Creates both normal network traffic and various attack patterns.
"""

import csv
import json
import random
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Any
import pandas as pd


class ThreatDataGenerator:
    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.internal_networks = [
            "192.168.0.0/16",
            "10.0.0.0/8", 
            "172.16.0.0/12"
        ]
        
        # Common legitimate services
        self.legitimate_ports = [22, 80, 443, 53, 25, 110, 143, 993, 995]
        self.attack_ports = [23, 135, 139, 445, 1433, 3389, 5432]
        
        # Attack patterns
        self.attack_ips = self._generate_attack_ips()
        self.legitimate_ips = self._generate_internal_ips(100)
        
    def _generate_attack_ips(self) -> List[str]:
        """Generate IP addresses that will represent attackers (external)."""
        attack_ips = []
        # Generate some external IPs
        for _ in range(50):
            ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            # Make sure it's not in private ranges
            if not self._is_internal_ip(ip):
                attack_ips.append(ip)
        return attack_ips
    
    def _generate_internal_ips(self, count: int) -> List[str]:
        """Generate internal IP addresses for legitimate traffic."""
        internal_ips = []
        for _ in range(count):
            # Generate from 192.168.x.x range
            ip = f"192.168.{random.randint(1, 10)}.{random.randint(10, 254)}"
            internal_ips.append(ip)
        return internal_ips
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP is in internal network range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network_str in self.internal_networks:
                if ip in ipaddress.ip_network(network_str):
                    return True
            return False
        except ValueError:
            return False
    
    def generate_normal_traffic(self, count: int) -> List[Dict[str, Any]]:
        """Generate normal network traffic logs."""
        records = []
        base_time = datetime.now() - timedelta(days=7)
        
        for i in range(count):
            timestamp = base_time + timedelta(
                seconds=random.randint(0, 7 * 24 * 3600)
            )
            
            # Normal business traffic patterns
            if 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5:
                # Business hours - more web traffic
                dest_port = random.choice([80, 443, 22, 53] + [80, 443] * 3)
                bytes_in = random.randint(100, 5000)
                bytes_out = random.randint(50, 2000)
            else:
                # Off hours - lighter traffic
                dest_port = random.choice([443, 22, 53])
                bytes_in = random.randint(50, 1000) 
                bytes_out = random.randint(20, 500)
            
            record = {
                "source_ip": random.choice(self.legitimate_ips),
                "destination_ip": random.choice(self.legitimate_ips + 
                    ["8.8.8.8", "1.1.1.1", "208.67.222.222"]),  # Add some external legitimate IPs
                "destination_port": dest_port,
                "protocol": random.choice(["TCP", "UDP", "TCP", "TCP"]),  # TCP more common
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "action": "ALLOW",
                "timestamp": timestamp.isoformat() + "Z",
                "connection_count": random.randint(1, 5),
                "label": "normal"
            }
            records.append(record)
        
        return records
    
    def generate_dos_attack(self, count: int) -> List[Dict[str, Any]]:
        """Generate DoS/DDoS attack patterns."""
        records = []
        base_time = datetime.now() - timedelta(days=3)
        
        # Pick an attacker IP
        attacker_ip = random.choice(self.attack_ips)
        target_ip = random.choice(self.legitimate_ips)
        target_port = random.choice([80, 443, 22])
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=i * random.randint(1, 10))
            
            record = {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "destination_port": target_port,
                "protocol": "TCP",
                "bytes_in": random.randint(0, 100),  # Small packets
                "bytes_out": 0,  # No response due to overload
                "action": random.choice(["ALLOW", "DROP", "DROP"]),  # Many dropped
                "timestamp": timestamp.isoformat() + "Z",
                "connection_count": random.randint(50, 200),  # High frequency
                "label": "dos_attack"
            }
            records.append(record)
        
        return records
    
    def generate_port_scan(self, count: int) -> List[Dict[str, Any]]:
        """Generate port scanning attack patterns."""
        records = []
        base_time = datetime.now() - timedelta(days=5)
        
        attacker_ip = random.choice(self.attack_ips)
        target_ip = random.choice(self.legitimate_ips)
        
        # Port scanning - sequential or random ports
        ports_to_scan = list(range(20, 1000, 10)) + self.attack_ports
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=i * random.randint(1, 5))
            port = ports_to_scan[i % len(ports_to_scan)]
            
            record = {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "bytes_in": random.randint(0, 50),  # Small reconnaissance packets
                "bytes_out": random.randint(0, 50),
                "action": random.choice(["DROP", "REJECT", "ALLOW"]),
                "timestamp": timestamp.isoformat() + "Z",
                "connection_count": 1,
                "label": "port_scan"
            }
            records.append(record)
        
        return records
    
    def generate_sql_injection_attack(self, count: int) -> List[Dict[str, Any]]:
        """Generate SQL injection attack patterns."""
        records = []
        base_time = datetime.now() - timedelta(days=2)
        
        attacker_ip = random.choice(self.attack_ips)
        target_ip = random.choice(self.legitimate_ips)
        
        sql_injection_uris = [
            "/login.php?user=admin' or '1'='1",
            "/search.php?q='; DROP TABLE users; --",
            "/product.php?id=1 UNION SELECT password FROM users",
            "/admin.php?id=1'; INSERT INTO admin VALUES('hacker','pass'); --"
        ]
        
        user_agents = [
            "sqlmap/1.4.12",
            "Mozilla/5.0 (compatible; sqlmap)",
            "curl/7.68.0",
            "Python-urllib/3.8"
        ]
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=i * random.randint(10, 60))
            
            record = {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "destination_port": 80,
                "protocol": "HTTP",
                "bytes_in": random.randint(200, 1000),
                "bytes_out": random.randint(100, 500),
                "action": random.choice(["ALLOW", "DROP"]),
                "timestamp": timestamp.isoformat() + "Z",
                "connection_count": random.randint(1, 10),
                "request_uri": random.choice(sql_injection_uris),
                "user_agent": random.choice(user_agents),
                "label": "sql_injection"
            }
            records.append(record)
        
        return records
    
    def generate_data_exfiltration(self, count: int) -> List[Dict[str, Any]]:
        """Generate data exfiltration patterns."""
        records = []
        base_time = datetime.now() - timedelta(days=1)
        
        # Insider threat or compromised account
        source_ip = random.choice(self.legitimate_ips)
        external_ip = random.choice(self.attack_ips)
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=i * random.randint(30, 300))
            
            # Large data uploads during off-hours
            if timestamp.hour < 6 or timestamp.hour > 22:
                bytes_out = random.randint(10000, 100000)  # Large uploads
            else:
                bytes_out = random.randint(1000, 10000)
            
            record = {
                "source_ip": source_ip,
                "destination_ip": external_ip,
                "destination_port": random.choice([443, 22, 21]),  # HTTPS, SSH, FTP
                "protocol": "TCP",
                "bytes_in": random.randint(100, 500),
                "bytes_out": bytes_out,
                "action": "ALLOW",
                "timestamp": timestamp.isoformat() + "Z",
                "connection_count": random.randint(1, 3),
                "label": "data_exfiltration"
            }
            records.append(record)
        
        return records
    
    def generate_brute_force_attack(self, count: int) -> List[Dict[str, Any]]:
        """Generate brute force login attack patterns."""
        records = []
        base_time = datetime.now() - timedelta(days=4)
        
        attacker_ip = random.choice(self.attack_ips)
        target_ip = random.choice(self.legitimate_ips)
        
        # Common brute force targets
        services = [
            {"port": 22, "protocol": "SSH"},
            {"port": 3389, "protocol": "RDP"}, 
            {"port": 21, "protocol": "FTP"},
            {"port": 80, "protocol": "HTTP"}
        ]
        
        service = random.choice(services)
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=i * random.randint(5, 30))
            
            record = {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "destination_port": service["port"],
                "protocol": service["protocol"],
                "bytes_in": random.randint(50, 200),
                "bytes_out": random.randint(20, 100),
                "action": random.choice(["DROP", "DENY", "ALLOW"]),  # Mostly failed attempts
                "timestamp": timestamp.isoformat() + "Z",
                "connection_count": random.randint(10, 50),
                "label": "brute_force"
            }
            records.append(record)
        
        return records
    
    def generate_complete_dataset(self, 
                                  normal_count: int = 1000,
                                  dos_count: int = 100,
                                  scan_count: int = 150,
                                  sql_count: int = 75,
                                  exfil_count: int = 50,
                                  brute_count: int = 125) -> pd.DataFrame:
        """Generate a complete dataset with all attack types."""
        
        print("Generating normal traffic...")
        all_records = self.generate_normal_traffic(normal_count)
        
        print("Generating DoS attacks...")
        all_records.extend(self.generate_dos_attack(dos_count))
        
        print("Generating port scans...")
        all_records.extend(self.generate_port_scan(scan_count))
        
        print("Generating SQL injection attacks...")
        all_records.extend(self.generate_sql_injection_attack(sql_count))
        
        print("Generating data exfiltration...")
        all_records.extend(self.generate_data_exfiltration(exfil_count))
        
        print("Generating brute force attacks...")
        all_records.extend(self.generate_brute_force_attack(brute_count))
        
        # Shuffle the records
        random.shuffle(all_records)
        
        print(f"Generated {len(all_records)} total records")
        return pd.DataFrame(all_records)


def main():
    """Generate and save threat detection dataset."""
    generator = ThreatDataGenerator()
    
    # Generate dataset
    df = generator.generate_complete_dataset(
        normal_count=1500,
        dos_count=200, 
        scan_count=300,
        sql_count=150,
        exfil_count=100,
        brute_count=250
    )
    
    # Print dataset statistics
    print("\nDataset Statistics:")
    print(df['label'].value_counts())
    print(f"\nTotal records: {len(df)}")
    print(f"Features: {len(df.columns)}")
    
    # Save raw data (before preprocessing)
    raw_file = "data/raw/network_logs.csv"
    df.to_csv(raw_file, index=False)
    print(f"\nRaw data saved to: {raw_file}")
    
    # Also save a few sample JSON records for Lambda testing
    sample_records = df.head(10).to_dict('records')
    # Clean up NaN values for JSON serialization
    for record in sample_records:
        for key, value in record.items():
            if pd.isna(value):
                record[key] = None
    
    with open("data/raw/sample_logs.json", 'w') as f:
        json.dump(sample_records, f, indent=2)
    print("Sample JSON data saved to: data/raw/sample_logs.json")
    
    print("\nSample records:")
    print(df.head())
    
    print("\nData generation complete!")


if __name__ == "__main__":
    main()