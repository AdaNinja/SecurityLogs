#!/usr/bin/env python3
"""
DNS and HTTP Proxy Configuration for Raw Unencrypted Flow Capture
Enhanced for SecurityLogs DNS Attack Module
"""

import json
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import os

class DNSHTTPProxyConfig:
    """Configuration for DNS and HTTP proxies to capture raw unencrypted flows"""
    
    def __init__(self, output_dir: str = "/opt/proxy_logs"):
        self.output_dir = output_dir
        self.dns_log_file = f"{output_dir}/dns_proxy_raw.jsonl"
        self.http_log_file = f"{output_dir}/http_proxy_raw.jsonl"
        self.attack_log_file = f"{output_dir}/attack_flows.jsonl"
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{output_dir}/proxy.log"),
                logging.StreamHandler()
            ]
        )
    
    def generate_dns_proxy_config(self) -> Dict[str, Any]:
        """Generate DNS proxy configuration for raw flow capture"""
        return {
            "dns_proxy": {
                "enabled": True,
                "listen_address": "0.0.0.0",
                "listen_port": 53,
                "upstream_dns": ["8.8.8.8", "8.8.4.4"],
                "log_format": "jsonl",
                "log_fields": [
                    "timestamp",
                    "client_ip",
                    "query_type",
                    "query_domain",
                    "response_ip",
                    "response_time",
                    "response_size",
                    "attack_detection",
                    "attack_stage",
                    "tunnel_detection",
                    "raw_query",
                    "raw_response"
                ],
                "attack_detection": {
                    "enabled": True,
                    "patterns": {
                        "dns_tunnel": [
                            r"[A-Za-z0-9+/]{20,}",  # Base64 patterns
                            r"cmd\.[a-zA-Z0-9]+",   # Command patterns
                            r"exfil\.[a-zA-Z0-9]+", # Exfiltration patterns
                            r"tunnel\.[a-zA-Z0-9]+" # Tunnel patterns
                        ],
                        "dns_amplification": [
                            r"ANY\.",
                            r"TXT\.",
                            r"MX\.",
                            r"AAAA\."
                        ],
                        "dns_reconnaissance": [
                            r"admin\.",
                            r"api\.",
                            r"db\.",
                            r"internal\.",
                            r"jenkins\.",
                            r"gitlab\.",
                            r"jira\.",
                            r"confluence\."
                        ]
                    }
                },
                "tunnel_detection": {
                    "enabled": True,
                    "techniques": [
                        "base64_encoding",
                        "hex_encoding", 
                        "custom_encoding",
                        "compression"
                    ],
                    "thresholds": {
                        "query_length": 63,
                        "subdomain_count": 5,
                        "response_size": 512
                    }
                }
            }
        }
    
    def generate_http_proxy_config(self) -> Dict[str, Any]:
        """Generate HTTP proxy configuration for raw flow capture"""
        return {
            "http_proxy": {
                "enabled": True,
                "listen_address": "0.0.0.0",
                "listen_port": 8080,
                "upstream_proxy": None,
                "log_format": "jsonl",
                "log_fields": [
                    "timestamp",
                    "client_ip",
                    "method",
                    "url",
                    "headers",
                    "body",
                    "response_code",
                    "response_headers",
                    "response_body",
                    "response_time",
                    "attack_detection",
                    "attack_stage",
                    "sql_injection_detection",
                    "raw_request",
                    "raw_response"
                ],
                "attack_detection": {
                    "enabled": True,
                    "sql_injection": {
                        "enabled": True,
                        "patterns": [
                            r"'.*OR.*1=1",
                            r"'.*UNION.*SELECT",
                            r"'.*AND.*SELECT",
                            r"admin'.*--",
                            r"'.*OR.*'x'='x",
                            r"'.*AND.*SLEEP",
                            r"'.*UPDATEXML"
                        ],
                        "thresholds": {
                            "max_payload_length": 1000,
                            "suspicious_keywords": 3
                        }
                    },
                    "dns_followup": {
                        "enabled": True,
                        "detect_dns_queries_after_http": True,
                        "correlation_window": 30  # seconds
                    }
                },
                "content_analysis": {
                    "enabled": True,
                    "extract_credentials": True,
                    "extract_sensitive_data": True,
                    "detect_data_exfiltration": True
                }
            }
        }
    
    def generate_attack_flow_correlation(self) -> Dict[str, Any]:
        """Generate attack flow correlation configuration"""
        return {
            "flow_correlation": {
                "enabled": True,
                "correlation_window": 60,  # seconds
                "attack_sequences": {
                    "dns_reconnaissance_to_http": {
                        "description": "DNS reconnaissance followed by HTTP attack",
                        "sequence": [
                            {"type": "dns", "stage": "reconnaissance"},
                            {"type": "http", "stage": "exploitation"}
                        ],
                        "time_window": 300  # 5 minutes
                    },
                    "sql_injection_to_dns_exfiltration": {
                        "description": "SQL injection followed by DNS data exfiltration",
                        "sequence": [
                            {"type": "http", "stage": "exploitation", "technique": "sql_injection"},
                            {"type": "dns", "stage": "exfiltration", "technique": "tunnel"}
                        ],
                        "time_window": 600  # 10 minutes
                    },
                    "dns_cc_communication": {
                        "description": "DNS-based command and control communication",
                        "sequence": [
                            {"type": "dns", "stage": "command_control"},
                            {"type": "dns", "stage": "command_control"}
                        ],
                        "time_window": 120  # 2 minutes
                    }
                },
                "output_format": {
                    "flow_id": "auto_generated",
                    "attack_sequence": "sequence_name",
                    "start_time": "timestamp",
                    "end_time": "timestamp",
                    "flows": [
                        {
                            "timestamp": "timestamp",
                            "protocol": "dns|http",
                            "source_ip": "client_ip",
                            "destination_ip": "server_ip",
                            "attack_stage": "stage",
                            "attack_technique": "technique",
                            "raw_data": "base64_encoded"
                        }
                    ]
                }
            }
        }
    
    def generate_docker_compose_proxy_config(self) -> str:
        """Generate Docker Compose configuration for DNS and HTTP proxies"""
        return """
version: '3.8'

services:
  dns-proxy:
    image: securitylogs-dns-proxy:latest
    container_name: securitylogs-dns-proxy
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    volumes:
      - ./proxy_config:/etc/dns-proxy
      - ../../data/proxy_logs:/var/log/dns-proxy
    environment:
      - DNS_PROXY_CONFIG=/etc/dns-proxy/dns-proxy.conf
      - LOG_LEVEL=INFO
    networks:
      - attacknet
    restart: unless-stopped

  http-proxy:
    image: securitylogs-http-proxy:latest
    container_name: securitylogs-http-proxy
    ports:
      - "8080:8080"
    volumes:
      - ./proxy_config:/etc/http-proxy
      - ../../data/proxy_logs:/var/log/http-proxy
    environment:
      - HTTP_PROXY_CONFIG=/etc/http-proxy/http-proxy.conf
      - LOG_LEVEL=INFO
    networks:
      - attacknet
    restart: unless-stopped

  flow-correlator:
    image: securitylogs-flow-correlator:latest
    container_name: securitylogs-flow-correlator
    volumes:
      - ../../data/proxy_logs:/var/log/proxy
      - ../../data/correlated_flows:/var/log/correlated
    environment:
      - CORRELATION_CONFIG=/etc/correlator/config.json
      - LOG_LEVEL=INFO
    networks:
      - attacknet
    depends_on:
      - dns-proxy
      - http-proxy
    restart: unless-stopped

networks:
  attacknet:
    external: true
"""
    
    def save_configurations(self):
        """Save all proxy configurations to files"""
        configs = {
            "dns_proxy": self.generate_dns_proxy_config(),
            "http_proxy": self.generate_http_proxy_config(),
            "flow_correlation": self.generate_attack_flow_correlation()
        }
        
        # Save DNS proxy config
        with open(f"{self.output_dir}/dns-proxy.conf", 'w') as f:
            json.dump(configs["dns_proxy"], f, indent=2)
        
        # Save HTTP proxy config
        with open(f"{self.output_dir}/http-proxy.conf", 'w') as f:
            json.dump(configs["http_proxy"], f, indent=2)
        
        # Save flow correlation config
        with open(f"{self.output_dir}/flow-correlation.conf", 'w') as f:
            json.dump(configs["flow_correlation"], f, indent=2)
        
        # Save Docker Compose config
        with open(f"{self.output_dir}/docker-compose.proxy.yml", 'w') as f:
            f.write(self.generate_docker_compose_proxy_config())
        
        logging.info(f"Proxy configurations saved to {self.output_dir}")
        
        return configs
    
    def generate_log_parser(self) -> str:
        """Generate log parser for DNS and HTTP proxy logs"""
        return '''
#!/usr/bin/env python3
"""
DNS and HTTP Proxy Log Parser for SecurityLogs
Parses raw unencrypted flows and correlates attack sequences
"""

import json
import re
import time
from datetime import datetime
from typing import Dict, List, Any

class ProxyLogParser:
    def __init__(self, dns_log_file: str, http_log_file: str, output_file: str):
        self.dns_log_file = dns_log_file
        self.http_log_file = http_log_file
        self.output_file = output_file
        self.attack_flows = []
        
    def parse_dns_log(self, log_line: str) -> Dict[str, Any]:
        """Parse DNS proxy log line"""
        try:
            data = json.loads(log_line)
            
            # Detect attack patterns
            attack_detection = self.detect_dns_attack(data)
            
            return {
                "timestamp": data.get("timestamp"),
                "protocol": "dns",
                "client_ip": data.get("client_ip"),
                "query_type": data.get("query_type"),
                "query_domain": data.get("query_domain"),
                "response_ip": data.get("response_ip"),
                "attack_detection": attack_detection,
                "raw_query": data.get("raw_query"),
                "raw_response": data.get("raw_response")
            }
        except Exception as e:
            print(f"Error parsing DNS log: {e}")
            return {}
    
    def parse_http_log(self, log_line: str) -> Dict[str, Any]:
        """Parse HTTP proxy log line"""
        try:
            data = json.loads(log_line)
            
            # Detect attack patterns
            attack_detection = self.detect_http_attack(data)
            
            return {
                "timestamp": data.get("timestamp"),
                "protocol": "http",
                "client_ip": data.get("client_ip"),
                "method": data.get("method"),
                "url": data.get("url"),
                "attack_detection": attack_detection,
                "raw_request": data.get("raw_request"),
                "raw_response": data.get("raw_response")
            }
        except Exception as e:
            print(f"Error parsing HTTP log: {e}")
            return {}
    
    def detect_dns_attack(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect DNS attack patterns"""
        query_domain = data.get("query_domain", "")
        
        # DNS tunnel detection
        tunnel_patterns = [
            r"[A-Za-z0-9+/]{20,}",
            r"cmd\.[a-zA-Z0-9]+",
            r"exfil\.[a-zA-Z0-9]+",
            r"tunnel\.[a-zA-Z0-9]+"
        ]
        
        for pattern in tunnel_patterns:
            if re.search(pattern, query_domain):
                return {
                    "is_attack": True,
                    "attack_type": "dns_tunnel",
                    "technique": "base64_encoding",
                    "confidence": 0.9
                }
        
        # DNS reconnaissance detection
        recon_patterns = [
            r"admin\.",
            r"api\.",
            r"db\.",
            r"internal\.",
            r"jenkins\.",
            r"gitlab\."
        ]
        
        for pattern in recon_patterns:
            if re.search(pattern, query_domain):
                return {
                    "is_attack": True,
                    "attack_type": "dns_reconnaissance",
                    "technique": "subdomain_enumeration",
                    "confidence": 0.7
                }
        
        return {"is_attack": False}
    
    def detect_http_attack(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect HTTP attack patterns"""
        url = data.get("url", "")
        body = data.get("body", "")
        
        # SQL injection detection
        sql_patterns = [
            r"'.*OR.*1=1",
            r"'.*UNION.*SELECT",
            r"'.*AND.*SELECT",
            r"admin'.*--",
            r"'.*OR.*'x'='x"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, url) or re.search(pattern, body):
                return {
                    "is_attack": True,
                    "attack_type": "sql_injection",
                    "technique": "union_based",
                    "confidence": 0.9
                }
        
        return {"is_attack": False}
    
    def correlate_flows(self, dns_flows: List[Dict], http_flows: List[Dict]) -> List[Dict]:
        """Correlate DNS and HTTP flows to identify attack sequences"""
        correlated_flows = []
        
        # Group flows by client IP and time window
        for dns_flow in dns_flows:
            if not dns_flow.get("attack_detection", {}).get("is_attack"):
                continue
                
            client_ip = dns_flow.get("client_ip")
            timestamp = dns_flow.get("timestamp")
            
            # Find related HTTP flows within 5 minutes
            related_http_flows = []
            for http_flow in http_flows:
                if (http_flow.get("client_ip") == client_ip and
                    http_flow.get("attack_detection", {}).get("is_attack")):
                    related_http_flows.append(http_flow)
            
            if related_http_flows:
                correlated_flows.append({
                    "flow_id": f"flow_{len(correlated_flows)}",
                    "start_time": timestamp,
                    "client_ip": client_ip,
                    "attack_sequence": "dns_reconnaissance_to_http",
                    "flows": [dns_flow] + related_http_flows
                })
        
        return correlated_flows
    
    def parse_all_logs(self):
        """Parse all DNS and HTTP proxy logs"""
        dns_flows = []
        http_flows = []
        
        # Parse DNS logs
        try:
            with open(self.dns_log_file, 'r') as f:
                for line in f:
                    flow = self.parse_dns_log(line.strip())
                    if flow:
                        dns_flows.append(flow)
        except FileNotFoundError:
            print(f"DNS log file not found: {self.dns_log_file}")
        
        # Parse HTTP logs
        try:
            with open(self.http_log_file, 'r') as f:
                for line in f:
                    flow = self.parse_http_log(line.strip())
                    if flow:
                        http_flows.append(flow)
        except FileNotFoundError:
            print(f"HTTP log file not found: {self.http_log_file}")
        
        # Correlate flows
        correlated_flows = self.correlate_flows(dns_flows, http_flows)
        
        # Save results
        with open(self.output_file, 'w') as f:
            for flow in correlated_flows:
                f.write(json.dumps(flow) + '\\n')
        
        print(f"Parsed {len(dns_flows)} DNS flows, {len(http_flows)} HTTP flows")
        print(f"Correlated {len(correlated_flows)} attack sequences")
        print(f"Results saved to {self.output_file}")

if __name__ == "__main__":
    parser = ProxyLogParser(
        dns_log_file="/var/log/dns-proxy/dns_proxy_raw.jsonl",
        http_log_file="/var/log/http-proxy/http_proxy_raw.jsonl",
        output_file="/var/log/correlated_flows.jsonl"
    )
    parser.parse_all_logs()
'''

if __name__ == "__main__":
    config = DNSHTTPProxyConfig()
    configs = config.save_configurations()
    
    # Generate log parser
    with open(f"{config.output_dir}/proxy_log_parser.py", 'w') as f:
        f.write(config.generate_log_parser())
    
    print("✅ DNS and HTTP proxy configuration generated successfully!")
    print(f"📁 Configuration files saved to: {config.output_dir}")
    print("🚀 Next steps:")
    print("1. Build proxy containers: docker-compose -f docker-compose.proxy.yml build")
    print("2. Start proxies: docker-compose -f docker-compose.proxy.yml up -d")
    print("3. Configure your DNS and HTTP clients to use the proxies")
    print("4. Run your DNS attack experiments")
    print("5. Parse logs: python3 proxy_log_parser.py") 