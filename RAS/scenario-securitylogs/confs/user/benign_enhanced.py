#!/usr/bin/env python3
"""
Enhanced Benign User Traffic Script for Juice Shop
Simulates realistic user behavior with multiple sessions and User-Agents
"""

import requests
import time
import random
import json
import sys
import os
from datetime import datetime
from urllib.parse import urljoin

class BenignUser:
    def __init__(self, target_url="http://fancystore.com"):
        self.target_url = target_url
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1"
        ]
        
    def set_random_user_agent(self):
        """Set a random User-Agent for this session"""
        user_agent = random.choice(self.user_agents)
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        print(f"[*] Using User-Agent: {user_agent}")
        
    def browse_homepage(self):
        """Browse the homepage"""
        print("[*] Browsing homepage...")
        try:
            response = self.session.get(self.target_url, timeout=10)
            print(f"    Status: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def browse_products(self):
        """Browse products page"""
        print("[*] Browsing products...")
        try:
            response = self.session.get(f"{self.target_url}/#/search", timeout=10)
            print(f"    Status: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def search_products(self, query):
        """Search for products using REST API"""
        print(f"[*] Searching for: {query}")
        try:
            search_url = f"{self.target_url}/rest/products/search"
            params = {'q': query}
            response = self.session.get(search_url, params=params, timeout=10)
            print(f"    Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"    Found {len(data.get('data', []))} products")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def get_products(self):
        """Get all products"""
        print("[*] Getting product list...")
        try:
            response = self.session.get(f"{self.target_url}/rest/products", timeout=10)
            print(f"    Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"    Found {len(data.get('data', []))} products")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def view_product(self, product_id):
        """View specific product details"""
        print(f"[*] Viewing product {product_id}...")
        try:
            response = self.session.get(f"{self.target_url}/rest/products/{product_id}", timeout=10)
            print(f"    Status: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def browse_categories(self):
        """Browse product categories"""
        print("[*] Browsing categories...")
        try:
            response = self.session.get(f"{self.target_url}/#/categories", timeout=10)
            print(f"    Status: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def view_about_page(self):
        """View about page"""
        print("[*] Viewing about page...")
        try:
            response = self.session.get(f"{self.target_url}/#/about", timeout=10)
            print(f"    Status: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def view_contact_page(self):
        """View contact page"""
        print("[*] Viewing contact page...")
        try:
            response = self.session.get(f"{self.target_url}/#/contact", timeout=10)
            print(f"    Status: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def view_basket(self):
        """View shopping basket"""
        print("[*] Viewing basket...")
        try:
            response = self.session.get(f"{self.target_url}/#/basket", timeout=10)
            print(f"    Status: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def register_user(self, email, password):
        """Register a new user"""
        print(f"[*] Registering user: {email}")
        try:
            register_data = {
                'email': email,
                'password': password,
                'passwordRepeat': password,
                'securityQuestion': {
                    'id': 1,
                    'question': 'Your eldest siblings middle name?'
                },
                'securityAnswer': 'test'
            }
            response = self.session.post(
                f"{self.target_url}/api/Users/",
                json=register_data,
                timeout=10
            )
            print(f"    Status: {response.status_code}")
            return response.status_code in [200, 201]
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def login_user(self, email, password):
        """Login user"""
        print(f"[*] Logging in user: {email}")
        try:
            login_data = {
                'email': email,
                'password': password
            }
            response = self.session.post(
                f"{self.target_url}/rest/user/login",
                json=login_data,
                timeout=10
            )
            print(f"    Status: {response.status_code}")
            if response.status_code == 200:
                print("    Login successful!")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def add_to_basket(self, product_id, quantity=1):
        """Add product to basket"""
        print(f"[*] Adding product {product_id} to basket...")
        try:
            basket_data = {
                'ProductId': product_id,
                'quantity': quantity
            }
            response = self.session.post(
                f"{self.target_url}/api/BasketItems/",
                json=basket_data,
                timeout=10
            )
            print(f"    Status: {response.status_code}")
            return response.status_code in [200, 201]
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def get_basket_items(self):
        """Get basket items"""
        print("[*] Getting basket items...")
        try:
            response = self.session.get(f"{self.target_url}/api/BasketItems/", timeout=10)
            print(f"    Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"    Found {len(data.get('data', []))} items in basket")
            return response.status_code == 200
        except Exception as e:
            print(f"    Error: {e}")
            return False
            
    def run_user_session(self):
        """Run a complete user session"""
        session_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n[*] Starting new user session for {self.target_url} at {session_start}")
        print("=" * 60)
        
        # Set random User-Agent
        self.set_random_user_agent()
        
        # Log session start
        with open("/opt/output/benign_traffic.log", "a") as f:
            f.write(f"[{session_start}] Session started with User-Agent: {self.session.headers.get('User-Agent', 'Unknown')}\n")
        
        # Basic browsing
        self.browse_homepage()
        time.sleep(random.uniform(1, 3))
        
        self.browse_products()
        time.sleep(random.uniform(1, 3))
        
        self.get_products()
        time.sleep(random.uniform(1, 3))
        
        # Search activities
        search_queries = ['apple', 'orange', 'banana', 'juice', 'fruit', 'organic']
        for query in random.sample(search_queries, 3):
            self.search_products(query)
            time.sleep(random.uniform(2, 4))
            
        # Browse specific pages
        self.browse_categories()
        time.sleep(random.uniform(1, 3))
        
        self.view_about_page()
        time.sleep(random.uniform(1, 3))
        
        self.view_contact_page()
        time.sleep(random.uniform(1, 3))
        
        self.view_basket()
        time.sleep(random.uniform(1, 3))
        
        # Try to view some products (assuming product IDs 1-10 exist)
        for product_id in random.sample(range(1, 11), 3):
            self.view_product(product_id)
            time.sleep(random.uniform(1, 2))
            
        session_end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print("=" * 60)
        print(f"[*] User session completed at {session_end}\n")
        
        # Log session end
        with open("/opt/output/benign_traffic.log", "a") as f:
            f.write(f"[{session_end}] Session completed successfully\n")

def main():
    target_url = "http://fancystore.com"
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        
    print(f"[*] Benign user traffic starting for: {target_url}")
    print("[*] Installing required packages...")
    
    # Simulate package installation
    time.sleep(2)
    print("[*] Packages installed successfully")
    
    # Create output directory and log file
    output_dir = "/opt/output"
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "benign_traffic.log")
    
    print(f"[*] Output directory: {output_dir}")
    print(f"[*] Log file: {log_file}")
    
    print("[*] Waiting 10 seconds before starting benign traffic...")
    time.sleep(10)
    
    # Run multiple user sessions
    session_count = 0
    while True:
        try:
            user = BenignUser(target_url)
            user.run_user_session()
            session_count += 1
            
            print(f"[*] Completed {session_count} user sessions")
            print("[*] Waiting 15 seconds before next session...")
            time.sleep(15)
            
        except KeyboardInterrupt:
            print("\n[*] Benign user traffic stopped by user")
            break
        except Exception as e:
            print(f"[!] Error in user session: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main() 