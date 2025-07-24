#!/usr/bin/env python3
"""
Benign Traffic Generator for SecurityLogs
Generates realistic background traffic to provide cover for attacks
"""

import time
import random
import json
import os
import argparse
import threading
from datetime import datetime
from typing import Dict, List, Any
import requests
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class BenignTrafficGenerator:
    """Generates realistic benign traffic for security experiments"""
    
    def __init__(self, variant_id: str, protocol_mix: str = "HTTP:0.7,DNS:0.2,SMTP:0.1", 
                 duration: int = 300, attack_aware: bool = True):
        self.variant_id = variant_id
        self.duration = duration
        self.attack_aware = attack_aware
        self.running = False
        
        # Parse protocol mix
        self.protocol_weights = self._parse_protocol_mix(protocol_mix)
        
        # Output directories
        self.output_dir = f"data/logs/{variant_id}/proxy"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Traffic counters
        self.counters = {
            'http': 0,
            'dns': 0, 
            'smtp': 0
        }
        
        # Realistic domains and URLs
        self.normal_domains = [
            "www.google.com", "www.github.com", "www.stackoverflow.com",
            "www.wikipedia.org", "www.reddit.com", "www.youtube.com",
            "www.amazon.com", "www.microsoft.com", "www.apple.com", "www.netflix.com",
            "www.facebook.com", "www.twitter.com", "www.instagram.com", "www.linkedin.com",
            "www.medium.com", "www.dev.to", "www.hashnode.com", "www.producthunt.com",
            "www.hackernews.com", "www.techcrunch.com", "www.verge.com", "www.wired.com",
            "www.ars-technica.com", "www.engadget.com", "www.mashable.com", "www.gizmodo.com",
            "www.lifehacker.com", "www.kotaku.com", "www.jalopnik.com", "www.deadspin.com"
        ]
        
        self.normal_urls = [
            "http://www.victim-web.local/",
            "http://www.victim-web.local/about",
            "http://www.victim-web.local/contact", 
            "http://www.victim-web.local/products",
            "http://www.victim-web.local/services",
            "http://www.victim-web.local/help",
            "http://www.victim-web.local/faq",
            "http://www.victim-web.local/privacy",
            "http://www.victim-web.local/terms",
            "http://www.victim-web.local/sitemap"
        ]
        
        # DNS query types
        self.dns_query_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        # SMTP servers
        self.smtp_servers = [
            "smtp.gmail.com", "smtp.outlook.com", "smtp.yahoo.com",
            "smtp.office365.com", "smtp.zoho.com", "smtp.protonmail.com"
        ]
    
    def _parse_protocol_mix(self, protocol_mix: str) -> Dict[str, float]:
        """Parse protocol mix string into weights"""
        weights = {}
        for part in protocol_mix.split(','):
            protocol, weight = part.split(':')
            weights[protocol.lower()] = float(weight)
        return weights
    
    def generate_http_traffic(self):
        """Generate realistic HTTP traffic"""
        while self.running:
            try:
                # Select random URL
                url = random.choice(self.normal_urls)
                method = random.choice(['GET', 'POST', 'HEAD'])
                
                # Generate realistic user agent
                user_agents = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15'
                ]
                
                headers = {
                    'User-Agent': random.choice(user_agents),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                # Simulate request
                start_time = time.time()
                try:
                    response = requests.request(
                        method, url, headers=headers, timeout=5,
                        allow_redirects=True
                    )
                    response_time = time.time() - start_time
                    status_code = response.status_code
                    response_size = len(response.content)
                except:
                    response_time = random.uniform(0.1, 2.0)
                    status_code = random.choice([200, 404, 500])
                    response_size = random.randint(100, 5000)
                
                # Log HTTP traffic
                log_entry = f"{datetime.now().isoformat()}Z {method} {url} {status_code} {response_size}"
                
                with open(f"{self.output_dir}/http_proxy_raw.jsonl", 'a') as f:
                    f.write(log_entry + '\n')
                
                self.counters['http'] += 1
                
                # Random delay between requests
                time.sleep(random.uniform(1, 5))
                
            except Exception as e:
                print(f"HTTP traffic error: {e}")
                time.sleep(5)
    
    def generate_dns_traffic(self):
        """Generate realistic DNS traffic"""
        while self.running:
            try:
                # Select random domain and query type
                domain = random.choice(self.normal_domains)
                query_type = random.choice(self.dns_query_types)
                
                # Generate realistic DNS query
                record = {
                    "timestamp": datetime.now().isoformat() + "Z",
                    "query": domain,
                    "client_ip": f"172.16.0.{random.randint(10, 50)}",
                    "response": f"172.16.0.{random.randint(100, 200)}",
                    "record_type": query_type,
                    "is_attack": False,
                    "attack_stage": "normal",
                    "query_count": self.counters['dns'] + 1,
                    "source": "benign_traffic"
                }
                
                # Log DNS traffic
                with open(f"{self.output_dir}/dns_proxy_raw.jsonl", 'a') as f:
                    f.write(json.dumps(record, ensure_ascii=False) + '\n')
                
                self.counters['dns'] += 1
                
                # Random delay between queries
                time.sleep(random.uniform(0.5, 3))
                
            except Exception as e:
                print(f"DNS traffic error: {e}")
                time.sleep(3)
    
    def generate_smtp_traffic(self):
        """Generate realistic SMTP traffic"""
        while self.running:
            try:
                # Simulate SMTP session
                smtp_server = random.choice(self.smtp_servers)
                
                # Generate SMTP log entry
                smtp_log = {
                    "timestamp": datetime.now().isoformat() + "Z",
                    "server": smtp_server,
                    "client_ip": f"172.16.0.{random.randint(10, 50)}",
                    "action": random.choice(['CONNECT', 'AUTH', 'MAIL', 'RCPT', 'DATA', 'QUIT']),
                    "status": random.choice(['250', '220', '235', '354', '221']),
                    "is_attack": False,
                    "source": "benign_traffic"
                }
                
                # Log SMTP traffic
                with open(f"{self.output_dir}/smtp_proxy_raw.jsonl", 'a') as f:
                    f.write(json.dumps(smtp_log, ensure_ascii=False) + '\n')
                
                self.counters['smtp'] += 1
                
                # Random delay between SMTP sessions
                time.sleep(random.uniform(2, 10))
                
            except Exception as e:
                print(f"SMTP traffic error: {e}")
                time.sleep(5)
    
    def start(self):
        """Start benign traffic generation"""
        print(f"🚀 Starting benign traffic generator for variant: {self.variant_id}")
        print(f"📊 Protocol mix: {self.protocol_weights}")
        print(f"⏱️  Duration: {self.duration} seconds")
        
        self.running = True
        threads = []
        
        # Start HTTP traffic thread
        if self.protocol_weights.get('http', 0) > 0:
            http_thread = threading.Thread(target=self.generate_http_traffic)
            http_thread.daemon = True
            http_thread.start()
            threads.append(http_thread)
        
        # Start DNS traffic thread
        if self.protocol_weights.get('dns', 0) > 0:
            dns_thread = threading.Thread(target=self.generate_dns_traffic)
            dns_thread.daemon = True
            dns_thread.start()
            threads.append(dns_thread)
        
        # Start SMTP traffic thread
        if self.protocol_weights.get('smtp', 0) > 0:
            smtp_thread = threading.Thread(target=self.generate_smtp_traffic)
            smtp_thread.daemon = True
            smtp_thread.start()
            threads.append(smtp_thread)
        
        # Run for specified duration
        start_time = time.time()
        while time.time() - start_time < self.duration and self.running:
            time.sleep(1)
            
            # Print progress every 30 seconds
            elapsed = int(time.time() - start_time)
            if elapsed % 30 == 0:
                print(f"⏱️  Elapsed: {elapsed}s, HTTP: {self.counters['http']}, DNS: {self.counters['dns']}, SMTP: {self.counters['smtp']}")
        
        self.stop()
        
        # Print final statistics
        print(f"✅ Benign traffic generation completed!")
        print(f"📊 Final counts - HTTP: {self.counters['http']}, DNS: {self.counters['dns']}, SMTP: {self.counters['smtp']}")
    
    def stop(self):
        """Stop benign traffic generation"""
        self.running = False
        print("🛑 Stopping benign traffic generator...")

def main():
    parser = argparse.ArgumentParser(description="Generate benign traffic for security experiments")
    parser.add_argument("--variant-id", required=True, help="Variant ID")
    parser.add_argument("--mix", default="HTTP:0.7,DNS:0.2,SMTP:0.1", help="Protocol mix")
    parser.add_argument("--duration", type=int, default=300, help="Duration in seconds")
    parser.add_argument("--attack-aware", action="store_true", help="Attack-aware mode")
    
    args = parser.parse_args()
    
    generator = BenignTrafficGenerator(
        variant_id=args.variant_id,
        protocol_mix=args.mix,
        duration=args.duration,
        attack_aware=args.attack_aware
    )
    
    try:
        generator.start()
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        generator.stop()

if __name__ == "__main__":
    main() 