#!/usr/bin/env python3
"""
Attack Simulation Script
Simulates various attack patterns for comparison with benign activities
"""

import os
import time
import subprocess
import threading
from datetime import datetime

class AttackSimulator:
    def __init__(self, target_host="172.16.218.130", target_port="80"):
        self.target_host = target_host
        self.target_port = target_port
        self.target_url = f"http://{target_host}:{target_port}"
        
    def simulate_slow_http_attack(self, duration=300):
        """Simulate slow HTTP attack (similar to FiberFox SLOW strategy)"""
        print(f"🚀 Starting SLOW HTTP attack simulation for {duration}s...")
        
        # Create attack directory
        os.makedirs("attack_test/slow_http", exist_ok=True)
        
        # Start tcpdump for traffic capture
        self.start_traffic_capture("attack_test/slow_http/attack_traffic.pcap")
        
        # Simulate slow HTTP attack patterns
        threads = []
        for i in range(5):  # 5 concurrent connections
            thread = threading.Thread(
                target=self.slow_http_worker,
                args=(i, duration)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Stop traffic capture
        self.stop_traffic_capture()
        print("✅ SLOW HTTP attack simulation completed")
    
    def slow_http_worker(self, worker_id, duration):
        """Individual worker for slow HTTP attack"""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                # Simulate slow HTTP request
                cmd = [
                    "curl", "-s", "--max-time", "30",
                    "--connect-timeout", "10",
                    "--header", "User-Agent: Mozilla/5.0 (compatible; SlowBot/1.0)",
                    "--header", f"X-Attack-Worker: {worker_id}",
                    self.target_url
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Log the request
                with open(f"attack_test/slow_http/worker_{worker_id}.log", "a") as f:
                    timestamp = datetime.now().isoformat()
                    f.write(f"{timestamp} - Worker {worker_id} - Status: {result.returncode}\n")
                
                # Slow down between requests
                time.sleep(2 + worker_id * 0.5)
                
            except Exception as e:
                print(f"❌ Worker {worker_id} error: {e}")
                time.sleep(5)
    
    def simulate_get_flood_attack(self, duration=300):
        """Simulate GET flood attack (similar to FiberFox GET strategy)"""
        print(f"🚀 Starting GET flood attack simulation for {duration}s...")
        
        os.makedirs("attack_test/get_flood", exist_ok=True)
        self.start_traffic_capture("attack_test/get_flood/attack_traffic.pcap")
        
        threads = []
        for i in range(10):  # 10 concurrent connections
            thread = threading.Thread(
                target=self.get_flood_worker,
                args=(i, duration)
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        self.stop_traffic_capture()
        print("✅ GET flood attack simulation completed")
    
    def get_flood_worker(self, worker_id, duration):
        """Individual worker for GET flood attack"""
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Rapid GET requests
                cmd = [
                    "curl", "-s", "--max-time", "5",
                    "--connect-timeout", "3",
                    "--header", "User-Agent: Mozilla/5.0 (compatible; FloodBot/1.0)",
                    "--header", f"X-Attack-Worker: {worker_id}",
                    self.target_url
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                request_count += 1
                
                # Log every 10th request
                if request_count % 10 == 0:
                    with open(f"attack_test/get_flood/worker_{worker_id}.log", "a") as f:
                        timestamp = datetime.now().isoformat()
                        f.write(f"{timestamp} - Worker {worker_id} - Requests: {request_count} - Status: {result.returncode}\n")
                
                # Minimal delay for flood effect
                time.sleep(0.1)
                
            except Exception as e:
                print(f"❌ Worker {worker_id} error: {e}")
                time.sleep(1)
    
    def simulate_bypass_attack(self, duration=300):
        """Simulate bypass attack (similar to FiberFox BYPASS strategy)"""
        print(f"🚀 Starting BYPASS attack simulation for {duration}s...")
        
        os.makedirs("attack_test/bypass", exist_ok=True)
        self.start_traffic_capture("attack_test/bypass/attack_traffic.pcap")
        
        threads = []
        for i in range(3):  # 3 concurrent connections
            thread = threading.Thread(
                target=self.bypass_worker,
                args=(i, duration)
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        self.stop_traffic_capture()
        print("✅ BYPASS attack simulation completed")
    
    def bypass_worker(self, worker_id, duration):
        """Individual worker for bypass attack"""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                # Try different bypass techniques
                bypass_techniques = [
                    ["--header", "X-Forwarded-For: 127.0.0.1"],
                    ["--header", "X-Real-IP: 192.168.1.1"],
                    ["--header", "X-Originating-IP: 10.0.0.1"],
                    ["--header", "CF-Connecting-IP: 172.16.0.1"],
                    ["--user-agent", "Googlebot/2.1 (+http://www.google.com/bot.html)"],
                    ["--user-agent", "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"]
                ]
                
                for technique in bypass_techniques:
                    cmd = [
                        "curl", "-s", "--max-time", "10",
                        "--connect-timeout", "5"
                    ] + technique + [
                        "--header", f"X-Attack-Worker: {worker_id}",
                        self.target_url
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    # Log bypass attempts
                    with open(f"attack_test/bypass/worker_{worker_id}.log", "a") as f:
                        timestamp = datetime.now().isoformat()
                        technique_name = technique[1] if len(technique) > 1 else technique[0]
                        f.write(f"{timestamp} - Worker {worker_id} - Technique: {technique_name} - Status: {result.returncode}\n")
                    
                    time.sleep(1)
                
                # Wait between bypass rounds
                time.sleep(5)
                
            except Exception as e:
                print(f"❌ Worker {worker_id} error: {e}")
                time.sleep(5)
    
    def start_traffic_capture(self, output_file):
        """Start tcpdump traffic capture"""
        try:
            # Start tcpdump in background
            cmd = [
                "sudo", "tcpdump", "-i", "any", 
                "-w", output_file,
                "host", self.target_host
            ]
            self.tcpdump_process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            print(f"📡 Started traffic capture: {output_file}")
        except Exception as e:
            print(f"❌ Failed to start traffic capture: {e}")
    
    def stop_traffic_capture(self):
        """Stop tcpdump traffic capture"""
        try:
            if hasattr(self, 'tcpdump_process'):
                self.tcpdump_process.terminate()
                self.tcpdump_process.wait()
                print("📡 Stopped traffic capture")
        except Exception as e:
            print(f"❌ Failed to stop traffic capture: {e}")
    
    def run_all_attacks(self, duration=300):
        """Run all attack simulations"""
        print("🎯 Starting comprehensive attack simulation...")
        
        # Create main attack directory
        os.makedirs("attack_test", exist_ok=True)
        
        # Run each attack type
        self.simulate_slow_http_attack(duration)
        time.sleep(10)  # Wait between attacks
        
        self.simulate_get_flood_attack(duration)
        time.sleep(10)
        
        self.simulate_bypass_attack(duration)
        
        print("🎉 All attack simulations completed!")
        print("📁 Results saved in attack_test/ directory")

def main():
    # Configuration
    target_host = "172.16.218.130"  # Your target host
    target_port = "80"              # Your target port
    attack_duration = 300           # 5 minutes per attack
    
    # Create simulator
    simulator = AttackSimulator(target_host, target_port)
    
    # Run attacks
    simulator.run_all_attacks(attack_duration)

if __name__ == "__main__":
    main() 