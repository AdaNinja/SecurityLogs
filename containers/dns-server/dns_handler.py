#!/usr/bin/env python3
"""
DNS Query Handler for Real C&C Communication
Processes DNS queries and generates dynamic responses
"""

import dns.resolver
import dns.zone
import dns.query
import dns.message
import dns.rdatatype
import dns.rdataclass
import base64
import json
import time
import os
import re
from datetime import datetime
from typing import Dict, Any, Optional

class DNSQueryHandler:
    """Handle DNS queries for C&C communication"""
    
    def __init__(self, zone_file: str = "/etc/bind/zones/attacker.local.zone"):
        self.zone_file = zone_file
        self.cc_commands = {}
        self.exfiltrated_data = {}
        self.query_log = []
        
        # Load existing zone data
        self.load_zone_data()
    
    def load_zone_data(self):
        """Load existing DNS zone data"""
        try:
            self.zone = dns.zone.from_file(self.zone_file, 'attacker.local')
        except Exception as e:
            print(f"Warning: Could not load zone file: {e}")
            self.zone = None
    
    def process_query(self, query_name: str, query_type: str) -> Optional[str]:
        """Process DNS query and return response"""
        timestamp = datetime.now().isoformat()
        
        # Log the query
        query_log = {
            "timestamp": timestamp,
            "query_name": query_name,
            "query_type": query_type,
            "source": "dns_handler"
        }
        
        # Check for C&C communication
        if query_name.startswith("cmd."):
            response = self.handle_cc_query(query_name)
            query_log["attack_type"] = "cc_communication"
            query_log["response"] = response
        elif query_name.startswith("exfil."):
            response = self.handle_exfiltration_query(query_name)
            query_log["attack_type"] = "data_exfiltration"
            query_log["response"] = response
        elif query_name.startswith("tunnel."):
            response = self.handle_tunnel_query(query_name)
            query_log["attack_type"] = "dns_tunnel"
            query_log["response"] = response
        else:
            response = self.handle_normal_query(query_name, query_type)
            query_log["attack_type"] = "normal_query"
            query_log["response"] = response
        
        # Save query log
        self.query_log.append(query_log)
        self.save_query_log()
        
        return response
    
    def handle_cc_query(self, query_name: str) -> str:
        """Handle command and control queries"""
        try:
            # Extract encoded command from query
            # Format: cmd.<base64_encoded_command>.attacker.local
            parts = query_name.split('.')
            if len(parts) >= 2:
                encoded_command = parts[1]
                command = base64.b64decode(encoded_command).decode('utf-8')
                
                # Simulate command execution
                execution_result = self.execute_command(command)
                
                # Store command and result
                self.cc_commands[encoded_command] = {
                    "command": command,
                    "result": execution_result,
                    "timestamp": time.time()
                }
                
                # Return execution result as IP address
                # Convert result to numeric IP for DNS response
                result_hash = hash(execution_result) % 255
                response_ip = f"172.16.0.{result_hash}"
                
                print(f"C&C Query: {command} -> {execution_result} -> {response_ip}")
                return response_ip
                
        except Exception as e:
            print(f"Error processing C&C query: {e}")
        
        return "172.16.0.10"  # Default response
    
    def handle_exfiltration_query(self, query_name: str) -> str:
        """Handle data exfiltration queries"""
        try:
            # Extract encoded data from query
            # Format: exfil.<base64_encoded_data>.attacker.local
            parts = query_name.split('.')
            if len(parts) >= 2:
                encoded_data = parts[1]
                data = base64.b64decode(encoded_data).decode('utf-8')
                
                # Store exfiltrated data
                self.exfiltrated_data[time.time()] = {
                    "data": data,
                    "query": query_name,
                    "timestamp": datetime.now().isoformat()
                }
                
                print(f"Data Exfiltration: {data[:50]}...")
                return "172.16.0.20"  # Exfiltration success
                
        except Exception as e:
            print(f"Error processing exfiltration query: {e}")
        
        return "172.16.0.21"  # Exfiltration failure
    
    def handle_tunnel_query(self, query_name: str) -> str:
        """Handle DNS tunnel queries"""
        try:
            # Extract tunnel data from query
            # Format: tunnel.<encoded_data>.attacker.local
            parts = query_name.split('.')
            if len(parts) >= 2:
                tunnel_data = parts[1]
                
                # Process tunnel data
                tunnel_result = self.process_tunnel_data(tunnel_data)
                
                print(f"DNS Tunnel: {tunnel_data[:30]}... -> {tunnel_result}")
                return "172.16.0.30"  # Tunnel success
                
        except Exception as e:
            print(f"Error processing tunnel query: {e}")
        
        return "172.16.0.31"  # Tunnel failure
    
    def handle_normal_query(self, query_name: str, query_type: str) -> str:
        """Handle normal DNS queries"""
        # Check if query exists in zone
        if self.zone and query_name in self.zone:
            node = self.zone[query_name]
            for rdataset in node.rdatasets:
                if rdataset.rdtype == dns.rdatatype.from_text(query_type):
                    return str(rdataset[0])
        
        # Return default response for attacker.local domain
        if query_name.endswith('.attacker.local'):
            return "172.16.0.10"
        
        return None
    
    def execute_command(self, command: str) -> str:
        """Simulate command execution"""
        command_results = {
            "whoami": "attacker",
            "hostname": "attacker-container",
            "pwd": "/opt/scripts",
            "ls -la": "total 1234\ndrwxr-xr-x 1 root root 4096 Jul 23 09:00 .\n-rw-r--r-- 1 root root 1234 Jul 23 09:00 attack_script.py",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nattacker:x:1000:1000:attacker:/home/attacker:/bin/bash",
            "netstat -tuln": "Active Internet connections (only servers)\ntcp 0 0 0.0.0.0:53 0.0.0.0:* LISTEN",
            "ps aux": "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.0 0.1 12345 6789 ? Ss 09:00 0:00 /usr/sbin/named",
            "uname -a": "Linux attacker-container 5.15.0-143-generic #143-Ubuntu SMP x86_64 GNU/Linux"
        }
        
        return command_results.get(command, f"Command executed: {command}")
    
    def process_tunnel_data(self, tunnel_data: str) -> str:
        """Process DNS tunnel data"""
        try:
            # Try to decode as base64
            decoded = base64.b64decode(tunnel_data).decode('utf-8')
            return f"Tunnel data decoded: {decoded[:50]}..."
        except:
            # Return as hex
            return f"Tunnel data (hex): {tunnel_data[:50]}..."
    
    def save_query_log(self):
        """Save query log to file"""
        log_file = "/var/log/dns-server/query_handler.log"
        try:
            with open(log_file, 'w') as f:
                json.dump(self.query_log, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving query log: {e}")
    
    def get_cc_commands(self) -> Dict[str, Any]:
        """Get all C&C commands"""
        return self.cc_commands
    
    def get_exfiltrated_data(self) -> Dict[str, Any]:
        """Get all exfiltrated data"""
        return self.exfiltrated_data
    
    def get_query_log(self) -> list:
        """Get query log"""
        return self.query_log

if __name__ == "__main__":
    # Test DNS handler
    handler = DNSQueryHandler()
    
    # Test C&C query
    response = handler.process_query("cmd.d2hvYW1p.attacker.local", "A")
    print(f"C&C Response: {response}")
    
    # Test exfiltration query
    response = handler.process_query("exfil.c2Vuc2l0aXZlX2RhdGE=.attacker.local", "A")
    print(f"Exfiltration Response: {response}") 