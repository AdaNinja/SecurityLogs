#!/usr/bin/env python3
"""
Real Network Scanning Script
Performs actual network reconnaissance and port scanning
"""

import nmap
import time
import random
import sys
import os
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/logs/network_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class NetworkScanner:
    def __init__(self, target_host, scan_rate=0.016):
        self.target_host = target_host
        self.scan_rate = scan_rate  # Packets per second
        self.nm = nmap.PortScanner()
        
        logging.info(f"Initialized Network Scanner")
        logging.info(f"Target: {target_host}")
        logging.info(f"Scan Rate: {scan_rate} packets/sec")

    def perform_host_discovery(self):
        """Perform host discovery scan"""
        try:
            logging.info("Phase 1: Host Discovery...")
            
            # Slow ping scan to discover hosts
            scan_args = f"-sn -PE -n --max-retries 1 --min-rate {self.scan_rate}"
            self.nm.scan(hosts=self.target_host, arguments=scan_args)
            
            discovered_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    discovered_hosts.append(host)
                    logging.info(f"Discovered host: {host}")
            
            logging.info(f"Host discovery completed. Found {len(discovered_hosts)} hosts")
            return discovered_hosts
            
        except Exception as e:
            logging.error(f"Error in host discovery: {e}")
            return []

    def perform_port_scan(self, hosts):
        """Perform slow port scanning"""
        try:
            logging.info("Phase 2: Port Scanning...")
            
            scan_results = {}
            
            for host in hosts:
                logging.info(f"Scanning ports on {host}...")
                
                # Slow TCP SYN scan
                scan_args = f"-sS -p- --min-rate {self.scan_rate} --max-retries 2"
                self.nm.scan(hosts=host, arguments=scan_args)
                
                if host in self.nm.all_hosts():
                    open_ports = []
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            if self.nm[host][proto][port]['state'] == 'open':
                                open_ports.append(port)
                                logging.info(f"Open port on {host}: {port}/{proto}")
                    
                    scan_results[host] = {
                        'open_ports': open_ports,
                        'scan_time': datetime.now().isoformat()
                    }
                
                # Random delay between hosts
                time.sleep(random.uniform(2, 5))
            
            logging.info(f"Port scanning completed for {len(hosts)} hosts")
            return scan_results
            
        except Exception as e:
            logging.error(f"Error in port scanning: {e}")
            return {}

    def perform_service_detection(self, scan_results):
        """Perform service detection on open ports"""
        try:
            logging.info("Phase 3: Service Detection...")
            
            service_results = {}
            
            for host, data in scan_results.items():
                if not data['open_ports']:
                    continue
                    
                logging.info(f"Detecting services on {host}...")
                
                # Service detection scan
                ports_str = ','.join(map(str, data['open_ports']))
                scan_args = f"-sV -p {ports_str} --min-rate {self.scan_rate} --version-intensity 2"
                self.nm.scan(hosts=host, arguments=scan_args)
                
                if host in self.nm.all_hosts():
                    services = {}
                    for proto in self.nm[host].all_protocols():
                        for port in self.nm[host][proto]:
                            service_info = self.nm[host][proto][port]
                            if service_info['state'] == 'open':
                                services[port] = {
                                    'service': service_info.get('name', 'unknown'),
                                    'version': service_info.get('version', ''),
                                    'product': service_info.get('product', ''),
                                    'extrainfo': service_info.get('extrainfo', '')
                                }
                                logging.info(f"Service on {host}:{port} - {service_info.get('name', 'unknown')} {service_info.get('version', '')}")
                    
                    service_results[host] = services
                
                # Random delay between hosts
                time.sleep(random.uniform(3, 7))
            
            logging.info("Service detection completed")
            return service_results
            
        except Exception as e:
            logging.error(f"Error in service detection: {e}")
            return {}

    def perform_vulnerability_scan(self, service_results):
        """Perform basic vulnerability scanning"""
        try:
            logging.info("Phase 4: Vulnerability Scanning...")
            
            vuln_results = {}
            
            for host, services in service_results.items():
                logging.info(f"Scanning vulnerabilities on {host}...")
                
                host_vulns = []
                
                for port, service_info in services.items():
                    service_name = service_info['service'].lower()
                    
                    # Check for common vulnerable services
                    if service_name in ['http', 'https']:
                        host_vulns.append({
                            'port': port,
                            'service': service_name,
                            'vulnerability': 'Web application - potential SQL injection, XSS, etc.',
                            'severity': 'Medium'
                        })
                        
                    elif service_name in ['ssh']:
                        host_vulns.append({
                            'port': port,
                            'service': service_name,
                            'vulnerability': 'SSH service - potential brute force, weak keys',
                            'severity': 'Medium'
                        })
                        
                    elif service_name in ['ftp']:
                        host_vulns.append({
                            'port': port,
                            'service': service_name,
                            'vulnerability': 'FTP service - potential anonymous access, weak auth',
                            'severity': 'High'
                        })
                        
                    elif service_name in ['telnet']:
                        host_vulns.append({
                            'port': port,
                            'service': service_name,
                            'vulnerability': 'Telnet service - cleartext authentication',
                            'severity': 'Critical'
                        })
                
                vuln_results[host] = host_vulns
                
                # Random delay
                time.sleep(random.uniform(1, 3))
            
            logging.info("Vulnerability scanning completed")
            return vuln_results
            
        except Exception as e:
            logging.error(f"Error in vulnerability scanning: {e}")
            return {}

    def run_scan(self):
        """Run complete network reconnaissance"""
        logging.info("Starting Network Reconnaissance...")
        
        # Phase 1: Host Discovery
        hosts = self.perform_host_discovery()
        if not hosts:
            logging.error("No hosts discovered")
            return None
        
        # Phase 2: Port Scanning
        port_results = self.perform_port_scan(hosts)
        
        # Phase 3: Service Detection
        service_results = self.perform_service_detection(port_results)
        
        # Phase 4: Vulnerability Assessment
        vuln_results = self.perform_vulnerability_scan(service_results)
        
        # Compile results
        scan_summary = {
            'timestamp': datetime.now().isoformat(),
            'target_host': self.target_host,
            'scan_rate': self.scan_rate,
            'discovered_hosts': len(hosts),
            'hosts': hosts,
            'port_scan_results': port_results,
            'service_results': service_results,
            'vulnerability_results': vuln_results
        }
        
        logging.info(f"Network reconnaissance completed")
        logging.info(f"Discovered {len(hosts)} hosts")
        
        return scan_summary

def main():
    # Get configuration from environment
    target_host = os.getenv('TARGET_HOST', 'victim-web')
    scan_rate = float(os.getenv('NMAP_RATE', '0.016'))
    
    # Create scanner instance
    scanner = NetworkScanner(target_host, scan_rate)
    
    # Run scan
    results = scanner.run_scan()
    
    if results:
        # Save results
        output_file = '/opt/output/network_scan_results.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logging.info(f"Scan results saved to {output_file}")
        
        # Print summary
        print(f"\n=== Network Scan Summary ===")
        print(f"Target: {target_host}")
        print(f"Hosts discovered: {results['discovered_hosts']}")
        print(f"Scan completed: {results['timestamp']}")
        
        for host in results['hosts']:
            if host in results['port_scan_results']:
                open_ports = len(results['port_scan_results'][host]['open_ports'])
                print(f"  {host}: {open_ports} open ports")
    else:
        logging.error("Scan failed")

if __name__ == "__main__":
    main() 