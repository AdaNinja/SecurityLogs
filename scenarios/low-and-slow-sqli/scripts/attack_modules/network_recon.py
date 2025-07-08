#!/usr/bin/env python3
"""
Network Reconnaissance Module for Attack Scenarios
Performs slow and stealthy network scanning
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
        logging.FileHandler('/opt/logs/network_recon.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class NetworkReconnaissance:
    def __init__(self, target_host, scan_rate=0.016, timeout=300):
        self.target_host = target_host
        self.scan_rate = scan_rate
        self.timeout = timeout
        self.nm = nmap.PortScanner()
        
        logging.info(f"Initialized Network Reconnaissance")
        logging.info(f"Target: {target_host}")
        logging.info(f"Scan Rate: {scan_rate} packets/sec")
        logging.info(f"Timeout: {timeout} seconds")

    def perform_host_discovery(self):
        """Perform slow host discovery"""
        try:
            logging.info("Phase 1: Host Discovery")
            
            # Very slow ping scan
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
            logging.info("Phase 2: Port Scanning")
            
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
                time.sleep(random.uniform(5, 15))
            
            logging.info(f"Port scanning completed for {len(hosts)} hosts")
            return scan_results
            
        except Exception as e:
            logging.error(f"Error in port scanning: {e}")
            return {}

    def perform_service_detection(self, scan_results):
        """Perform service detection on open ports"""
        try:
            logging.info("Phase 3: Service Detection")
            
            service_results = {}
            
            for host, data in scan_results.items():
                if not data['open_ports']:
                    continue
                    
                logging.info(f"Detecting services on {host}...")
                
                # Service detection scan
                ports_str = ','.join(map(str, data['open_ports']))
                scan_args = f"-sV -p {ports_str} --min-rate {self.scan_rate} --version-intensity 1"
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
                                    'product': service_info.get('product', '')
                                }
                                logging.info(f"Service on {host}:{port} - {service_info.get('name', 'unknown')}")
                    
                    service_results[host] = services
                
                # Random delay between hosts
                time.sleep(random.uniform(10, 20))
            
            logging.info("Service detection completed")
            return service_results
            
        except Exception as e:
            logging.error(f"Error in service detection: {e}")
            return {}

    def run_reconnaissance(self):
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
        
        # Compile results
        recon_summary = {
            'timestamp': datetime.now().isoformat(),
            'target_host': self.target_host,
            'scan_rate': self.scan_rate,
            'discovered_hosts': len(hosts),
            'hosts': hosts,
            'port_scan_results': port_results,
            'service_results': service_results
        }
        
        logging.info(f"Network reconnaissance completed")
        logging.info(f"Discovered {len(hosts)} hosts")
        
        return recon_summary

def main():
    # Get configuration from environment
    target_host = os.getenv('TARGET_HOST', 'victim-web')
    scan_rate = float(os.getenv('NMAP_RATE', '0.016'))
    timeout = int(os.getenv('PORT_SCAN_TIMEOUT', '300'))
    
    # Create reconnaissance instance
    recon = NetworkReconnaissance(target_host, scan_rate, timeout)
    
    # Run reconnaissance
    results = recon.run_reconnaissance()
    
    if results:
        # Save results
        output_file = '/opt/output/network_recon_results.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logging.info(f"Reconnaissance results saved to {output_file}")
    else:
        logging.error("Reconnaissance failed")

if __name__ == "__main__":
    main() 