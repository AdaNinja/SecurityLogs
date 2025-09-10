#!/usr/bin/env python3
"""
PCAP Network Traffic Parser
Parses PCAP files and outputs unified CSV format
"""

import re
from typing import Dict, Optional, Any
from base_parser import BaseParser


class PcapParser(BaseParser):
    """
    Parser for PCAP network traffic files
    Extracts network flow information
    """
    
    def _get_source_type(self) -> str:
        return "pcap"
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse PCAP log line (from tcpdump or similar tools)
        
        Expected format:
        10:30:45.123456 IP 192.168.1.100.12345 > 10.0.0.1.80: Flags [P], seq 1:100, ack 1, win 65535, length 99: HTTP: GET /api/users HTTP/1.1
        
        Returns:
            Dict: Parsed data or None if parsing failed
        """
        try:
            # Try different PCAP line formats
            if 'IP' in line and '>' in line:
                return self._parse_ip_line(line)
            elif 'TCP' in line or 'UDP' in line:
                return self._parse_protocol_line(line)
            else:
                return self._parse_generic_line(line)
                
        except Exception as e:
            self.logger.warning(f"Failed to parse PCAP line: {e}")
            return None
    
    def _parse_ip_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse IP traffic line"""
        try:
            # Pattern: timestamp interface direction IP src_ip.src_port > dst_ip.dst_port: details
            # or: timestamp IP src_ip.src_port > dst_ip.dst_port: details
            pattern1 = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{6})\s+\S+\s+\S+\s+IP\s+(\S+)\.(\d+)\s*>\s*(\S+)\.(\d+):\s*(.+)'
            pattern2 = r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(\S+)\.(\d+)\s*>\s*(\S+)\.(\d+):\s*(.+)'
            
            match = re.match(pattern1, line)
            if not match:
                match = re.match(pattern2, line)
            
            if not match:
                return None
            
            if len(match.groups()) == 6:
                # Pattern1: with interface
                timestamp_str, ip_src, port_src, ip_dst, port_dst, details = match.groups()
            else:
                # Pattern2: without interface
                timestamp_str, ip_src, port_src, ip_dst, port_dst, details = match.groups()
            
            # Normalize timestamp (add date if not present)
            if not timestamp_str.startswith('2025'):
                timestamp_str = f"2025-08-04 {timestamp_str}"
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Extract protocol and additional info
            protocol, event_type, severity = self._extract_protocol_info(details)
            
            # Detect attack
            label = self.detect_attack(details)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
                'severity': severity,
                'message': details,
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'port_src': port_src,
                'port_dst': port_dst,
                'protocol': protocol,
                'user_agent': '',
                'request_method': '',
                'request_path': '',
                'response_code': '',
                'payload': details,
                'label': label
            }
            
        except Exception:
            return None
    
    def _parse_protocol_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse TCP/UDP specific line"""
        try:
            # Pattern: timestamp protocol src_ip.src_port > dst_ip.dst_port: details
            pattern = r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+(TCP|UDP)\s+(\S+)\.(\d+)\s*>\s*(\S+)\.(\d+):\s*(.+)'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            timestamp_str, protocol, ip_src, port_src, ip_dst, port_dst, details = match.groups()
            
            # Normalize timestamp
            if not timestamp_str.startswith('2025'):
                timestamp_str = f"2025-08-04 {timestamp_str}"
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Extract additional info
            event_type, severity = self._classify_protocol_event(protocol, details)
            
            # Detect attack
            label = self.detect_attack(details)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
                'severity': severity,
                'message': details,
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'port_src': port_src,
                'port_dst': port_dst,
                'protocol': protocol,
                'user_agent': '',
                'request_method': '',
                'request_path': '',
                'response_code': '',
                'payload': details,
                'label': label
            }
            
        except Exception:
            return None
    
    def _parse_generic_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse generic PCAP line"""
        try:
            # Try to extract basic information
            timestamp_match = re.search(r'(\d{2}:\d{2}:\d{2}\.\d{6})', line)
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            
            if not timestamp_match:
                return None
            
            timestamp_str = timestamp_match.group(1)
            if not timestamp_str.startswith('2025'):
                timestamp_str = f"2025-08-04 {timestamp_str}"
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Extract IP addresses
            ip_src = ip_matches[0] if len(ip_matches) > 0 else ''
            ip_dst = ip_matches[1] if len(ip_matches) > 1 else ''
            
            # Detect attack
            label = self.detect_attack(line)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': 'network',
                'severity': 'info',
                'message': line,
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'port_src': '',
                'port_dst': '',
                'protocol': 'IP',
                'user_agent': '',
                'request_method': '',
                'request_path': '',
                'response_code': '',
                'payload': line,
                'label': label
            }
            
        except Exception:
            return None
    
    def _extract_protocol_info(self, details: str) -> tuple:
        """
        Extract protocol information from packet details
        
        Args:
            details: Packet details string
            
        Returns:
            tuple: (protocol, event_type, severity)
        """
        details_lower = details.lower()
        
        # Determine protocol
        if 'tcp' in details_lower:
            protocol = 'TCP'
        elif 'udp' in details_lower:
            protocol = 'UDP'
        elif 'icmp' in details_lower:
            protocol = 'ICMP'
        else:
            protocol = 'IP'
        
        # Determine event type and severity
        if 'http' in details_lower:
            event_type = 'http_request'
            severity = 'info'
        elif 'syn' in details_lower:
            event_type = 'connection_attempt'
            severity = 'info'
        elif 'rst' in details_lower:
            event_type = 'connection_reset'
            severity = 'warning'
        elif 'fin' in details_lower:
            event_type = 'connection_close'
            severity = 'info'
        else:
            event_type = 'network_traffic'
            severity = 'info'
        
        return protocol, event_type, severity
    
    def _classify_protocol_event(self, protocol: str, details: str) -> tuple:
        """
        Classify protocol event type and severity
        
        Args:
            protocol: Protocol (TCP, UDP, etc.)
            details: Packet details
            
        Returns:
            tuple: (event_type, severity)
        """
        details_lower = details.lower()
        
        # Check for suspicious patterns
        if any(pattern in details_lower for pattern in ['syn flood', 'port scan', 'brute force']):
            return 'attack', 'error'
        
        # Check for connection issues
        if any(pattern in details_lower for pattern in ['connection refused', 'timeout', 'reset']):
            return 'connection_error', 'warning'
        
        # Normal traffic
        return 'network_traffic', 'info'
    
    def parse_tcpdump_output(self, tcpdump_output: str, output_file: str) -> int:
        """
        Parse tcpdump output directly
        
        Args:
            tcpdump_output: Raw tcpdump output
            output_file: Output CSV file path
            
        Returns:
            int: Number of parsed lines
        """
        lines = tcpdump_output.strip().split('\n')
        parsed_count = 0
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
                import csv
                writer = csv.writer(outfile)
                writer.writerow(self.CSV_HEADERS)
                
                for line in lines:
                    if line.strip():
                        parsed_data = self.parse_line(line)
                        if parsed_data:
                            row = self.create_csv_row(parsed_data)
                            writer.writerow(row)
                            parsed_count += 1
            
            self.logger.info(f"Parsed {parsed_count} lines from tcpdump output to {output_file}")
            return parsed_count
            
        except Exception as e:
            self.logger.error(f"Failed to parse tcpdump output: {e}")
            return 0


# Example usage
if __name__ == "__main__":
    import logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Test parser
    parser = PcapParser("network_capture")
    
    # Test lines
    test_lines = [
        '10:30:45.123456 IP 192.168.1.100.12345 > 10.0.0.1.80: Flags [P], seq 1:100, ack 1, win 65535, length 99: HTTP: GET /api/users?id=1\' OR 1=1-- HTTP/1.1',
        '10:30:46.234567 TCP 192.168.1.100.12346 > 10.0.0.1.443: Flags [S], seq 1234567890, win 65535, options [mss 1460]',
        '10:30:47.345678 UDP 192.168.1.100.12347 > 8.8.8.8.53: 12345+ A? example.com'
    ]
    
    for i, test_line in enumerate(test_lines, 1):
        print(f"\n--- Test {i} ---")
        result = parser.parse_line(test_line)
        if result:
            print("✅ PCAP line parsed successfully!")
            print(f"   - Timestamp: {result['timestamp']}")
            print(f"   - Protocol: {result['protocol']}")
            print(f"   - Source: {result['ip_src']}:{result['port_src']}")
            print(f"   - Destination: {result['ip_dst']}:{result['port_dst']}")
            print(f"   - Event Type: {result['event_type']}")
            print(f"   - Label: {result['label']}")
        else:
            print("❌ Failed to parse PCAP line") 