#!/usr/bin/env python3
"""
Nginx Log Parser
Parses nginx access and error logs and outputs unified CSV format
"""

import re
from typing import Dict, Optional, Any
from base_parser import BaseParser


class NginxParser(BaseParser):
    """
    Parser for nginx access and error logs
    Extracts HTTP request information and error details
    """
    
    def _get_source_type(self) -> str:
        return "nginx"
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse nginx log line
        
        Expected formats:
        - Access log: 192.168.1.100 - - [10/Oct/2023:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."
        - Error log: 2023/10/10 13:55:36 [error] 1234#0: *5678 connect() failed (111: Connection refused)
        
        Returns:
            Dict: Parsed data or None if parsing failed
        """
        try:
            # Try access log format first
            if 'HTTP/' in line and '"' in line:
                return self._parse_access_line(line)
            
            # Try error log format
            if '[error]' in line or '[warn]' in line or '[info]' in line:
                return self._parse_error_line(line)
            
            # Try combined format
            if ' - - [' in line and '] "' in line:
                return self._parse_combined_line(line)
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to parse nginx line: {e}")
            return None
    
    def _parse_access_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse nginx access log line"""
        try:
            # Pattern: IP - - [timestamp] "METHOD path HTTP/version" status size "referer" "user_agent"
            pattern = r'^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            ip_src, timestamp_str, request, status_code, size, referer, user_agent = match.groups()
            
            # Parse request line
            request_parts = request.split()
            if len(request_parts) >= 2:
                method = request_parts[0]
                path = request_parts[1]
            else:
                method = "UNKNOWN"
                path = "/"
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine event type and severity
            event_type = "http_request"
            severity = "info"
            if status_code.startswith('4'):
                severity = "warning"
                event_type = "http_error"
            elif status_code.startswith('5'):
                severity = "error"
                event_type = "http_error"
            
            # Detect attack patterns
            label = self.detect_attack(request + " " + user_agent)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
                'severity': severity,
                'message': f"{method} {path} - {status_code}",
                'ip_src': ip_src,
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': 'HTTP',
                'user_agent': user_agent,
                'request_method': method,
                'request_path': path,
                'response_code': status_code,
                'payload': request,
                'label': label
            }
            
        except Exception:
            return None
    
    def _parse_error_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse nginx error log line"""
        try:
            # Pattern: timestamp [level] pid#tid: *cid message
            pattern = r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): \*(\d+) (.+)$'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            timestamp_str, level, pid, tid, cid, message = match.groups()
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine severity
            severity_map = {
                'error': 'error',
                'warn': 'warning',
                'info': 'info',
                'debug': 'debug'
            }
            severity = severity_map.get(level.lower(), 'info')
            
            # Detect attack patterns
            label = self.detect_attack(message)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': 'nginx_error',
                'severity': severity,
                'message': message,
                'ip_src': '',
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': '',
                'user_agent': '',
                'request_method': '',
                'request_path': '',
                'response_code': '',
                'payload': message,
                'label': label
            }
            
        except Exception:
            return None
    
    def _parse_combined_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse nginx combined/detailed log line"""
        try:
            # Try detailed log format first (with attack headers)
            # Format: IP - - [timestamp] "METHOD path HTTP/version" status size "referer" "user_agent" "attack-id" "payload-id" "timestamp" "real-ip" "traffic-type" "attack-type" "chain-id" "phase"
            detailed_pattern = r'^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)"'
            match = re.match(detailed_pattern, line)
            
            if match:
                # Parse detailed format
                groups = match.groups()
                ip_src = groups[0]
                timestamp_str = groups[1]
                request = groups[2]
                status_code = groups[3]
                size = groups[4]
                referer = groups[5]
                user_agent = groups[6]
                attack_id = groups[7]
                payload_id = groups[8]
                attack_timestamp = groups[9]
                real_ip = groups[10]
                traffic_type = groups[11]
                attack_type = groups[12]
                chain_id = groups[13]
                phase = groups[14]
                
                # Parse request line
                request_parts = request.split()
                if len(request_parts) >= 2:
                    method = request_parts[0]
                    path = request_parts[1]
                else:
                    method = "UNKNOWN"
                    path = "/"
                
                # Normalize timestamp
                normalized_timestamp = self.normalize_timestamp(timestamp_str)
                
                # Determine event type and severity
                event_type = "http_request"
                severity = "info"
                if status_code.startswith('4'):
                    severity = "warning"
                    event_type = "http_error"
                elif status_code.startswith('5'):
                    severity = "error"
                    event_type = "http_error"
                
                # Determine label from traffic type
                label = 1 if traffic_type == "attack" else 0
                
                return {
                    'timestamp': normalized_timestamp,
                    'source_type': self.source_type,
                    'source_name': self.source_name,
                    'event_type': event_type,
                    'severity': severity,
                    'message': f"{method} {path} - {status_code}",
                    'ip_src': ip_src,
                    'ip_dst': '',
                    'port_src': '',
                    'port_dst': '',
                    'protocol': 'HTTP',
                    'user_agent': user_agent,
                    'request_method': method,
                    'request_path': path,
                    'response_code': status_code,
                    'payload': attack_id if attack_id != "-" else payload_id,
                    'label': label,
                    # Additional fields for detailed analysis
                    'attack_type': attack_type if attack_type != "-" else '',
                    'chain_id': chain_id if chain_id != "-" else '',
                    'phase': phase if phase != "-" else ''
                }
            
            # Fall back to standard combined format
            # Pattern: IP - - [timestamp] "METHOD path HTTP/version" status size "referer" "user_agent"
            pattern = r'^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            ip_src, timestamp_str, request, status_code, size, referer, user_agent = match.groups()
            
            # Parse request line
            request_parts = request.split()
            if len(request_parts) >= 2:
                method = request_parts[0]
                path = request_parts[1]
            else:
                method = "UNKNOWN"
                path = "/"
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine event type and severity
            event_type = "http_request"
            severity = "info"
            if status_code.startswith('4'):
                severity = "warning"
                event_type = "http_error"
            elif status_code.startswith('5'):
                severity = "error"
                event_type = "http_error"
            
            # Detect attack patterns
            label = self.detect_attack(request + " " + user_agent)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
                'severity': severity,
                'message': f"{method} {path} - {status_code}",
                'ip_src': ip_src,
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': 'HTTP',
                'user_agent': user_agent,
                'request_method': method,
                'request_path': path,
                'response_code': status_code,
                'payload': request,
                'label': label
            }
            
        except Exception:
            return None 