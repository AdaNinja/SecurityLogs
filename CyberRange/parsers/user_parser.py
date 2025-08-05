#!/usr/bin/env python3
"""
User Behavior Log Parser
Parses user behavior logs and outputs unified CSV format
"""

import re
import json
from typing import Dict, Optional, Any
from base_parser import BaseParser


class ApplicationParser(BaseParser):
    """
    Parser for application logs
    Supports various application log formats
    """
    
    def _get_source_type(self) -> str:
        return "application"
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse application log line
        
        Expected formats:
        - JSON format: {"timestamp":"2025-08-04T10:30:45.123Z","level":"ERROR","message":"SQL injection attempt"}
        - Standard format: [2025-08-04T10:30:45.123Z] ERROR: SQL injection attempt detected
        - Simple format: 2025-08-04 10:30:45 ERROR SQL injection attempt
        
        Returns:
            Dict: Parsed data or None if parsing failed
        """
        try:
            # Try JSON format first
            if line.strip().startswith('{'):
                return self._parse_json_line(line)
            
            # Try standard format
            if '[' in line and ']' in line:
                return self._parse_standard_line(line)
            
            # Try simple format
            return self._parse_simple_line(line)
            
        except Exception as e:
            self.logger.warning(f"Failed to parse application line: {e}")
            return None
    
    def _parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON format log line"""
        try:
            data = json.loads(line)
            
            # Extract fields
            timestamp_str = data.get('timestamp', '')
            level = data.get('level', 'INFO').upper()
            message = data.get('message', '')
            ip_src = data.get('ip', data.get('client_ip', ''))
            user_agent = data.get('user_agent', '')
            method = data.get('method', '')
            path = data.get('path', '')
            status_code = data.get('status_code', '')
            payload = data.get('payload', '')
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine event type and severity
            event_type, severity = self._classify_event(level, message, status_code)
            
            # Detect attack
            label = self.detect_attack(message, payload)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
                'severity': severity,
                'message': message,
                'ip_src': ip_src,
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': 'HTTP',
                'user_agent': user_agent,
                'request_method': method,
                'request_path': path,
                'response_code': status_code,
                'payload': payload,
                'label': label
            }
            
        except json.JSONDecodeError:
            return None
    
    def _parse_standard_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse standard format log line: [timestamp] LEVEL: message"""
        try:
            # Pattern: [timestamp] LEVEL: message
            pattern = r'\[([^\]]+)\]\s+(\w+):\s*(.+)'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            timestamp_str, level, message = match.groups()
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine event type and severity
            event_type, severity = self._classify_event(level, message)
            
            # Detect attack
            label = self.detect_attack(message)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
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
                'payload': '',
                'label': label
            }
            
        except Exception:
            return None
    
    def _parse_simple_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse simple format log line: timestamp LEVEL message"""
        try:
            # Pattern: timestamp LEVEL message
            pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)\s+(\w+)\s+(.+)'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            timestamp_str, level, message = match.groups()
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine event type and severity
            event_type, severity = self._classify_event(level, message)
            
            # Detect attack
            label = self.detect_attack(message)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
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
                'payload': '',
                'label': label
            }
            
        except Exception:
            return None
    
    def _classify_event(self, level: str, message: str, status_code: str = None) -> tuple:
        """
        Classify event type and severity based on log level and message
        
        Args:
            level: Log level (ERROR, WARN, INFO, DEBUG)
            message: Log message
            status_code: HTTP status code (if available)
            
        Returns:
            tuple: (event_type, severity)
        """
        level = level.upper()
        
        # Check for attack indicators in message
        if self.detect_attack(message):
            return "attack", "error"
        
        # Check for error status codes
        if status_code:
            try:
                status_code = int(status_code)
                if status_code >= 500:
                    return "error", "error"
                elif status_code >= 400:
                    return "error", "warning"
            except ValueError:
                pass
        
        # Classify based on log level
        if level in ['ERROR', 'FATAL', 'CRITICAL']:
            return "error", "error"
        elif level in ['WARN', 'WARNING']:
            return "warning", "warning"
        elif level in ['INFO']:
            return "info", "info"
        elif level in ['DEBUG', 'TRACE']:
            return "debug", "info"
        else:
            return "unknown", "info"
    
    def _extract_http_info(self, message: str) -> Dict[str, str]:
        """
        Extract HTTP information from log message
        
        Args:
            message: Log message
            
        Returns:
            Dict: HTTP information
        """
        result = {}
        
        # Extract IP address
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, message)
        if ip_match:
            result['ip_src'] = ip_match.group(0)
        
        # Extract HTTP method and path
        http_pattern = r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)'
        http_match = re.search(http_pattern, message)
        if http_match:
            result['method'] = http_match.group(1)
            result['path'] = http_match.group(2)
        
        # Extract status code
        status_pattern = r'(\d{3})'
        status_match = re.search(status_pattern, message)
        if status_match:
            result['status_code'] = status_match.group(1)
        
        return result


# Example usage
if __name__ == "__main__":
    import logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Test parser
    parser = ApplicationParser("juice_shop")
    
    # Test lines
    test_lines = [
        '{"timestamp":"2025-08-04T10:30:45.123Z","level":"ERROR","message":"SQL injection attempt detected","ip":"192.168.1.100"}',
        '[2025-08-04T10:30:45.123Z] ERROR: SQL injection attempt detected',
        '2025-08-04 10:30:45 ERROR SQL injection attempt detected'
    ]
    
    for i, test_line in enumerate(test_lines, 1):
        print(f"\n--- Test {i} ---")
        result = parser.parse_line(test_line)
        if result:
            print("✅ Application line parsed successfully!")
            print(f"   - Timestamp: {result['timestamp']}")
            print(f"   - Event Type: {result['event_type']}")
            print(f"   - Severity: {result['severity']}")
            print(f"   - Message: {result['message'][:50]}...")
            print(f"   - Label: {result['label']}")
        else:
            print("❌ Failed to parse application line") 