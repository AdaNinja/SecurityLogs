#!/usr/bin/env python3
"""
Base Parser Class
Provides unified interface for all log parsers
"""

import csv
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any
import re


class BaseParser(ABC):
    """
    Abstract base class for all log parsers
    Ensures consistent interface and output format
    """
    
    # Unified timestamp format: ISO 8601 with milliseconds
    TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
    
    # CSV field headers (unified across all parsers)
    CSV_HEADERS = [
        'timestamp', 'source_type', 'source_name', 'event_type', 'severity',
        'message', 'ip_src', 'ip_dst', 'port_src', 'port_dst', 'protocol',
        'user_agent', 'request_method', 'request_path', 'response_code',
        'payload', 'label'
    ]
    
    def __init__(self, source_name: str):
        """
        Initialize parser
        
        Args:
            source_name: Name of the log source (e.g., 'nginx_proxy', 'juice_shop')
        """
        self.source_name = source_name
        self.source_type = self._get_source_type()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Attack patterns for binary labeling
        self.attack_patterns = self._load_attack_patterns()
    
    @abstractmethod
    def _get_source_type(self) -> str:
        """Return the source type (nginx, application, pcap, system)"""
        pass
    
    @abstractmethod
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line
        
        Args:
            line: Raw log line
            
        Returns:
            Dict: Parsed data or None if parsing failed
        """
        pass
    
    def normalize_timestamp(self, timestamp_str: str, input_format: str = None) -> str:
        """
        Normalize timestamp to unified format
        
        Args:
            timestamp_str: Input timestamp string
            input_format: Input format (if None, will try to auto-detect)
            
        Returns:
            str: Normalized timestamp in ISO 8601 format
        """
        try:
            if input_format:
                dt = datetime.strptime(timestamp_str, input_format)
            else:
                dt = self._auto_detect_timestamp(timestamp_str)
            
            return dt.strftime(self.TIMESTAMP_FORMAT)
            
        except Exception as e:
            self.logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return datetime.now().strftime(self.TIMESTAMP_FORMAT)
    
    def _auto_detect_timestamp(self, timestamp_str: str) -> datetime:
        """
        Auto-detect timestamp format
        
        Args:
            timestamp_str: Timestamp string
            
        Returns:
            datetime: Parsed datetime object
        """
        # Common timestamp formats
        formats = [
            # Nginx format with brackets: [04/Aug/2025:10:30:45 +0000]
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]',
            # Nginx format without brackets: 04/Aug/2025:10:30:45 +0000
            r'^(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})$',
            # ISO format: 2025-08-04T10:30:45.123Z
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?)',
            # Unix timestamp: 1641234567
            r'(\d{10,13})',
            # Simple format: 2025-08-04 10:30:45
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in formats:
            match = re.search(pattern, timestamp_str)
            if match:
                ts_str = match.group(1)
                
                # Handle different formats
                if '/' in ts_str and ':' in ts_str:
                    # Nginx format
                    return datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z')
                elif 'T' in ts_str:
                    # ISO format
                    if ts_str.endswith('Z'):
                        ts_str = ts_str[:-1] + '+00:00'
                    return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                elif len(ts_str) == 10:
                    # Unix timestamp (seconds)
                    return datetime.fromtimestamp(int(ts_str))
                elif len(ts_str) == 13:
                    # Unix timestamp (milliseconds)
                    return datetime.fromtimestamp(int(ts_str) / 1000)
                else:
                    # Simple format
                    return datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
        
        raise ValueError(f"Could not auto-detect timestamp format: {timestamp_str}")
    
    def detect_attack(self, message: str, payload: str = None) -> int:
        """
        Detect if the event is an attack (binary classification)
        
        Args:
            message: Log message
            payload: Request payload (if available)
            
        Returns:
            int: 0 for normal, 1 for attack
        """
        text_to_check = f"{message} {payload or ''}".lower()
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    self.logger.debug(f"Attack detected: {attack_type} - {pattern}")
                    return 1
        
        return 0
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load attack detection patterns"""
        return {
            'sql_injection': [
                r"'.*OR.*1=1",
                r"'.*UNION.*SELECT",
                r"'.*DROP.*TABLE",
                r"'.*EXEC.*",
                r"'.*INSERT.*INTO",
                r"'.*UPDATE.*SET",
                r"'.*DELETE.*FROM",
                r"'.*ALTER.*TABLE",
                r"'.*CREATE.*TABLE",
                r"'.*TRUNCATE.*",
                r"'.*--",
                r"'.*#",
                r"'.*/\*.*\*/",
            ],
            'xss': [
                r"<script.*>",
                r"javascript:",
                r"onload=",
                r"onerror=",
                r"onclick=",
                r"onmouseover=",
                r"onfocus=",
                r"onblur=",
                r"alert\(",
                r"confirm\(",
                r"prompt\(",
                r"document\.cookie",
                r"window\.location",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c",
                r"\.\.%2f",
                r"\.\.%5c",
            ],
            'command_injection': [
                r";.*ls",
                r"\|.*cat",
                r"`.*whoami",
                r"\$\(.*\)",
                r"&&.*",
                r"\|\|.*",
                r";.*rm",
                r";.*wget",
                r";.*curl",
                r";.*nc",
            ],
            'ldap_injection': [
                r"\(.*\*\)",
                r"\(.*\|\|.*\)",
                r"\(.*&&.*\)",
                r"\(.*!.*\)",
            ],
            'nosql_injection': [
                r"\$where",
                r"\$ne",
                r"\$gt",
                r"\$lt",
                r"\$regex",
                r"\$exists",
            ],
            'file_inclusion': [
                r"\.\./.*\.php",
                r"\.\./.*\.asp",
                r"\.\./.*\.jsp",
                r"include.*\.\./",
                r"require.*\.\./",
            ],
            'authentication_bypass': [
                r"admin.*'--",
                r"admin.*'#",
                r"admin.*'OR",
                r"admin.*'AND",
                r"password.*'--",
                r"password.*'#",
            ]
        }
    
    def create_csv_row(self, parsed_data: Dict[str, Any]) -> List[str]:
        """
        Create a CSV row from parsed data
        
        Args:
            parsed_data: Parsed log data
            
        Returns:
            List[str]: CSV row values
        """
        row = []
        for header in self.CSV_HEADERS:
            value = parsed_data.get(header, '')
            # Convert None to empty string
            if value is None:
                value = ''
            row.append(str(value))
        return row
    
    def parse_file(self, input_file: str, output_file: str) -> int:
        """
        Parse entire log file
        
        Args:
            input_file: Input log file path
            output_file: Output CSV file path
            
        Returns:
            int: Number of parsed lines
        """
        parsed_count = 0
        
        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile:
                with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
                    writer = csv.writer(outfile)
                    writer.writerow(self.CSV_HEADERS)
                    
                    for line_num, line in enumerate(infile, 1):
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            parsed_data = self.parse_line(line)
                            if parsed_data:
                                row = self.create_csv_row(parsed_data)
                                writer.writerow(row)
                                parsed_count += 1
                            else:
                                self.logger.debug(f"Failed to parse line {line_num}: {line[:100]}...")
                                
                        except Exception as e:
                            self.logger.warning(f"Error parsing line {line_num}: {e}")
                            continue
            
            self.logger.info(f"Parsed {parsed_count} lines from {input_file} to {output_file}")
            return parsed_count
            
        except Exception as e:
            self.logger.error(f"Failed to parse file {input_file}: {e}")
            return 0


class ParserManager:
    """Manager for multiple parsers"""
    
    def __init__(self):
        self.parsers = {}
        self.logger = logging.getLogger(__name__)
    
    def register_parser(self, name: str, parser: BaseParser):
        """Register a parser"""
        self.parsers[name] = parser
    
    def parse_file(self, parser_name: str, input_file: str, output_file: str) -> int:
        """Parse file using specified parser"""
        if parser_name not in self.parsers:
            self.logger.error(f"Parser '{parser_name}' not found")
            return 0
        
        parser = self.parsers[parser_name]
        return parser.parse_file(input_file, output_file)
    
    def get_parser(self, parser_name: str) -> Optional[BaseParser]:
        """Get parser by name"""
        return self.parsers.get(parser_name) 