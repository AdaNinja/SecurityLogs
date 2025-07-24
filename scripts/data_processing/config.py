#!/usr/bin/env python3
"""
ETL Configuration and Path Management
Centralized configuration for all ETL processes
"""

import os
from typing import Dict, List

class ETLConfig:
    """Centralized ETL configuration"""
    
    def __init__(self, variant_id: str):
        self.variant_id = variant_id
        
        # Raw logs directory structure (simplified)
        self.logs_dir = f"data/logs/{variant_id}"
        self.proxy_logs_dir = f"{self.logs_dir}/attacks/proxy"  # Updated to use attacks/proxy
        self.web_logs_dir = f"{self.logs_dir}/web"
        self.attack_logs_dir = f"{self.logs_dir}/attacks"
        self.system_logs_dir = f"{self.logs_dir}/system"
        self.pcap_dir = f"{self.logs_dir}/pcap"
        
        # Processed data directory structure (simplified)
        self.processed_dir = f"data/processed/{variant_id}"
        self.dns_data_dir = f"{self.processed_dir}/dns_data"
        self.proxy_data_dir = f"{self.processed_dir}/proxy_data"
        self.system_logs_data_dir = f"{self.processed_dir}/system_logs"
        self.security_data_dir = f"{self.processed_dir}/security_data"
        self.analysis_dir = f"{self.processed_dir}/analysis"
        self.datasets_dir = f"{self.processed_dir}/datasets"
        
        # Raw log directories mapping
        self.raw_log_dirs = {
            'dns_proxy_logs': self.proxy_logs_dir,
            'http_proxy_logs': self.proxy_logs_dir,
            'system_logs': self.system_logs_dir,
            'web_logs': self.web_logs_dir,
            'attack_logs': self.attack_logs_dir,
            'pcap_logs': self.pcap_dir
        }
        
        # Processed log directories mapping
        self.processed_log_dirs = {
            'dns_data': self.dns_data_dir,
            'proxy_data': self.proxy_data_dir,
            'system_logs': self.system_logs_data_dir,
            'security_data': self.security_data_dir,
            'analysis': self.analysis_dir,
            'datasets': self.datasets_dir
        }
        
        # File patterns for different log types
        self.file_patterns = {
            'dns_proxy_logs': ['*.jsonl', '*.log'],
            'http_proxy_logs': ['*.jsonl', '*.log'],
            'system_logs': ['*.log', 'messages', 'syslog'],
            'web_logs': ['*.log', 'access.log', 'error.log'],
            'attack_logs': ['*.json', '*.log'],
            'pcap_logs': ['*.pcap']
        }
        
        # File paths
        self.dns_proxy_raw = f"{self.proxy_logs_dir}/dns_proxy_raw.jsonl"
        self.http_proxy_raw = f"{self.proxy_logs_dir}/http_proxy_raw.jsonl"
        self.nginx_access = f"{self.web_logs_dir}/access.log"
        self.nginx_error = f"{self.web_logs_dir}/error.log"
        self.nginx_detailed = f"{self.web_logs_dir}/detailed.log"
        self.php_fpm_log = f"{self.web_logs_dir}/php7.4-fpm.log"
        self.login_attempts = f"{self.web_logs_dir}/login_attempts.log"
        self.search_attempts = f"{self.web_logs_dir}/search_attempts.log"
        self.error_log = f"{self.web_logs_dir}/error.log"
        self.info_log = f"{self.web_logs_dir}/info.log"
        self.messages_log = f"{self.system_logs_dir}/messages"
        self.syslog = f"{self.system_logs_dir}/syslog"
        self.user_log = f"{self.system_logs_dir}/user.log"
        
        # Attack logs
        self.container_attack_log = f"{self.attack_logs_dir}/container_attack_log.json"
        self.sql_injection_results = f"{self.attack_logs_dir}/sql_injection_results.json"
        self.dns_attack_results = f"{self.attack_logs_dir}/dns_attacks/dns_attack_results.json"
        self.scan_results = f"{self.attack_logs_dir}/scan_results.json"
        self.attack_log = f"{self.attack_logs_dir}/attack.log"
        
        # Output files
        self.dns_proxy_processed = f"{self.dns_data_dir}/dns_proxy_logs.jsonl"
        self.http_proxy_processed = f"{self.proxy_data_dir}/http_proxy_logs.jsonl"
        self.flow_correlation = f"{self.analysis_dir}/flow_correlation.jsonl"
        self.unified_dataset = f"{self.datasets_dir}/unified_dataset.csv"
        self.simplified_view = f"{self.datasets_dir}/simplified_view.csv"
        self.simplified_excel = f"{self.datasets_dir}/simplified_view.xlsx"
        
    def create_directories(self):
        """Create all necessary directories"""
        directories = [
            self.dns_data_dir,
            self.proxy_data_dir,
            self.system_logs_data_dir,
            self.security_data_dir,
            self.analysis_dir,
            self.datasets_dir
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        print("📁 All directories created successfully")
    
    def create_all_directories(self):
        """Alias for create_directories() for compatibility"""
        self.create_directories()
    
    def get_raw_log_path(self, log_type: str, filename: str = None) -> str:
        """Get path for raw log file"""
        base_dir = self.raw_log_dirs.get(log_type)
        if not base_dir:
            raise ValueError(f"Unknown log type: {log_type}")
        
        if filename:
            return os.path.join(base_dir, filename)
        return base_dir
    
    def get_processed_log_path(self, log_type: str, filename: str = None) -> str:
        """Get path for processed log file"""
        base_dir = self.processed_log_dirs.get(log_type)
        if not base_dir:
            raise ValueError(f"Unknown log type: {log_type}")
        
        if filename:
            return os.path.join(base_dir, filename)
        return base_dir
    
    def get_file_patterns(self, log_type: str) -> List[str]:
        """Get file patterns for a log type"""
        return self.file_patterns.get(log_type, ["*"])
    
    def list_available_logs(self) -> Dict[str, List[str]]:
        """List all available log files by type"""
        available_logs = {}
        
        for log_type, base_dir in self.raw_log_dirs.items():
            if os.path.exists(base_dir):
                patterns = self.get_file_patterns(log_type)
                files = []
                for pattern in patterns:
                    import glob
                    files.extend(glob.glob(os.path.join(base_dir, pattern)))
                available_logs[log_type] = files
        
        return available_logs

# Global configuration instance
_config = None

def get_config(variant_id: str) -> ETLConfig:
    """Get global ETL configuration"""
    global _config
    if _config is None or _config.variant_id != variant_id:
        _config = ETLConfig(variant_id)
    return _config 