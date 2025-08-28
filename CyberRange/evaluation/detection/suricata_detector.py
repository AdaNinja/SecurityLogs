#!/usr/bin/env python3
"""
Suricata IDS Detector
Suricata IDS集成，用于检测PCAP文件中的攻击
"""

import logging
import subprocess
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import tempfile
import shutil


class SuricataDetector:
    """Suricata检测器"""
    
    def __init__(self, output_dir: str):
        """
        初始化Suricata检测器
        
        Args:
            output_dir: 输出目录
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Suricata配置
        self.suricata_binary = self._find_suricata()
        self.rules_dir = self._setup_rules_dir()
        self.config_file = self._setup_config()
        
        self.logger.info(f"Suricata detector initialized. Output: {self.output_dir}")
    
    def _find_suricata(self) -> str:
        """查找Suricata二进制文件"""
        # 尝试常见位置
        possible_paths = [
            'suricata',  # PATH中
            '/usr/bin/suricata',
            '/usr/local/bin/suricata',
            '/opt/suricata/bin/suricata'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '-V'], capture_output=True, text=True)
                if result.returncode == 0:
                    self.logger.info(f"Found Suricata at: {path}")
                    return path
            except FileNotFoundError:
                continue
        
        self.logger.warning("Suricata not found in common locations")
        return 'suricata'  # 默认假设在PATH中
    
    def _setup_rules_dir(self) -> Path:
        """设置规则目录"""
        rules_dir = self.output_dir / 'rules'
        rules_dir.mkdir(exist_ok=True)
        
        # 复制或创建基本规则文件
        default_rules_path = rules_dir / 'cyberrange.rules'
        if not default_rules_path.exists():
            # 创建基本的检测规则
            default_rules = self._get_default_rules()
            with open(default_rules_path, 'w') as f:
                f.write(default_rules)
        
        return rules_dir
    
    def _get_default_rules(self) -> str:
        """获取默认的Suricata规则"""
        return """# CyberRange Detection Rules

# SQL Injection Detection
alert http any any -> any any (msg:"SQL Injection - Union Select"; flow:to_server,established; content:"union"; nocase; http_uri; content:"select"; nocase; http_uri; distance:0; classtype:web-application-attack; sid:1000001; rev:1;)
alert http any any -> any any (msg:"SQL Injection - OR 1=1"; flow:to_server,established; content:"or"; nocase; http_uri; content:"1=1"; distance:0; http_uri; classtype:web-application-attack; sid:1000002; rev:1;)

# XSS Detection
alert http any any -> any any (msg:"XSS - Script Tag"; flow:to_server,established; content:"<script"; nocase; http_uri; classtype:web-application-attack; sid:1000003; rev:1;)
alert http any any -> any any (msg:"XSS - Javascript URI"; flow:to_server,established; content:"javascript:"; nocase; http_uri; classtype:web-application-attack; sid:1000004; rev:1;)

# Path Traversal Detection
alert http any any -> any any (msg:"Path Traversal - ../"; flow:to_server,established; content:"../"; http_uri; classtype:web-application-attack; sid:1000005; rev:1;)
alert http any any -> any any (msg:"Path Traversal - /etc/passwd"; flow:to_server,established; content:"/etc/passwd"; http_uri; classtype:web-application-attack; sid:1000006; rev:1;)

# Command Injection Detection
alert http any any -> any any (msg:"Command Injection - Shell Commands"; flow:to_server,established; pcre:"/(\||;|&|`|\$\()/U"; http_uri; classtype:web-application-attack; sid:1000007; rev:1;)

# HTTP Flood Detection
alert tcp any any -> any 80 (msg:"HTTP Flood - High Request Rate"; flow:to_server,established; flags:S; threshold:type both, track by_src, count 100, seconds 10; classtype:attempted-dos; sid:1000008; rev:1;)

# Slowloris Detection
alert tcp any any -> any 80 (msg:"Slowloris Attack"; flow:to_server,established; content:"X-"; http_header; dsize:<10; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-dos; sid:1000009; rev:1;)

# Port Scan Detection
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 60; classtype:attempted-recon; sid:1000010; rev:1;)

# Suspicious User-Agent
alert http any any -> any any (msg:"Suspicious User-Agent - Scanner"; flow:to_server,established; content:"scanner"; nocase; http_user_agent; classtype:web-application-activity; sid:1000011; rev:1;)
alert http any any -> any any (msg:"Suspicious User-Agent - Bot"; flow:to_server,established; content:"bot"; nocase; http_user_agent; classtype:web-application-activity; sid:1000012; rev:1;)

# File Upload Detection
alert http any any -> any any (msg:"File Upload - PHP"; flow:to_server,established; content:".php"; http_uri; content:"multipart/form-data"; http_header; classtype:web-application-activity; sid:1000013; rev:1;)

# Authentication Bypass Attempts
alert http any any -> any any (msg:"Auth Bypass - Admin Access"; flow:to_server,established; content:"/admin"; http_uri; content:"cookie"; nocase; http_header; classtype:web-application-attack; sid:1000014; rev:1;)

# XXE Detection
alert http any any -> any any (msg:"XXE Attack - ENTITY"; flow:to_server,established; content:"<!ENTITY"; nocase; http_client_body; classtype:web-application-attack; sid:1000015; rev:1;)
"""
    
    def _setup_config(self) -> Path:
        """设置Suricata配置文件"""
        config_path = self.output_dir / 'suricata.yaml'
        
        if not config_path.exists():
            # 创建最小配置
            config = self._get_minimal_config()
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        
        return config_path
    
    def _get_minimal_config(self) -> Dict:
        """获取最小的Suricata配置"""
        return {
            'vars': {
                'address-groups': {
                    'HOME_NET': '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]',
                    'EXTERNAL_NET': '!$HOME_NET'
                },
                'port-groups': {
                    'HTTP_PORTS': '80',
                    'SHELLCODE_PORTS': '!80'
                }
            },
            'outputs': [
                {
                    'eve-log': {
                        'enabled': True,
                        'filetype': 'regular',
                        'filename': 'eve.json',
                        'types': [
                            {'alert': {'enabled': True}},
                            {'http': {'enabled': True}},
                            {'dns': {'enabled': True}},
                            {'flow': {'enabled': True}}
                        ]
                    }
                }
            ],
            'logging': {
                'default-log-level': 'notice',
                'outputs': [
                    {
                        'file': {
                            'enabled': True,
                            'level': 'info',
                            'filename': 'suricata.log'
                        }
                    }
                ]
            }
        }
    
    def detect(self, pcap_path: str, label: str = "unknown") -> Dict:
        """
        使用Suricata检测PCAP文件
        
        Args:
            pcap_path: PCAP文件路径
            label: 数据集标签
            
        Returns:
            检测结果
        """
        self.logger.info(f"Running Suricata detection on: {pcap_path}")
        
        # 创建运行目录
        run_dir = self.output_dir / f"run_{label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_dir.mkdir(exist_ok=True)
        
        # 运行Suricata
        cmd = [
            self.suricata_binary,
            '-c', str(self.config_file),
            '-r', pcap_path,
            '-l', str(run_dir),
            '-S', str(self.rules_dir / 'cyberrange.rules')
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                self.logger.error(f"Suricata failed: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr,
                    'output_dir': str(run_dir)
                }
            
            # 解析结果
            eve_file = run_dir / 'eve.json'
            alerts = self._parse_eve_log(eve_file)
            
            # 生成统计
            stats = self._generate_stats(alerts)
            
            return {
                'success': True,
                'alert_count': len(alerts),
                'alerts': alerts[:100],  # 限制返回的告警数量
                'statistics': stats,
                'output_dir': str(run_dir),
                'eve_log': str(eve_file)
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error("Suricata detection timed out")
            return {
                'success': False,
                'error': 'Detection timed out after 300 seconds',
                'output_dir': str(run_dir)
            }
        except Exception as e:
            self.logger.error(f"Suricata detection error: {e}")
            return {
                'success': False,
                'error': str(e),
                'output_dir': str(run_dir)
            }
    
    def _parse_eve_log(self, eve_file: Path) -> List[Dict]:
        """解析EVE日志文件"""
        alerts = []
        
        if not eve_file.exists():
            self.logger.warning(f"EVE log not found: {eve_file}")
            return alerts
        
        try:
            with open(eve_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if event.get('event_type') == 'alert':
                            # 提取关键信息
                            alert = {
                                'timestamp': datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')),
                                'signature': event.get('alert', {}).get('signature', ''),
                                'signature_id': event.get('alert', {}).get('signature_id', 0),
                                'severity': event.get('alert', {}).get('severity', 3),
                                'category': event.get('alert', {}).get('category', ''),
                                'src_ip': event.get('src_ip', ''),
                                'dest_ip': event.get('dest_ip', ''),
                                'src_port': event.get('src_port', 0),
                                'dest_port': event.get('dest_port', 0),
                                'proto': event.get('proto', '')
                            }
                            
                            # 添加HTTP信息（如果有）
                            if 'http' in event:
                                alert['http'] = {
                                    'method': event['http'].get('http_method', ''),
                                    'uri': event['http'].get('url', ''),
                                    'user_agent': event['http'].get('http_user_agent', ''),
                                    'status': event['http'].get('status', 0)
                                }
                            
                            alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        self.logger.warning(f"Error parsing EVE event: {e}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Error reading EVE log: {e}")
        
        return alerts
    
    def _generate_stats(self, alerts: List[Dict]) -> Dict:
        """生成告警统计信息"""
        stats = {
            'total_alerts': len(alerts),
            'severity_distribution': {},
            'category_distribution': {},
            'top_signatures': {},
            'top_src_ips': {},
            'protocol_distribution': {}
        }
        
        if not alerts:
            return stats
        
        # 严重程度分布
        severity_counts = {}
        category_counts = {}
        signature_counts = {}
        src_ip_counts = {}
        proto_counts = {}
        
        for alert in alerts:
            # 严重程度
            severity = alert.get('severity', 3)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # 类别
            category = alert.get('category', 'Unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # 签名
            signature = alert.get('signature', 'Unknown')
            signature_counts[signature] = signature_counts.get(signature, 0) + 1
            
            # 源IP
            src_ip = alert.get('src_ip', 'Unknown')
            src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
            
            # 协议
            proto = alert.get('proto', 'Unknown')
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
        
        # 转换为统计结果
        stats['severity_distribution'] = dict(sorted(severity_counts.items()))
        stats['category_distribution'] = dict(sorted(category_counts.items(), 
                                                   key=lambda x: x[1], reverse=True)[:10])
        stats['top_signatures'] = dict(sorted(signature_counts.items(), 
                                            key=lambda x: x[1], reverse=True)[:10])
        stats['top_src_ips'] = dict(sorted(src_ip_counts.items(), 
                                         key=lambda x: x[1], reverse=True)[:10])
        stats['protocol_distribution'] = proto_counts
        
        return stats
    
    def get_version(self) -> str:
        """获取Suricata版本"""
        try:
            result = subprocess.run([self.suricata_binary, '-V'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # 解析版本信息
                output = result.stdout + result.stderr
                for line in output.split('\n'):
                    if 'version' in line.lower():
                        return line.strip()
            return "Unknown"
        except:
            return "Unknown"
    
    def get_rules_count(self) -> int:
        """获取规则数量"""
        count = 0
        rules_file = self.rules_dir / 'cyberrange.rules'
        
        if rules_file.exists():
            with open(rules_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and line.startswith(('alert', 'drop', 'pass')):
                        count += 1
        
        return count
    
    def is_available(self) -> bool:
        """检查Suricata是否可用"""
        try:
            result = subprocess.run([self.suricata_binary, '-V'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def add_custom_rules(self, rules: List[str], rule_file: str = "custom.rules"):
        """添加自定义规则"""
        custom_rules_path = self.rules_dir / rule_file
        
        with open(custom_rules_path, 'w') as f:
            f.write('\n'.join(rules))
        
        self.logger.info(f"Added {len(rules)} custom rules to {custom_rules_path}")


def main():
    """测试Suricata检测器"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Suricata detector")
    parser.add_argument("pcap", help="PCAP file to analyze")
    parser.add_argument("--output", default="./suricata_test",
                       help="Output directory")
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建检测器
    detector = SuricataDetector(args.output)
    
    # 检查可用性
    print(f"🔍 Suricata version: {detector.get_version()}")
    print(f"📋 Rules count: {detector.get_rules_count()}")
    print(f"✓ Available: {detector.is_available()}")
    
    # 运行检测
    print(f"\n🚀 Running detection on: {args.pcap}")
    result = detector.detect(args.pcap, "test")
    
    if result['success']:
        print(f"\n✅ Detection completed successfully")
        print(f"📊 Total alerts: {result['alert_count']}")
        print(f"📁 Results saved to: {result['output_dir']}")
        
        # 显示统计信息
        stats = result.get('statistics', {})
        if stats.get('top_signatures'):
            print("\n🔝 Top signatures:")
            for sig, count in list(stats['top_signatures'].items())[:5]:
                print(f"  • {sig}: {count}")
    else:
        print(f"\n❌ Detection failed: {result.get('error', 'Unknown error')}")
    
    return 0


if __name__ == "__main__":
    exit(main())
