#!/usr/bin/env python3
"""
Fiberfox Configuration
Fiberfox攻击策略的配置和参数定义
"""

from typing import Dict, Any


class FiberfoxConfig:
    """Fiberfox配置类"""
    
    # 攻击策略描述
    STRATEGY_DESCRIPTIONS = {
        "SLOW": "Slowloris攻击 - 慢速HTTP DoS攻击，保持连接开放耗尽服务器资源",
        "GET": "HTTP GET Flood - 大量GET请求造成服务器过载",
        "BYPASS": "WAF绕过攻击 - 使用各种技术绕过Web应用防火墙",
        "AVB": "应用层漏洞利用 - 针对应用层的各种漏洞攻击"
    }
    
    # 默认攻击参数
    DEFAULT_PARAMS = {
        "SLOW": {
            "connections": 200,
            "timeout": 10,
            "interval": 5,
            "headers": [
                "X-a: b",
                "Content-Length: 4096",
                "Accept-Language: en-US"
            ]
        },
        "GET": {
            "threads": 50,
            "requests_per_thread": 1000,
            "random_params": True,
            "user_agents_rotate": True
        },
        "BYPASS": {
            "payload_encoding": ["url", "html", "unicode", "base64"],
            "techniques": [
                "case_variation",
                "comment_injection", 
                "parameter_pollution",
                "path_traversal"
            ],
            "test_payloads": True
        },
        "AVB": {
            "attack_types": [
                "sql_injection",
                "xss",
                "command_injection",
                "xxe",
                "path_traversal"
            ],
            "fuzz_params": True,
            "smart_detection": True
        }
    }
    
    # PCAP生成配置
    PCAP_CONFIG = {
        "capture_filter": "tcp port 80 or tcp port 443 or tcp port 8080",
        "snap_length": 65535,
        "promiscuous_mode": True,
        "buffer_size": 10485760  # 10MB
    }
    
    # 目标配置示例
    TARGET_EXAMPLES = {
        "juice_shop": {
            "url": "http://localhost:3000",
            "description": "OWASP Juice Shop - 易受攻击的Web应用",
            "recommended_strategies": ["GET", "BYPASS", "AVB"]
        },
        "dvwa": {
            "url": "http://localhost:8080",
            "description": "Damn Vulnerable Web Application",
            "recommended_strategies": ["SLOW", "BYPASS", "AVB"]
        },
        "webgoat": {
            "url": "http://localhost:8080/WebGoat",
            "description": "OWASP WebGoat",
            "recommended_strategies": ["GET", "AVB"]
        }
    }
    
    @classmethod
    def get_strategy_config(cls, strategy: str) -> Dict[str, Any]:
        """获取特定策略的配置"""
        return cls.DEFAULT_PARAMS.get(strategy.upper(), {})
    
    @classmethod
    def get_strategy_description(cls, strategy: str) -> str:
        """获取策略描述"""
        return cls.STRATEGY_DESCRIPTIONS.get(strategy.upper(), "Unknown strategy")
    
    @classmethod
    def get_recommended_duration(cls, strategy: str) -> int:
        """获取推荐的攻击持续时间（秒）"""
        duration_map = {
            "SLOW": 120,    # 慢速攻击需要更长时间
            "GET": 60,      # 快速洪水攻击
            "BYPASS": 90,   # WAF绕过需要尝试多种技术
            "AVB": 90       # 漏洞利用需要时间探测
        }
        return duration_map.get(strategy.upper(), 60)
    
    @classmethod
    def get_pcap_size_estimate(cls, strategy: str, duration: int) -> float:
        """估算PCAP文件大小（MB）"""
        # 基于策略和持续时间的粗略估算
        rate_map = {
            "SLOW": 0.1,    # MB/秒 - 慢速攻击流量较小
            "GET": 2.0,     # MB/秒 - 洪水攻击流量大
            "BYPASS": 0.5,  # MB/秒 - 中等流量
            "AVB": 0.8      # MB/秒 - 中等流量
        }
        rate = rate_map.get(strategy.upper(), 1.0)
        return rate * duration
    
    @classmethod
    def validate_target(cls, url: str) -> bool:
        """验证目标URL是否有效"""
        import re
        pattern = r'^https?://[^\s]+$'
        return bool(re.match(pattern, url))
    
    @classmethod
    def get_attack_characteristics(cls, strategy: str) -> Dict[str, Any]:
        """获取攻击特征，用于检测验证"""
        characteristics = {
            "SLOW": {
                "signatures": [
                    "incomplete HTTP headers",
                    "slow header transmission",
                    "connection holding pattern"
                ],
                "expected_alerts": [
                    "POLICY Slowloris",
                    "DOS Slowloris",
                    "MALWARE-CNC"
                ],
                "traffic_pattern": "low_bandwidth_persistent"
            },
            "GET": {
                "signatures": [
                    "high request rate",
                    "repeated GET requests",
                    "similar URI patterns"
                ],
                "expected_alerts": [
                    "DOS HTTP flood",
                    "POLICY excessive requests",
                    "WEB-MISC high activity"
                ],
                "traffic_pattern": "high_bandwidth_burst"
            },
            "BYPASS": {
                "signatures": [
                    "encoded payloads",
                    "parameter tampering",
                    "unusual characters in URI"
                ],
                "expected_alerts": [
                    "WEB-ATTACK",
                    "SQL injection attempt",
                    "XSS attempt"
                ],
                "traffic_pattern": "moderate_varied"
            },
            "AVB": {
                "signatures": [
                    "injection attempts",
                    "vulnerability scanning",
                    "exploit payloads"
                ],
                "expected_alerts": [
                    "WEB-ATTACK",
                    "EXPLOIT-KIT",
                    "MALWARE-BACKDOOR"
                ],
                "traffic_pattern": "moderate_targeted"
            }
        }
        return characteristics.get(strategy.upper(), {})
