"""
CyberRange Parser Package
Provides unified log parsing and CSV output functionality
"""

from .base_parser import BaseParser, ParserManager
from .config_parser import ModularConfigParser
from .nginx_parser import NginxParser
from .attack_parser import AttackParser as ApplicationParser  
from .pcap_parser import PcapParser

__version__ = "1.0.0"
__author__ = "CyberRange Team"

__all__ = [
    'BaseParser',
    'ParserManager',
    'ModularConfigParser',
    'NginxParser',
    'ApplicationParser',
    'PcapParser'
] 