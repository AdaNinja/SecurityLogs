"""
CyberRange Parser Package
Provides unified log parsing and CSV output functionality
"""

from .base_parser import BaseParser, ParserManager
from .config_parser import ModularConfigParser
from .log_parsers.nginx_parser import NginxParser
from .log_parsers.application_parser import ApplicationParser
from .network_parsers.pcap_parser import PcapParser

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