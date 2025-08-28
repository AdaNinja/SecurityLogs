"""
IDS detection components
"""

from .ids_manager import IDSManager
from .suricata_detector import SuricataDetector

__all__ = [
    'IDSManager',
    'SuricataDetector'
]
