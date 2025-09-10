"""
CyberRange Orchestrator Package
Provides scenario orchestration and management capabilities
"""

from .scenario_manager import ScenarioManager, ScenarioContext
from .container_manager import ContainerManager, ContainerInfo
from .script_executor import ScriptExecutor
from .log_collector import LogCollector
from .error_handler import ErrorHandler, ErrorInfo
from .modular_adapter import load_config_with_adapter, ConfigurationAdapter

__version__ = "1.0.0"
__author__ = "CyberRange Team"

__all__ = [
    'ScenarioManager',
    'ScenarioContext', 
    'ContainerManager',
    'ContainerInfo',
    'ScriptExecutor',
    'LogCollector',
    'ErrorHandler',
    'ErrorInfo',
    'load_config_with_adapter',
    'ConfigurationAdapter'
] 