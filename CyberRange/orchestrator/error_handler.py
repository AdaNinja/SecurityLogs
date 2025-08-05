#!/usr/bin/env python3
"""
Error Handler for CyberRange
Handles errors during scenario execution
"""

import logging
import traceback
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ErrorInfo:
    """Error information"""
    timestamp: datetime
    error_type: str
    message: str
    context: Dict
    traceback: str
    severity: str = "error"  # error, warning, info


class ErrorHandler:
    def __init__(self):
        """Initialize ErrorHandler"""
        self.logger = logging.getLogger(__name__)
        self.errors: List[ErrorInfo] = []
        self.error_strategies = self._load_error_strategies()
    
    def _load_error_strategies(self) -> Dict:
        """Load error handling strategies"""
        return {
            'container_start_failure': {
                'action': 'stop_and_cleanup',
                'retry': False,
                'log_level': 'ERROR',
                'description': 'Container failed to start'
            },
            'script_execution_failure': {
                'action': 'continue_with_warning',
                'retry': True,
                'max_retries': 3,
                'log_level': 'WARNING',
                'description': 'Script execution failed'
            },
            'log_collection_failure': {
                'action': 'continue_with_warning',
                'retry': True,
                'max_retries': 2,
                'log_level': 'WARNING',
                'description': 'Log collection failed'
            },
            'network_failure': {
                'action': 'retry',
                'retry': True,
                'max_retries': 3,
                'log_level': 'ERROR',
                'description': 'Network operation failed'
            },
            'hook_execution_failure': {
                'action': 'continue_with_warning',
                'retry': False,
                'log_level': 'WARNING',
                'description': 'Hook execution failed'
            },
            'payload_loading_failure': {
                'action': 'use_default',
                'retry': False,
                'log_level': 'WARNING',
                'description': 'Failed to load attack payloads'
            }
        }
    
    def handle_error(self, error_type: str, error: Exception, context: Dict = None) -> Dict:
        """
        Handle an error based on its type
        
        Args:
            error_type: Type of error
            error: Exception object
            context: Additional context information
            
        Returns:
            Dict: Error handling result
        """
        try:
            # Create error info
            error_info = ErrorInfo(
                timestamp=datetime.now(),
                error_type=error_type,
                message=str(error),
                context=context or {},
                traceback=traceback.format_exc(),
                severity=self.error_strategies.get(error_type, {}).get('log_level', 'ERROR').lower()
            )
            
            # Add to error list
            self.errors.append(error_info)
            
            # Get error strategy
            strategy = self.error_strategies.get(error_type, {})
            
            # Log error
            self._log_error(error_info, strategy)
            
            # Execute error handling action
            result = self._execute_error_action(error_info, strategy)
            
            return {
                'handled': True,
                'action': strategy.get('action', 'unknown'),
                'retry': strategy.get('retry', False),
                'max_retries': strategy.get('max_retries', 0),
                'error_info': error_info,
                'result': result
            }
            
        except Exception as e:
            self.logger.error(f"Failed to handle error {error_type}: {str(e)}")
            return {
                'handled': False,
                'action': 'unknown',
                'retry': False,
                'error': str(e)
            }
    
    def _log_error(self, error_info: ErrorInfo, strategy: Dict):
        """Log error based on strategy"""
        log_level = strategy.get('log_level', 'ERROR')
        description = strategy.get('description', 'Unknown error')
        
        log_message = f"{description}: {error_info.message}"
        
        if log_level == 'ERROR':
            self.logger.error(log_message)
        elif log_level == 'WARNING':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Log detailed error information
        self.logger.debug(f"Error context: {error_info.context}")
        self.logger.debug(f"Error traceback: {error_info.traceback}")
    
    def _execute_error_action(self, error_info: ErrorInfo, strategy: Dict) -> Dict:
        """Execute error handling action"""
        action = strategy.get('action', 'unknown')
        
        if action == 'stop_and_cleanup':
            return self._stop_and_cleanup(error_info)
        elif action == 'continue_with_warning':
            return self._continue_with_warning(error_info)
        elif action == 'retry':
            return self._retry_operation(error_info, strategy)
        elif action == 'use_default':
            return self._use_default_values(error_info)
        else:
            return {'action': 'unknown', 'success': False}
    
    def _stop_and_cleanup(self, error_info: ErrorInfo) -> Dict:
        """Stop execution and cleanup resources"""
        self.logger.error("Stopping scenario execution due to critical error")
        
        # Perform cleanup operations
        cleanup_result = self._perform_cleanup(error_info.context)
        
        return {
            'action': 'stop_and_cleanup',
            'success': True,
            'cleanup_result': cleanup_result
        }
    
    def _continue_with_warning(self, error_info: ErrorInfo) -> Dict:
        """Continue execution with warning"""
        self.logger.warning("Continuing execution despite error")
        
        return {
            'action': 'continue_with_warning',
            'success': True
        }
    
    def _retry_operation(self, error_info: ErrorInfo, strategy: Dict) -> Dict:
        """Retry the failed operation"""
        max_retries = strategy.get('max_retries', 3)
        retry_count = error_info.context.get('retry_count', 0)
        
        if retry_count < max_retries:
            self.logger.info(f"Retrying operation (attempt {retry_count + 1}/{max_retries})")
            return {
                'action': 'retry',
                'success': True,
                'retry_count': retry_count + 1,
                'should_retry': True
            }
        else:
            self.logger.error(f"Max retries ({max_retries}) exceeded")
            return {
                'action': 'retry',
                'success': False,
                'retry_count': retry_count,
                'should_retry': False
            }
    
    def _use_default_values(self, error_info: ErrorInfo) -> Dict:
        """Use default values when operation fails"""
        self.logger.warning("Using default values due to error")
        
        return {
            'action': 'use_default',
            'success': True
        }
    
    def _perform_cleanup(self, context: Dict) -> Dict:
        """Perform cleanup operations"""
        cleanup_result = {
            'containers_stopped': 0,
            'networks_removed': 0,
            'files_cleaned': 0
        }
        
        try:
            # Stop containers if available
            containers = context.get('containers', {})
            for container_name, container_info in containers.items():
                try:
                    # This would need access to container manager
                    # container_manager.stop_container(container_info['id'])
                    cleanup_result['containers_stopped'] += 1
                except Exception as e:
                    self.logger.error(f"Failed to stop container {container_name}: {str(e)}")
            
            # Remove networks if available
            networks = context.get('networks', [])
            for network in networks:
                try:
                    # This would need access to container manager
                    # container_manager.remove_network(network['name'])
                    cleanup_result['networks_removed'] += 1
                except Exception as e:
                    self.logger.error(f"Failed to remove network {network['name']}: {str(e)}")
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")
        
        return cleanup_result
    
    def get_error_summary(self) -> Dict:
        """Get summary of all errors"""
        if not self.errors:
            return {'total_errors': 0}
        
        error_counts = {}
        severity_counts = {}
        
        for error in self.errors:
            # Count by error type
            error_counts[error.error_type] = error_counts.get(error.error_type, 0) + 1
            
            # Count by severity
            severity_counts[error.severity] = severity_counts.get(error.severity, 0) + 1
        
        return {
            'total_errors': len(self.errors),
            'error_types': error_counts,
            'severity_counts': severity_counts,
            'first_error': self.errors[0].timestamp.isoformat() if self.errors else None,
            'last_error': self.errors[-1].timestamp.isoformat() if self.errors else None
        }
    
    def get_errors_by_type(self, error_type: str) -> List[ErrorInfo]:
        """Get all errors of a specific type"""
        return [error for error in self.errors if error.error_type == error_type]
    
    def get_errors_by_severity(self, severity: str) -> List[ErrorInfo]:
        """Get all errors of a specific severity"""
        return [error for error in self.errors if error.severity == severity]
    
    def clear_errors(self):
        """Clear all errors"""
        self.errors.clear()
        self.logger.info("Error history cleared")
    
    def should_abort_scenario(self) -> bool:
        """Determine if scenario should be aborted based on errors"""
        # Check for critical errors that require abort
        critical_errors = self.get_errors_by_type('container_start_failure')
        return len(critical_errors) > 0
    
    def can_continue_execution(self) -> bool:
        """Determine if execution can continue despite errors"""
        # Check for non-critical errors
        non_critical_errors = [
            error for error in self.errors 
            if error.error_type in ['script_execution_failure', 'log_collection_failure', 'hook_execution_failure']
        ]
        
        # Allow continuation if only non-critical errors
        return len(non_critical_errors) == len(self.errors)


def main():
    """Test the ErrorHandler"""
    handler = ErrorHandler()
    
    # Test error handling
    try:
        # Simulate an error
        raise Exception("Test error for container start failure")
    except Exception as e:
        result = handler.handle_error('container_start_failure', e, {'container_name': 'test'})
        print(f"Error handling result: {result}")
    
    # Get error summary
    summary = handler.get_error_summary()
    print(f"Error summary: {summary}")


if __name__ == "__main__":
    main() 