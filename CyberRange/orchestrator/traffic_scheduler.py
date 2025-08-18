#!/usr/bin/env python3
"""
Parallel Traffic Executor for CyberRange
Executes traffic behaviors in parallel threads for realistic concurrent traffic
"""

import time
import random
import threading
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass


@dataclass
class ParallelTrafficBehavior:
    """Configuration for a parallel traffic behavior"""
    name: str
    behavior_type: str  # 'attack' or 'benign'
    percentage: float
    node: str
    script: str
    script_args: List[str]
    payload_config: Optional[Dict] = None


def create_parallel_behaviors(config: Dict) -> List[ParallelTrafficBehavior]:
    """
    Creates parallel behavior configurations based on percentages.
    Each behavior will run as a separate thread.
    """
    logger = logging.getLogger(__name__)
    scenario_duration = config.get('scenario', {}).get('duration', 300)
    attacks_config = config.get('behaviors', {}).get('attacks', [])
    benign_config = config.get('behaviors', {}).get('benign_traffic', [])

    behaviors = []
    
    # Add attack behaviors
    for attack in attacks_config:
        percentage = attack.get('percentage', 0)
        if percentage > 0:
            behaviors.append(ParallelTrafficBehavior(
                name=attack['name'],
                behavior_type='attack',
                percentage=percentage,
                node=attack['node'],
                script=attack['script'],
                script_args=attack.get('script_args', []),
                payload_config=attack.get('payload_config', {})
            ))
    
    # Add benign behaviors
    for benign in benign_config:
        percentage = benign.get('percentage', 0)
        if percentage > 0:
            behaviors.append(ParallelTrafficBehavior(
                name=benign['name'],
                behavior_type='benign',
                percentage=percentage,
                node=benign['node'],
                script=benign['script'],
                script_args=benign.get('script_args', [])
            ))
    
    # Validate and normalize percentages
    total_percentage = sum(b.percentage for b in behaviors)
    if total_percentage == 0:
        logger.warning("No traffic percentages defined. No behaviors will be scheduled.")
        return []
    
    if total_percentage != 100:
        logger.warning(f"Total percentage is {total_percentage}%. Normalizing...")
        for behavior in behaviors:
            behavior.percentage = (behavior.percentage / total_percentage) * 100
    
    logger.info(f"Created {len(behaviors)} parallel traffic behaviors for {scenario_duration} seconds")
    for behavior in behaviors:
        # Calculate approximate interval between actions
        interval = 100.0 / behavior.percentage if behavior.percentage > 0 else float('inf')
        logger.info(f"- {behavior.name} ({behavior.behavior_type}): {behavior.percentage}% (every ~{interval:.1f}s)")
    
    return behaviors


class ParallelTrafficExecutor:
    """Executes traffic behaviors in parallel threads"""
    
    def __init__(self, scenario_duration: int):
        self.scenario_duration = scenario_duration
        self.start_time = None
        self.stop_event = threading.Event()
        self.threads = []
        self.logger = logging.getLogger(__name__)
        self.execution_stats = {}
    
    def execute_behaviors(self, behaviors: List[ParallelTrafficBehavior], 
                         attack_executor: Callable, benign_executor: Callable):
        """Execute all behaviors in parallel threads"""
        self.start_time = time.time()
        self.stop_event.clear()
        self.execution_stats = {}
        
        # Check if this is an unlimited duration scenario
        unlimited_duration = self.scenario_duration == 0
        
        if unlimited_duration:
            self.logger.info("Starting unlimited parallel traffic execution (will stop when all behaviors complete)")
        else:
            self.logger.info(f"Starting parallel traffic execution for {self.scenario_duration} seconds")
        
        # Initialize execution stats for all behaviors BEFORE starting threads
        for behavior in behaviors:
            self.execution_stats[behavior.name] = {'count': 0, 'success': 0, 'failed': 0, 'completed': False}
        
        # Start a thread for each behavior
        for behavior in behaviors:
            if behavior.behavior_type == 'attack':
                thread = threading.Thread(
                    target=self._run_attack_behavior,
                    args=(behavior, attack_executor),
                    name=f"Attack-{behavior.name}"
                )
            else:
                thread = threading.Thread(
                    target=self._run_benign_behavior, 
                    args=(behavior, benign_executor),
                    name=f"Benign-{behavior.name}"
                )
            
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
            self.logger.info(f"Started parallel thread: {thread.name}")
        
        if unlimited_duration:
            # Monitor threads until all complete
            self.logger.info("All threads started. Monitoring for completion...")
            while not self.stop_event.is_set():
                # Check if all threads have completed their work
                all_completed = True
                for behavior_name, stats in self.execution_stats.items():
                    if not stats.get('completed', False):
                        all_completed = False
                        break
                
                if all_completed:
                    self.logger.info("All behaviors completed, stopping execution...")
                    break
                
                # Wait a bit before checking again
                time.sleep(2.0)
        else:
            # Wait for scenario duration
            self.logger.info(f"All threads started. Waiting {self.scenario_duration} seconds...")
            time.sleep(self.scenario_duration)
        
        # Stop all threads
        self.logger.info("Stopping all traffic threads...")
        self.stop_event.set()
        
        # Wait for threads to finish (with timeout)
        for thread in self.threads:
            thread.join(timeout=5.0)
            if thread.is_alive():
                self.logger.warning(f"Thread {thread.name} did not stop gracefully")
        
        self._log_execution_summary()
        self.logger.info("Parallel traffic execution completed")
        return True
    
    def _run_attack_behavior(self, behavior: ParallelTrafficBehavior, executor: Callable):
        """Run attack behavior in a loop until stopped"""
        # Calculate interval based on percentage
        # Higher percentage = shorter interval between attacks
        base_interval = 100.0 / behavior.percentage if behavior.percentage > 0 else 60.0
        
        # For unlimited duration, we need to determine when to stop
        # This could be based on payload completion or other criteria
        max_executions = 1000  # Safety limit to prevent infinite loops
        
        while not self.stop_event.is_set() and self.execution_stats[behavior.name]['count'] < max_executions:
            try:
                # Execute single attack
                attack_config = {
                    'name': behavior.name,
                    'node': behavior.node,
                    'script': behavior.script,
                    'script_args': behavior.script_args,
                    'payload_config': behavior.payload_config
                }
                
                success = executor(attack_config)
                self.execution_stats[behavior.name]['count'] += 1
                
                if success:
                    self.execution_stats[behavior.name]['success'] += 1
                    self.logger.debug(f"{behavior.name}: Attack #{self.execution_stats[behavior.name]['count']} completed")
                else:
                    self.execution_stats[behavior.name]['failed'] += 1
                    self.logger.warning(f"{behavior.name}: Attack #{self.execution_stats[behavior.name]['count']} failed")
                
                # For unlimited duration, check if we should continue
                if self.scenario_duration == 0:
                    # In unlimited mode, we'll stop after a reasonable number of executions
                    # This prevents infinite loops while still allowing comprehensive testing
                    if self.execution_stats[behavior.name]['count'] >= 100:  # Execute 100 attacks per type
                        self.logger.info(f"{behavior.name}: Reached execution limit for unlimited mode")
                        break
                
                # Wait for next attack with some randomness
                interval = base_interval + random.uniform(-1.0, 1.0)
                if self.stop_event.wait(max(0.5, interval)):
                    break
                    
            except Exception as e:
                self.logger.error(f"Error in attack behavior {behavior.name}: {e}")
                if self.stop_event.wait(5.0):
                    break
        
        # Mark this behavior as completed
        self.execution_stats[behavior.name]['completed'] = True
        total = self.execution_stats[behavior.name]['count']
        self.logger.info(f"{behavior.name}: Completed {total} attacks")
    
    def _run_benign_behavior(self, behavior: ParallelTrafficBehavior, executor: Callable):
        """Run benign behavior in a loop until stopped"""
        # Calculate interval based on percentage
        # Higher percentage = shorter interval between actions
        base_interval = 100.0 / behavior.percentage if behavior.percentage > 0 else 60.0
        
        # For unlimited duration, we need to determine when to stop
        max_executions = 1000  # Safety limit to prevent infinite loops
        
        while not self.stop_event.is_set() and self.execution_stats[behavior.name]['count'] < max_executions:
            try:
                # Execute single benign action
                benign_config = {
                    'name': behavior.name,
                    'node': behavior.node,
                    'script': behavior.script,
                    'script_args': behavior.script_args
                }
                
                success = executor(benign_config)
                self.execution_stats[behavior.name]['count'] += 1
                
                if success:
                    self.execution_stats[behavior.name]['success'] += 1
                    self.logger.debug(f"{behavior.name}: Action #{self.execution_stats[behavior.name]['count']} completed")
                else:
                    self.execution_stats[behavior.name]['failed'] += 1
                    self.logger.warning(f"{behavior.name}: Action #{self.execution_stats[behavior.name]['count']} failed")
                
                # For unlimited duration, check if we should continue
                if self.scenario_duration == 0:
                    # In unlimited mode, we'll stop after a reasonable number of executions
                    if self.execution_stats[behavior.name]['count'] >= 50:  # Execute 50 benign actions
                        self.logger.info(f"{behavior.name}: Reached execution limit for unlimited mode")
                        break
                
                # Wait for next action with some randomness
                interval = base_interval + random.uniform(-0.5, 0.5)
                if self.stop_event.wait(max(0.5, interval)):
                    break
                    
            except Exception as e:
                self.logger.error(f"Error in benign behavior {behavior.name}: {e}")
                if self.stop_event.wait(5.0):
                    break
        
        # Mark this behavior as completed
        self.execution_stats[behavior.name]['completed'] = True
        total = self.execution_stats[behavior.name]['count']
        self.logger.info(f"{behavior.name}: Completed {total} benign actions")
    
    def _log_execution_summary(self):
        """Log summary of execution statistics"""
        total_actions = sum(stats['count'] for stats in self.execution_stats.values())
        total_success = sum(stats['success'] for stats in self.execution_stats.values())
        total_failed = sum(stats['failed'] for stats in self.execution_stats.values())
        
        self.logger.info("=== Parallel Traffic Execution Summary ===")
        self.logger.info(f"Total actions executed: {total_actions}")
        self.logger.info(f"Successful actions: {total_success}")
        self.logger.info(f"Failed actions: {total_failed}")
        self.logger.info(f"Success rate: {(total_success/total_actions*100):.1f}%" if total_actions > 0 else "Success rate: 0%")
        
        for behavior_name, stats in self.execution_stats.items():
            success_rate = (stats['success']/stats['count']*100) if stats['count'] > 0 else 0
            self.logger.info(f"- {behavior_name}: {stats['count']} actions ({success_rate:.1f}% success)")


# Backward compatibility function
def create_traffic_schedule(scenario_config: Dict) -> List:
    """
    Backward compatibility function - now returns parallel behaviors instead of scheduled events
    """
    return create_parallel_behaviors(scenario_config)