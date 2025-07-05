#!/usr/bin/env python3
"""
Universal Scenario Execution Script
Supports configuration-driven attack scenario execution
"""

import yaml
import time
import subprocess
import threading
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

class ScenarioRunner:
    def __init__(self, scenario_file, variant="simple"):
        self.scenario_file = scenario_file
        self.variant = variant
        self.config = self.load_config()
        self.logger = self.setup_logging()
        
    def load_config(self):
        """Load scenario configuration file"""
        try:
            with open(self.scenario_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            print(f"Error: Cannot load configuration file {self.scenario_file}: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Setup logging configuration"""
        scenario_name = self.config.get('name', 'unknown')
        log_dir = Path(f"logs/{scenario_name}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"{self.variant}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def run_background_activities(self):
        """Run background activities"""
        variant_config = self.config['variants'][self.variant]
        activities = variant_config.get('background_activities', [])
        
        self.logger.info(f"Starting background activities (variant: {self.variant})")
        
        for activity in activities:
            activity_type = activity['type']
            self.logger.info(f"Starting background activity: {activity_type}")
            
            # Create background thread to run activity
            thread = threading.Thread(
                target=self._run_activity,
                args=(activity_type, activity)
            )
            thread.daemon = True
            thread.start()
    
    def _run_activity(self, activity_type, activity_config):
        """Run single background activity"""
        try:
            actions = activity_config.get('actions', [])
            
            if activity_type == "file_operations":
                self._run_file_operations(actions)
            elif activity_type == "network_activity":
                self._run_network_activity(actions)
            elif activity_type == "office_work":
                self._run_office_work(actions)
            elif activity_type == "multimedia":
                self._run_multimedia_activities(actions)
            elif activity_type == "communication":
                self._run_communication_activities(actions)
            elif activity_type == "development":
                self._run_development_activities(actions)
            elif activity_type == "web_browsing":
                self._run_web_browsing(actions)
            else:
                self.logger.warning(f"Unknown activity type: {activity_type}")
                
        except Exception as e:
            self.logger.error(f"Error running activity {activity_type}: {e}")
    
    def _run_file_operations(self, actions):
        """Run file operation activities"""
        for action in actions:
            if action == "create_temp_files":
                self._create_temp_files()
            elif action == "browse_documents":
                self._browse_documents()
    
    def _run_network_activity(self, actions):
        """Run network activities"""
        for action in actions:
            if action == "check_weather":
                self._check_weather()
            elif action == "simple_web_browsing":
                self._simple_web_browsing()
    
    def _run_office_work(self, actions):
        """Run office work activities"""
        for action in actions:
            if action == "open_existing_documents":
                self._open_existing_documents()
            elif action == "simple_editing":
                self._simple_editing()
    
    def _run_multimedia_activities(self, actions):
        """Run multimedia activities"""
        for action in actions:
            if action == "watch_youtube_video":
                self._watch_youtube_video()
            elif action == "listen_to_music":
                self._listen_to_music()
    
    def _run_communication_activities(self, actions):
        """Run communication activities"""
        for action in actions:
            if action == "slack_chat":
                self._slack_chat()
            elif action == "zoom_meeting":
                self._zoom_meeting()
    
    def _run_development_activities(self, actions):
        """Run development activities"""
        for action in actions:
            if action == "edit_code":
                self._edit_code()
            elif action == "run_tests":
                self._run_tests()
    
    def _run_web_browsing(self, actions):
        """Run web browsing activities"""
        for action in actions:
            if action == "check_company_website":
                self._check_company_website()
            elif action == "read_news":
                self._read_news()
    
    # Specific activity implementation methods
    def _create_temp_files(self):
        """Create temporary files"""
        try:
            temp_dir = Path("/tmp/scenario_files")
            temp_dir.mkdir(exist_ok=True)
            
            for i in range(5):
                file_path = temp_dir / f"temp_file_{i}.txt"
                with open(file_path, 'w') as f:
                    f.write(f"Temporary file content {i}\n")
            
            self.logger.info("Created temporary files")
        except Exception as e:
            self.logger.error(f"Failed to create temporary files: {e}")
    
    def _browse_documents(self):
        """Browse documents"""
        self.logger.info("Browsed documents")
    
    def _check_weather(self):
        """Check weather"""
        try:
            subprocess.run(["curl", "-s", "http://wttr.in/?format=3"], 
                         capture_output=True, timeout=10)
            self.logger.info("Checked weather")
        except Exception as e:
            self.logger.error(f"Failed to check weather: {e}")
    
    def _simple_web_browsing(self):
        """Simple web browsing"""
        try:
            urls = ["http://example.com", "http://httpbin.org/get"]
            for url in urls:
                subprocess.run(["curl", "-s", url], 
                             capture_output=True, timeout=10)
            self.logger.info("Performed web browsing")
        except Exception as e:
            self.logger.error(f"Web browsing failed: {e}")
    
    def _open_existing_documents(self):
        self.logger.info("Opened existing documents")
    
    def _simple_editing(self):
        self.logger.info("Performed simple editing")
    
    def _watch_youtube_video(self):
        self.logger.info("Watched YouTube video")
    
    def _listen_to_music(self):
        self.logger.info("Listened to music")
    
    def _slack_chat(self):
        self.logger.info("Had Slack chat")
    
    def _zoom_meeting(self):
        self.logger.info("Attended Zoom meeting")
    
    def _edit_code(self):
        self.logger.info("Edited code")
    
    def _run_tests(self):
        self.logger.info("Ran tests")
    
    def _check_company_website(self):
        self.logger.info("Visited company website")
    
    def _read_news(self):
        self.logger.info("Read news")
    
    def run_attack(self):
        """Run attack"""
        variant_config = self.config['variants'][self.variant]
        attack_config = variant_config.get('attack', {})
        
        if not attack_config:
            self.logger.warning("No attack configuration found")
            return
        
        attack_type = attack_config.get('type')
        self.logger.info(f"Starting attack execution: {attack_type}")
        
        try:
            if attack_type == "ssh_bruteforce":
                self._run_ssh_bruteforce(attack_config)
            elif attack_type == "redis_unauthorized":
                self._run_redis_unauthorized(attack_config)
            elif attack_type == "macro_document":
                self._run_macro_document_attack(attack_config)
            else:
                self.logger.error(f"Unknown attack type: {attack_type}")
                
        except Exception as e:
            self.logger.error(f"Error executing attack: {e}")
    
    def _run_ssh_bruteforce(self, config):
        """Run SSH brute force attack"""
        target = config.get('target', 'localhost:22')
        username_list = config.get('username_list', ['root'])
        password_list = config.get('password_list', ['password'])
        attempts_per_second = config.get('attempts_per_second', 1)
        
        self.logger.info(f"Starting SSH brute force attack: {target}")
        
        for username in username_list:
            for password in password_list:
                self.logger.info(f"Attempting: {username}:{password}")
                time.sleep(1.0 / attempts_per_second)
        
        self.logger.info("SSH brute force attack completed")
    
    def _run_redis_unauthorized(self, config):
        """Run Redis unauthorized access attack"""
        target = config.get('target', 'localhost:6379')
        redis_commands = config.get('redis_commands', [])
        
        self.logger.info(f"Starting Redis unauthorized access attack: {target}")
        
        for command in redis_commands:
            self.logger.info(f"Executing Redis command: {command}")
            time.sleep(0.5)
        
        self.logger.info("Redis unauthorized access attack completed")
    
    def _run_macro_document_attack(self, config):
        """Run macro document attack"""
        document_type = config.get('document_type', 'word')
        delivery_method = config.get('delivery_method', 'email')
        
        self.logger.info(f"Starting macro document attack: {document_type} via {delivery_method}")
        
        self.logger.info("Simulating user opening malicious document")
        time.sleep(2)
        self.logger.info("Simulating user enabling macros")
        time.sleep(1)
        self.logger.info("Macro execution started")
        
        self.logger.info("Macro document attack completed")
    
    def run_post_attack(self):
        """Run post-attack behavior"""
        variant_config = self.config['variants'][self.variant]
        post_attack_configs = variant_config.get('post_attack', [])
        
        self.logger.info("Starting post-attack behavior execution")
        
        for post_attack_config in post_attack_configs:
            attack_type = post_attack_config.get('type')
            actions = post_attack_config.get('actions', [])
            
            self.logger.info(f"Executing post-attack behavior: {attack_type}")
            
            for action in actions:
                self.logger.info(f"Executing action: {action}")
                time.sleep(0.5)
        
        self.logger.info("Post-attack behavior execution completed")
    
    def run(self):
        """Run complete scenario"""
        self.logger.info(f"Starting scenario: {self.config.get('name')} (variant: {self.variant})")
        
        try:
            # 1. Start background activities
            self.run_background_activities()
            
            # 2. Wait for background activities to establish
            time.sleep(5)
            
            # 3. Execute attack
            self.run_attack()
            
            # 4. Execute post-attack behavior
            self.run_post_attack()
            
            # 5. Continue running background activities for a while
            time.sleep(10)
            
            self.logger.info("Scenario execution completed")
            
        except KeyboardInterrupt:
            self.logger.info("Scenario interrupted by user")
        except Exception as e:
            self.logger.error(f"Scenario execution error: {e}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python run_scenario.py <scenario_file> [variant]")
        print("Example: python run_scenario.py scenarios/ssh_attack/scenario.yaml simple")
        sys.exit(1)
    
    scenario_file = sys.argv[1]
    variant = sys.argv[2] if len(sys.argv) > 2 else "simple"
    
    if not os.path.exists(scenario_file):
        print(f"Error: Scenario file does not exist: {scenario_file}")
        sys.exit(1)
    
    # Create and run scenario
    runner = ScenarioRunner(scenario_file, variant)
    runner.run()

if __name__ == "__main__":
    main() 