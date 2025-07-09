#!/usr/bin/env python3
"""
Service installer for phishing attack scenario
Installs and configures required services (MailHog, etc.)
"""

import os
import subprocess
import requests
import logging
import time
import threading
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ServiceInstaller:
    def __init__(self, params):
        self.params = params
        self.services = params.get("services", {})
        self.processes = {}
        
    def install_mailhog(self):
        """Install MailHog email testing tool"""
        if not self.services.get("mailhog", {}).get("install", False):
            logger.info("MailHog installation not required")
            return True
            
        try:
            logger.info("Installing MailHog...")
            
            # Download MailHog
            download_url = self.services["mailhog"]["download_url"]
            version = self.services["mailhog"]["version"]
            
            # Create installation directory
            install_dir = "/usr/local/bin"
            os.makedirs(install_dir, exist_ok=True)
            
            # Download MailHog binary
            logger.info(f"Downloading MailHog {version}...")
            response = requests.get(download_url, stream=True)
            response.raise_for_status()
            
            mailhog_path = f"{install_dir}/mailhog"
            with open(mailhog_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Make executable
            os.chmod(mailhog_path, 0o755)
            
            logger.info("MailHog installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install MailHog: {e}")
            return False
    
    def start_mailhog(self):
        """Start MailHog service"""
        try:
            smtp_port = self.services["mailhog"]["ports"]["smtp"]
            web_port = self.services["mailhog"]["ports"]["web_ui"]
            
            # Start MailHog in background
            cmd = [
                "mailhog",
                "-api-bind-addr", f"0.0.0.0:{web_port}",
                "-ui-bind-addr", f"0.0.0.0:{web_port}",
                "-smtp-bind-addr", f"0.0.0.0:{smtp_port}"
            ]
            
            logger.info(f"Starting MailHog on SMTP:{smtp_port}, Web:{web_port}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes["mailhog"] = process
            
            # Wait for service to start
            time.sleep(3)
            
            # Check if process is running
            if process.poll() is None:
                logger.info("MailHog started successfully")
                return True
            else:
                logger.error("MailHog failed to start")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start MailHog: {e}")
            return False
    
    def start_credential_collector(self):
        """Start credential collection server"""
        try:
            if not self.services.get("credential_collector", {}).get("install", False):
                logger.info("Credential collector installation not required")
                return True
            
            port = self.services["credential_collector"]["port"]
            
            # Import and start credential collector
            from scenarios.phishing.credential_collector import start_server_background
            
            logger.info(f"Starting credential collection server on port {port}")
            server_thread = start_server_background(port=port)
            self.processes["credential_collector"] = server_thread
            
            logger.info("Credential collection server started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start credential collector: {e}")
            return False
    
    def verify_services(self):
        """Verify all required services are running"""
        services_status = {}
        
        # Check MailHog
        if self.services.get("mailhog", {}).get("install", False):
            try:
                web_port = self.services["mailhog"]["ports"]["web_ui"]
                response = requests.get(f"http://localhost:{web_port}", timeout=5)
                services_status["mailhog"] = response.status_code == 200
                logger.info(f"MailHog status: {'✓' if services_status['mailhog'] else '✗'}")
            except:
                services_status["mailhog"] = False
                logger.error("MailHog verification failed")
        
        # Check credential collector
        if self.services.get("credential_collector", {}).get("install", False):
            try:
                port = self.services["credential_collector"]["port"]
                response = requests.get(f"http://localhost:{port}/health", timeout=5)
                services_status["credential_collector"] = response.status_code == 200
                logger.info(f"Credential collector status: {'✓' if services_status['credential_collector'] else '✗'}")
            except:
                services_status["credential_collector"] = False
                logger.error("Credential collector verification failed")
        
        return services_status
    
    def install_all_services(self):
        """Install and start all required services"""
        logger.info("Installing and configuring services...")
        
        # Install MailHog
        if not self.install_mailhog():
            return False
        
        # Start MailHog
        if not self.start_mailhog():
            return False
        
        # Start credential collector
        if not self.start_credential_collector():
            return False
        
        # Verify services
        services_status = self.verify_services()
        
        all_running = all(services_status.values())
        if all_running:
            logger.info("All services installed and running successfully")
        else:
            logger.warning("Some services failed to start")
            
        return all_running
    
    def cleanup(self):
        """Cleanup running services"""
        logger.info("Cleaning up services...")
        
        for service_name, process in self.processes.items():
            try:
                if hasattr(process, 'terminate'):
                    process.terminate()
                    logger.info(f"Terminated {service_name}")
                elif hasattr(process, 'is_alive') and process.is_alive():
                    # Thread-based service
                    logger.info(f"Stopping {service_name} thread")
            except Exception as e:
                logger.error(f"Error cleaning up {service_name}: {e}")

def install_services(params):
    """Main function to install services"""
    installer = ServiceInstaller(params)
    return installer.install_all_services() 