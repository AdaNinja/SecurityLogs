#!/usr/bin/env python3
"""
Data Exfiltration Receiver Server
接收和记录数据外泄的HTTP服务器
"""

import os
import json
import time
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# 获取实验名称（从环境变量或默认值）
EXPERIMENT_NAME = os.environ.get('EXPERIMENT_NAME', 'default_experiment')
FULL_EXPERIMENT_NAME = os.environ.get('FULL_EXPERIMENT_NAME', EXPERIMENT_NAME)
EXFILTRATED_DATA_DIR = f'/exfiltrated_data/{FULL_EXPERIMENT_NAME}'
SHARED_DATA_DIR = f'/shared_data/{FULL_EXPERIMENT_NAME}'

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/data_exfiltration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DataExfiltrationHandler(BaseHTTPRequestHandler):
    """处理数据外泄请求的HTTP处理器"""
    
    def log_message(self, format, *args):
        """重写日志方法，使用自定义logger"""
        logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        """处理GET请求"""
        try:
            parsed_path = urlparse(self.path)
            
            if parsed_path.path == '/status':
                # 状态检查
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                status = {
                    'status': 'active',
                    'timestamp': datetime.now().isoformat(),
                    'server': 'data-exfiltration-receiver',
                    'experiment_name': EXPERIMENT_NAME,
                    'full_experiment_name': FULL_EXPERIMENT_NAME,
                    'received_files': len(os.listdir(EXFILTRATED_DATA_DIR)) if os.path.exists(EXFILTRATED_DATA_DIR) else 0,
                    'exfiltrated_data_dir': EXFILTRATED_DATA_DIR,
                    'shared_data_dir': SHARED_DATA_DIR
                }
                self.wfile.write(json.dumps(status).encode())
                
            elif parsed_path.path == '/instructions':
                # C2指令
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                
                instructions = "continue_data_collection"
                self.wfile.write(instructions.encode())
                
                # 记录C2通信
                self.log_exfiltration_event('c2_instruction', {
                    'client_ip': self.client_address[0],
                    'instruction': instructions,
                    'path': self.path
                })
                
            else:
                self.send_response(404)
                self.end_headers()
                
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_response(500)
            self.end_headers()
    
    def do_POST(self):
        """处理POST请求 - 数据外泄"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            content_type = self.headers.get('Content-Type', '')
            
            parsed_path = urlparse(self.path)
            
            if parsed_path.path == '/upload':
                # 文件上传
                self.handle_file_upload(content_length, content_type)
                
            elif parsed_path.path == '/data':
                # 数据传输
                self.handle_data_transfer(content_length)
                
            elif parsed_path.path == '/docs':
                # 文档外泄
                self.handle_document_exfiltration(content_length, content_type)
                
            elif parsed_path.path == '/db':
                # 数据库外泄
                self.handle_database_exfiltration(content_length)
                
            elif parsed_path.path == '/checkin':
                # C2签到
                self.handle_c2_checkin(content_length)
                
            else:
                self.send_response(404)
                self.end_headers()
                
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_response(500)
            self.end_headers()
    
    def handle_file_upload(self, content_length, content_type):
        """处理文件上传"""
        if 'multipart/form-data' in content_type:
            # 处理multipart文件上传
            post_data = self.rfile.read(content_length)
            
            # 简单解析multipart数据（实际应用中应使用专门的库）
            filename = f"uploaded_file_{int(time.time())}.bin"
            filepath = f"{EXFILTRATED_DATA_DIR}/{filename}"
            
            # 确保目录存在
            os.makedirs(EXFILTRATED_DATA_DIR, exist_ok=True)
            
            # 保存文件
            with open(filepath, 'wb') as f:
                f.write(post_data)
            
            # 记录外泄事件
            self.log_exfiltration_event('file_upload', {
                'client_ip': self.client_address[0],
                'filename': filename,
                'size': len(post_data),
                'content_type': content_type,
                'saved_path': filepath
            })
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                'status': 'success',
                'message': 'File uploaded successfully',
                'filename': filename,
                'size': len(post_data)
            }
            self.wfile.write(json.dumps(response).encode())
            
        else:
            self.send_response(400)
            self.end_headers()
    
    def handle_data_transfer(self, content_length):
        """处理数据传输"""
        post_data = self.rfile.read(content_length)
        
        # 保存数据
        timestamp = int(time.time())
        filename = f"exfiltrated_data_{timestamp}.txt"
        filepath = f"{EXFILTRATED_DATA_DIR}/{filename}"
        
        os.makedirs(EXFILTRATED_DATA_DIR, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            f.write(post_data)
        
        # 记录外泄事件
        self.log_exfiltration_event('data_transfer', {
            'client_ip': self.client_address[0],
            'filename': filename,
            'size': len(post_data),
            'data_preview': post_data[:100].decode('utf-8', errors='ignore'),
            'saved_path': filepath
        })
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            'status': 'success',
            'message': 'Data received successfully',
            'size': len(post_data)
        }
        self.wfile.write(json.dumps(response).encode())
    
    def handle_document_exfiltration(self, content_length, content_type):
        """处理文档外泄"""
        post_data = self.rfile.read(content_length)
        
        timestamp = int(time.time())
        filename = f"document_{timestamp}.bin"
        filepath = f"{EXFILTRATED_DATA_DIR}/{filename}"
        
        os.makedirs(EXFILTRATED_DATA_DIR, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            f.write(post_data)
        
        # 记录外泄事件
        self.log_exfiltration_event('document_exfiltration', {
            'client_ip': self.client_address[0],
            'filename': filename,
            'size': len(post_data),
            'content_type': content_type,
            'saved_path': filepath
        })
        
        self.send_response(200)
        self.end_headers()
    
    def handle_database_exfiltration(self, content_length):
        """处理数据库外泄"""
        post_data = self.rfile.read(content_length)
        
        timestamp = int(time.time())
        filename = f"database_dump_{timestamp}.sql.gz"
        filepath = f"{EXFILTRATED_DATA_DIR}/{filename}"
        
        os.makedirs(EXFILTRATED_DATA_DIR, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            f.write(post_data)
        
        # 记录外泄事件
        self.log_exfiltration_event('database_exfiltration', {
            'client_ip': self.client_address[0],
            'filename': filename,
            'size': len(post_data),
            'type': 'database_dump',
            'saved_path': filepath
        })
        
        self.send_response(200)
        self.end_headers()
    
    def handle_c2_checkin(self, content_length):
        """处理C2签到"""
        post_data = self.rfile.read(content_length)
        
        try:
            checkin_data = json.loads(post_data.decode('utf-8'))
        except:
            checkin_data = {'raw_data': post_data.decode('utf-8', errors='ignore')}
        
        # 记录C2通信
        self.log_exfiltration_event('c2_checkin', {
            'client_ip': self.client_address[0],
            'checkin_data': checkin_data,
            'size': len(post_data)
        })
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            'status': 'success',
            'message': 'Checkin received',
            'next_instruction': 'continue_operation'
        }
        self.wfile.write(json.dumps(response).encode())
    
    def log_exfiltration_event(self, event_type, event_data):
        """记录数据外泄事件"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'client_ip': self.client_address[0],
            'user_agent': self.headers.get('User-Agent', ''),
            'event_data': event_data
        }
        
        # 写入专门的外泄日志
        exfil_log_path = '/logs/exfiltration_events.jsonl'
        with open(exfil_log_path, 'a') as f:
            f.write(json.dumps(event) + '\n')
        
        logger.info(f"Data exfiltration event: {event_type} from {self.client_address[0]}")

def start_data_receiver():
    """启动数据接收服务器"""
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, DataExfiltrationHandler)
    
    logger.info("Starting data exfiltration receiver on port 8080...")
    logger.info("Endpoints available:")
    logger.info("  POST /upload - File uploads")
    logger.info("  POST /data - Raw data transfer")
    logger.info("  POST /docs - Document exfiltration")
    logger.info("  POST /db - Database dumps")
    logger.info("  POST /checkin - C2 checkin")
    logger.info("  GET /status - Server status")
    logger.info("  GET /instructions - C2 instructions")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down data receiver...")
        httpd.shutdown()

if __name__ == '__main__':
    # 确保日志目录存在
    os.makedirs('/logs', exist_ok=True)
    os.makedirs(EXFILTRATED_DATA_DIR, exist_ok=True)
    os.makedirs(SHARED_DATA_DIR, exist_ok=True)
    
    print(f"Data Exfiltration Receiver - Experiment: {EXPERIMENT_NAME}")
    print(f"Full Experiment Name: {FULL_EXPERIMENT_NAME}")
    print(f"Exfiltrated Data Directory: {EXFILTRATED_DATA_DIR}")
    print(f"Shared Data Directory: {SHARED_DATA_DIR}")
    
    start_data_receiver()
