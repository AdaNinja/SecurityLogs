#!/usr/bin/env python3
"""
Log Parser for CyberRange
Parses various log files and outputs unified CSV format
"""

import os
import sys
import argparse
import logging
import csv
from pathlib import Path
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import parsers from flattened structure
from nginx_parser import NginxParser
from attack_parser import AttackParser
from user_parser import ApplicationParser


def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

# Create global logger
logger = logging.getLogger(__name__)





def parse_nginx_logs(input_file: str, output_file: str):
    """Parse nginx logs to CSV"""
    try:
        parser = NginxParser('nginx')
        
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        with open(output_file, 'w', encoding='utf-8', newline='') as csv_file:
            # Write CSV header
            csv_file.write('timestamp,source_type,source_name,event_type,severity,message,ip_src,ip_dst,port_src,port_dst,protocol,user_agent,request_method,request_path,response_code,payload,label\n')
            
            for line in lines:
                line = line.strip()
                if line:
                    result = parser.parse_line(line)
                    if result:
                        # Escape quotes in CSV fields
                        message = result['message'].replace('"', '""')
                        user_agent = result['user_agent'].replace('"', '""')
                        payload = result['payload'].replace('"', '""')
                        
                        csv_file.write(f'{result["timestamp"]},{result["source_type"]},{result["source_name"]},{result["event_type"]},{result["severity"]},"{message}",{result["ip_src"]},{result["ip_dst"]},{result["port_src"]},{result["port_dst"]},{result["protocol"]},"{user_agent}",{result["request_method"]},{result["request_path"]},{result["response_code"]},"{payload}",{result["label"]}\n')

        logging.info(f"✅ Nginx logs parsed successfully: {output_file}")
        return True
        
    except Exception as e:
        logging.error(f"❌ Failed to parse nginx logs: {e}")
        return False


def parse_merged_attack_logs(attack_files: list, output_file: str):
    """Parse and merge multiple attack log files into single CSV"""
    try:
        from attack_parser import AttackParser
        
        parser = AttackParser('attacker')
        total_lines = 0
        
        with open(output_file, 'w', encoding='utf-8', newline='') as csv_file:
            # Write CSV header
            csv_file.write('timestamp,source_type,source_name,event_type,severity,message,ip_src,ip_dst,port_src,port_dst,protocol,user_agent,request_method,request_path,response_code,payload,label,log_file\n')
            
            for attack_file in attack_files:
                filename = os.path.basename(attack_file)
                logging.info(f"Processing attack file: {filename}")
                
                try:
                    with open(attack_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    
                    for line in lines:
                        line = line.strip()
                        if line:
                            result = parser.parse_line(line)
                            if result:
                                # Escape quotes in CSV fields
                                message = result['message'].replace('"', '""')
                                user_agent = result['user_agent'].replace('"', '""')
                                payload = result['payload'].replace('"', '""')
                                
                                csv_file.write(f'{result["timestamp"]},{result["source_type"]},{result["source_name"]},{result["event_type"]},{result["severity"]},"{message}",{result["ip_src"]},{result["ip_dst"]},{result["port_src"]},{result["port_dst"]},{result["protocol"]},"{user_agent}",{result["request_method"]},{result["request_path"]},{result["response_code"]},"{payload}",{result["label"]},{filename}\n')
                                total_lines += 1
                                
                except Exception as e:
                    logging.warning(f"Failed to parse attack file {filename}: {e}")
                    continue

        logging.info(f"✅ Merged {len(attack_files)} attack log files into {output_file} ({total_lines} total records)")
        return True
        
    except Exception as e:
        logging.error(f"❌ Failed to merge attack logs: {e}")
        return False


def parse_attack_logs(input_file: str, output_file: str):
    """Parse attack logs to CSV"""
    try:
        from attack_parser import AttackParser
        
        parser = AttackParser('attacker')
        
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        with open(output_file, 'w', encoding='utf-8', newline='') as csv_file:
            # Write CSV header
            csv_file.write('timestamp,source_type,source_name,event_type,severity,message,ip_src,ip_dst,port_src,port_dst,protocol,user_agent,request_method,request_path,response_code,payload,label\n')
            
            for line in lines:
                line = line.strip()
                if line:
                    result = parser.parse_line(line)
                    if result:
                        # Escape quotes in CSV fields
                        message = result['message'].replace('"', '""')
                        user_agent = result['user_agent'].replace('"', '""')
                        payload = result['payload'].replace('"', '""')
                        
                        csv_file.write(f'{result["timestamp"]},{result["source_type"]},{result["source_name"]},{result["event_type"]},{result["severity"]},"{message}",{result["ip_src"]},{result["ip_dst"]},{result["port_src"]},{result["port_dst"]},{result["protocol"]},"{user_agent}",{result["request_method"]},{result["request_path"]},{result["response_code"]},"{payload}",{result["label"]}\n')

        logging.info(f"✅ Attack logs parsed successfully: {output_file}")
        return True
        
    except Exception as e:
        logging.error(f"❌ Failed to parse attack logs: {e}")
        return False


def parse_user_behavior_logs(input_file: str, output_file: str):
    """Parse user behavior logs"""
    try:
        parser = ApplicationParser('user_behavior')
        parsed_count = parser.parse_file(input_file, output_file)
        
        if parsed_count > 0:
            logging.info(f"✅ User behavior logs parsed successfully: {output_file}")
            return True
        else:
            logging.warning(f"⚠️ No data parsed from user behavior logs: {input_file}")
            return False
            
    except Exception as e:
        logging.error(f"❌ Failed to parse user behavior logs {input_file}: {e}")
        return False


def parse_user_log_line(line: str):
    """Parse a single user log line"""
    try:
        # Extract timestamp if present
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)', line)
        timestamp = timestamp_match.group(1) if timestamp_match else datetime.now().isoformat() + "Z"
        
        # Extract user ID and session ID from headers
        user_id_match = re.search(r'X-User-ID:\s*([^\s]+)', line)
        session_id_match = re.search(r'X-Session-ID:\s*([^\s]+)', line)
        
        user_id = user_id_match.group(1) if user_id_match else "unknown"
        session_id = session_id_match.group(1) if session_id_match else "unknown"
        
        # Determine event type and action based on content
        event_type = "user_activity"
        action = "unknown"
        resource = "unknown"
        result = "success"
        severity = "info"
        
        # Parse different types of activities
        if "🏠 Browsing homepage" in line:
            action = "browse"
            resource = "homepage"
            message = "User browsed homepage"
        elif "🔍 Searching for:" in line:
            search_match = re.search(r'Searching for:\s*([^\s]+)', line)
            search_term = search_match.group(1) if search_match else "unknown"
            action = "search"
            resource = f"search:{search_term}"
            message = f"User searched for: {search_term}"
        elif "📂 Browsing category:" in line:
            category_match = re.search(r'Browsing category:\s*([^\s]+)', line)
            category = category_match.group(1) if category_match else "unknown"
            action = "browse"
            resource = f"category:{category}"
            message = f"User browsed category: {category}"
        elif "📱 Viewing product:" in line:
            product_match = re.search(r'Viewing product:\s*([^(]+)', line)
            product = product_match.group(1).strip() if product_match else "unknown"
            action = "view"
            resource = f"product:{product}"
            message = f"User viewed product: {product}"
        elif "🛒 Adding product" in line:
            action = "add_to_cart"
            resource = "shopping_cart"
            message = "User added product to cart"
        elif "🛒 Viewing shopping cart" in line:
            action = "view"
            resource = "shopping_cart"
            message = "User viewed shopping cart"
        elif "🗑️ Removing product" in line:
            action = "remove_from_cart"
            resource = "shopping_cart"
            message = "User removed product from cart"
        elif "🔐 Attempting user login" in line:
            action = "login"
            resource = "authentication"
            message = "User attempted login"
        elif "📝 Attempting user registration" in line:
            action = "register"
            resource = "authentication"
            message = "User attempted registration"
        elif "📧 Submitting contact form" in line:
            action = "submit"
            resource = "contact_form"
            message = "User submitted contact form"
        elif "🔌 Making API call:" in line:
            api_match = re.search(r'Making API call:\s*([^\s]+)', line)
            api_endpoint = api_match.group(1) if api_match else "unknown"
            action = "api_call"
            resource = f"api:{api_endpoint}"
            message = f"User made API call: {api_endpoint}"
        elif "✅" in line or "Status:" in line:
            # HTTP response
            status_match = re.search(r'Status:\s*(\d+)', line)
            if status_match:
                status_code = status_match.group(1)
                if status_code.startswith('4') or status_code.startswith('5'):
                    severity = "warning"
                    result = "error"
                else:
                    result = "success"
            action = "http_request"
            resource = "web_server"
            message = "HTTP request completed"
        elif "❌" in line or "Error:" in line:
            severity = "error"
            result = "error"
            action = "http_request"
            resource = "web_server"
            message = "HTTP request failed"
        else:
            # Generic activity
            message = line[:100]  # Truncate long messages
        
        return {
            'timestamp': timestamp,
            'source_type': 'application',
            'source_name': 'benign_user',
            'event_type': event_type,
            'severity': severity,
            'message': message,
            'user_id': user_id,
            'session_id': session_id,
            'action': action,
            'resource': resource,
            'result': result
        }
        
    except Exception as e:
        logging.warning(f"Failed to parse user log line: {e}")
        return None


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Parse log files to CSV format')
    parser.add_argument('--input-dir', default='logs', help='Input directory containing log files')
    parser.add_argument('--output-dir', default='output', help='Output directory for CSV files')
    parser.add_argument('--log-type', choices=['all', 'nginx', 'attack', 'user'], default='all', 
                       help='Type of logs to parse')
    
    args = parser.parse_args()
    
    setup_logging()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    success_count = 0
    total_count = 0
    
    # Parse nginx logs
    if args.log_type in ['all', 'nginx']:
        nginx_files = [
            ('nginx/detailed.log', 'nginx_detailed.csv'),
            ('nginx/access.log', 'nginx_access.csv'),
            ('nginx/error.log', 'nginx_error.csv')
        ]
        
        for input_file, output_file in nginx_files:
            input_path = os.path.join(args.input_dir, input_file)
            output_path = os.path.join(args.output_dir, output_file)
            
            if os.path.exists(input_path):
                total_count += 1
                if parse_nginx_logs(input_path, output_path):
                    success_count += 1
        
        # Generate network traffic CSV from nginx logs
        nginx_log_path = os.path.join(args.input_dir, 'nginx/detailed.log')
        if os.path.exists(nginx_log_path):
            logger.info("Generating network traffic CSV from nginx detailed log...")
            try:
                from network_traffic_generator import NetworkTrafficGenerator
                generator = NetworkTrafficGenerator()
                
                # 加载nginx日志
                if generator.load_nginx_log(nginx_log_path):
                    # 生成CSV
                    output_path = os.path.join(args.output_dir, 'network_traffic.csv')
                    if generator.generate_network_traffic_csv(output_path):
                        logger.info("Successfully generated network traffic CSV")
                    else:
                        logger.error("Failed to generate network traffic CSV")
                else:
                    logger.error("Failed to load nginx log")
            except Exception as e:
                logger.error(f"Error generating network traffic CSV: {e}")
        

    
    # Parse attack logs - merge all into single CSV
    if args.log_type in ['all', 'attack']:
        # Look for attack log files with pattern structured_attack_*.log
        import glob
        attack_log_pattern = os.path.join(args.input_dir, 'attacker', 'structured_attack_*.log')
        attack_files = glob.glob(attack_log_pattern)
        
        if attack_files:
            # Merge all attack logs into single consolidated CSV
            output_path = os.path.join(args.output_dir, 'attack_consolidated.csv')
            total_count += 1
            if parse_merged_attack_logs(attack_files, output_path):
                success_count += 1
        else:
            # Fallback to old pattern
            attack_files = [
                ('attacker/attack.log', 'attack_log.csv'),
                ('attacker/attack_script.log', 'attack_script.csv')
            ]
            
            for input_file, output_file in attack_files:
                input_path = os.path.join(args.input_dir, input_file)
                output_path = os.path.join(args.output_dir, output_file)
                
                if os.path.exists(input_path):
                    total_count += 1
                    if parse_attack_logs(input_path, output_path):
                        success_count += 1
    
    # Parse user behavior logs
    if args.log_type in ['all', 'user']:
        user_files = [
            ('benign_user/user.log', 'user_behavior.csv'),
            ('benign_user/behavior.log', 'user_behavior_alt.csv'),
            ('benign_user/application.log', 'user_application.csv')
        ]
        
        for input_file, output_file in user_files:
            input_path = os.path.join(args.input_dir, input_file)
            output_path = os.path.join(args.output_dir, output_file)
            
            if os.path.exists(input_path):
                total_count += 1
                if parse_user_behavior_logs(input_path, output_path):
                    success_count += 1
    
    # 仅复制PCAP文件到输出目录，不生成CSV
    pcap_files = list(Path(args.input_dir).glob('*.pcap'))
    for pcap_file in pcap_files:
        output_pcap = os.path.join(args.output_dir, pcap_file.name)
        try:
            import shutil
            shutil.copy2(pcap_file, output_pcap)
            logging.info(f"✅ Copied pcap file: {output_pcap}")
            total_count += 1
            success_count += 1
        except Exception as e:
            logging.error(f"❌ Failed to copy pcap file: {e}")
            total_count += 1
    
    logging.info(f"📊 Parsing completed: {success_count}/{total_count} files processed successfully")
    
    # Generate network traffic summary if network_traffic.csv exists
    network_traffic_csv = os.path.join(args.output_dir, 'network_traffic.csv')
    if os.path.exists(network_traffic_csv):
        try:
            from traffic_summary_generator import TrafficSummaryGenerator
            
            summary_generator = TrafficSummaryGenerator()
            if summary_generator.analyze_network_traffic(network_traffic_csv):
                # Generate summary report
                summary_json = os.path.join(args.output_dir, 'network_traffic_summary.json')
                if summary_generator.generate_summary_report(summary_json):
                    logging.info(f"✅ Generated network traffic summary: {summary_json}")
                    summary_generator.print_summary()
                else:
                    logging.error("❌ Failed to generate network traffic summary")
            else:
                logging.error("❌ Failed to analyze network traffic")
        except Exception as e:
            logging.error(f"❌ Error generating network traffic summary: {e}")
    
    if success_count == total_count:
        logging.info("🎉 All files parsed successfully!")
        return 0
    else:
        logging.warning("⚠️ Some files failed to parse")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 