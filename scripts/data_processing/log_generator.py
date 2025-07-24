#!/usr/bin/env python3
"""
Unified Log Generator
Automatically generates logs in the correct paths for ETL processing
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List
from .config import get_config

class LogGenerator:
    """Unified log generator for all log types"""
    
    def __init__(self, variant_id: str):
        self.variant_id = variant_id
        self.config = get_config(variant_id)
        self.config.create_directories()
    
    def generate_dns_proxy_logs(self, count: int = 50) -> str:
        """Generate DNS proxy logs with complete attack chain"""
        output_file = self.config.get_raw_log_path('dns_proxy_logs', 'dns_proxy_raw.jsonl')
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        dns_records = []
        
        # Phase 1: DNS Reconnaissance (30 records) - 3% of total
        reconnaissance_domains = [
            "www.victim-web.local", "admin.victim-web.local", "api.victim-web.local",
            "db.victim-web.local", "mail.victim-web.local", "ftp.victim-web.local",
            "ssh.victim-web.local", "vpn.victim-web.local", "jenkins.victim-web.local",
            "gitlab.victim-web.local", "jira.victim-web.local", "confluence.victim-web.local",
            "kibana.victim-web.local", "grafana.victim-web.local", "prometheus.victim-web.local",
            "elasticsearch.victim-web.local", "redis.victim-web.local", "mongodb.victim-web.local",
            "postgres.victim-web.local", "mysql.victim-web.local", "ldap.victim-web.local",
            "kerberos.victim-web.local", "radius.victim-web.local", "sso.victim-web.local",
            "oauth.victim-web.local", "saml.victim-web.local", "keycloak.victim-web.local",
            "monitoring.victim-web.local", "logging.victim-web.local", "cms.victim-web.local"
        ]
        
        # Phase 2: Normal traffic (950 records) - 95% of total
        normal_domains = [
            "www.google.com", "www.github.com", "www.stackoverflow.com",
            "www.wikipedia.org", "www.reddit.com", "www.youtube.com",
            "www.amazon.com", "www.microsoft.com", "www.apple.com", "www.netflix.com",
            "www.facebook.com", "www.twitter.com", "www.instagram.com", "www.linkedin.com",
            "www.medium.com", "www.dev.to", "www.hashnode.com", "www.producthunt.com",
            "www.hackernews.com", "www.techcrunch.com", "www.verge.com", "www.wired.com",
            "www.ars-technica.com", "www.engadget.com", "www.mashable.com", "www.gizmodo.com",
            "www.lifehacker.com", "www.kotaku.com", "www.jalopnik.com", "www.deadspin.com",
            "www.avclub.com", "www.splinter.com", "www.theroot.com", "www.kinja.com",
            "www.gawker.com", "www.jezebel.com", "www.gawker.com", "www.deadspin.com",
            "www.jalopnik.com", "www.kotaku.com", "www.lifehacker.com", "www.gizmodo.com",
            "www.io9.com", "www.jezebel.com", "www.deadspin.com", "www.jalopnik.com",
            "www.kotaku.com", "www.lifehacker.com", "www.gizmodo.com", "www.io9.com"
        ]
        
        # Phase 3: DNS tunneling for data exfiltration (20 records) - 2% of total
        tunnel_domains = [
            "cmd.attacker.local", "exfil.attacker.local", "tunnel.attacker.local",
            "data.attacker.local", "cc.attacker.local", "beacon.attacker.local",
            "agent.attacker.local", "shell.attacker.local", "backdoor.attacker.local",
            "malware.attacker.local", "control.attacker.local", "command.attacker.local",
            "exfiltrate.attacker.local", "tunnel1.attacker.local", "tunnel2.attacker.local",
            "data1.attacker.local", "data2.attacker.local", "cc1.attacker.local",
            "beacon1.attacker.local", "agent1.attacker.local"
        ]
        
        # Calculate proportions based on count
        recon_count = min(30, int(count * 0.03))  # 3% reconnaissance
        normal_count = int(count * 0.95)  # 95% normal traffic
        tunnel_count = min(20, int(count * 0.02))  # 2% attack traffic
        
        # Generate records with proper proportions
        all_records = []
        
        # Add reconnaissance records
        for i, domain in enumerate(reconnaissance_domains[:recon_count]):
            record = {
                "timestamp": datetime.now().isoformat() + "Z",
                "query": domain,
                "client_ip": "172.16.0.5",
                "response": f"172.16.0.{10 + i}",
                "record_type": "A",
                "is_attack": False,
                "attack_stage": "reconnaissance",
                "query_count": len(all_records) + 1
            }
            all_records.append(record)
            time.sleep(0.01)
        
        # Add normal traffic records
        for i in range(normal_count):
            domain = normal_domains[i % len(normal_domains)]
            record = {
                "timestamp": datetime.now().isoformat() + "Z",
                "query": domain,
                "client_ip": "172.16.0.5",
                "response": f"172.16.0.{20 + i}",
                "record_type": "A",
                "is_attack": False,
                "attack_stage": "normal",
                "query_count": len(all_records) + 1
            }
            all_records.append(record)
            time.sleep(0.01)
        
        # Add attack traffic records
        for i, domain in enumerate(tunnel_domains[:tunnel_count]):
            record = {
                "timestamp": datetime.now().isoformat() + "Z",
                "query": domain,
                "client_ip": "172.16.0.5",
                "response": f"172.16.0.{200 + i}",
                "record_type": "A",
                "is_attack": True,
                "attack_stage": "exfiltration",
                "query_count": len(all_records) + 1
            }
            all_records.append(record)
            time.sleep(0.01)
        
        # Take only the requested count
        dns_records = all_records[:count]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in dns_records:
                f.write(json.dumps(record, ensure_ascii=False) + '\n')
        
        print(f"✅ Generated {len(dns_records)} DNS proxy logs: {output_file}")
        print(f"   - Reconnaissance: {len(reconnaissance_domains)} queries")
        print(f"   - Normal traffic: {len(normal_domains)} queries") 
        print(f"   - Data exfiltration: {len(tunnel_domains)} queries")
        return output_file
    
    def generate_http_proxy_logs(self, count: int = 1000) -> str:
        """Generate HTTP proxy logs with complete attack chain"""
        output_file = self.config.get_raw_log_path('http_proxy_logs', 'http_proxy_raw.jsonl')
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        http_records = []
        
        # Phase 1: Normal web browsing (950 records) - 95% of total
        normal_urls = [
            "http://www.victim-web.local/",
            "http://www.victim-web.local/about",
            "http://www.victim-web.local/contact",
            "http://www.victim-web.local/products",
            "http://www.victim-web.local/services",
            "http://www.victim-web.local/help",
            "http://www.victim-web.local/faq",
            "http://www.victim-web.local/privacy",
            "http://www.victim-web.local/terms",
            "http://www.victim-web.local/sitemap",
            "http://www.victim-web.local/robots.txt",
            "http://www.victim-web.local/favicon.ico",
            "http://www.victim-web.local/css/style.css",
            "http://www.victim-web.local/js/script.js",
            "http://www.victim-web.local/images/logo.png",
            "http://www.google.com/",
            "http://www.github.com/",
            "http://www.stackoverflow.com/",
            "http://www.wikipedia.org/",
            "http://www.reddit.com/",
            "http://www.youtube.com/",
            "http://www.amazon.com/",
            "http://www.microsoft.com/",
            "http://www.apple.com/",
            "http://www.netflix.com/",
            "http://www.facebook.com/",
            "http://www.twitter.com/",
            "http://www.instagram.com/",
            "http://www.linkedin.com/",
            "http://www.medium.com/",
            "http://www.dev.to/",
            "http://www.hashnode.com/",
            "http://www.producthunt.com/",
            "http://www.hackernews.com/",
            "http://www.techcrunch.com/",
            "http://www.verge.com/",
            "http://www.wired.com/",
            "http://www.ars-technica.com/",
            "http://www.engadget.com/",
            "http://www.mashable.com/",
            "http://www.gizmodo.com/",
            "http://www.lifehacker.com/",
            "http://www.kotaku.com/",
            "http://www.jalopnik.com/",
            "http://www.deadspin.com/",
            "http://www.avclub.com/",
            "http://www.splinter.com/",
            "http://www.theroot.com/",
            "http://www.kinja.com/",
            "http://www.gawker.com/",
            "http://www.jezebel.com/",
            "http://www.io9.com/"
        ]
        
        # Phase 2: SQL Injection attempts (30 records) - 3% of total
        sql_injection_urls = [
            "http://www.victim-web.local/search?q=admin'",
            "http://www.victim-web.local/search?q=' OR 1=1--",
            "http://www.victim-web.local/search?q=' UNION SELECT * FROM users--",
            "http://www.victim-web.local/search?q=' AND SLEEP(5)--",
            "http://www.victim-web.local/search?q=' OR 'x'='x",
            "http://www.victim-web.local/search?q=' AND 1=1--",
            "http://www.victim-web.local/search?q=' OR 1=1#",
            "http://www.victim-web.local/search?q=' UNION SELECT username,password FROM users--",
            "http://www.victim-web.local/search?q=' AND (SELECT COUNT(*) FROM users)>0--",
            "http://www.victim-web.local/search?q=' OR EXISTS(SELECT * FROM users)--",
            "http://www.victim-web.local/search?q=' AND (SELECT LENGTH(username) FROM users LIMIT 1)>0--",
            "http://www.victim-web.local/search?q=' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "http://www.victim-web.local/search?q=' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
            "http://www.victim-web.local/search?q=' OR (SELECT COUNT(*) FROM information_schema.schemata)>0--",
            "http://www.victim-web.local/search?q=' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
            "http://www.victim-web.local/search?q=' OR (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>0--",
            "http://www.victim-web.local/search?q=' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='password')>0--",
            "http://www.victim-web.local/search?q=' OR (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='username')>0--",
            "http://www.victim-web.local/search?q=' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='id')>0--",
            "http://www.victim-web.local/search?q=' OR (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='email')>0--",
            "http://www.victim-web.local/search?q=' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='role')>0--",
            "http://www.victim-web.local/search?q=' OR (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='created_at')>0--",
            "http://www.victim-web.local/search?q=' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='updated_at')>0--",
            "http://www.victim-web.local/search?q=' UNION SELECT filename,path,size FROM files--"
        ]
        
        # Phase 3: Data extraction attempts (10 records)
        data_extraction_urls = [
            "http://www.victim-web.local/admin/users",
            "http://www.victim-web.local/admin/database",
            "http://www.victim-web.local/admin/config",
            "http://www.victim-web.local/admin/backup",
            "http://www.victim-web.local/admin/logs",
            "http://www.victim-web.local/api/users",
            "http://www.victim-web.local/api/data",
            "http://www.victim-web.local/api/config",
            "http://www.victim-web.local/backup/users.sql",
            "http://www.victim-web.local/backup/database.sql"
        ]
        
        all_urls = normal_urls + sql_injection_urls + data_extraction_urls
        
        for i, url in enumerate(all_urls[:count]):
            is_sql_injection = "'" in url or "UNION" in url or "OR 1=1" in url
            is_data_extraction = "admin" in url or "api" in url or "backup" in url
            
            method = "GET"
            status = "200" if not is_sql_injection else "500" if i % 3 == 0 else "200"
            size = 1000 + i * 50
            
            record = f"{datetime.now().isoformat()}Z {method} {url} {status} {size}"
            http_records.append(record)
            time.sleep(0.1)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in http_records:
                f.write(record + '\n')
        
        print(f"✅ Generated {len(http_records)} HTTP proxy logs: {output_file}")
        print(f"   - Normal traffic: {len(normal_urls)} requests")
        print(f"   - SQL injection: {len(sql_injection_urls)} attempts")
        print(f"   - Data extraction: {len(data_extraction_urls)} attempts")
        return output_file
    
    def generate_system_logs(self) -> str:
        """Generate system logs for security analysis"""
        # Ensure system logs directory exists
        os.makedirs(self.config.system_logs_dir, exist_ok=True)
        
        # Generate syslog
        syslog_file = self.config.syslog
        syslog_entries = [
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=12345 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0",
            f"{datetime.now().isoformat()}Z sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 12345 ssh2",
            f"{datetime.now().isoformat()}Z sshd[1234]: Connection closed by invalid user admin 192.168.1.100 port 12345 [preauth]",
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54322 DF PROTO=TCP SPT=12346 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0",
            f"{datetime.now().isoformat()}Z nginx: 192.168.1.100 - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"GET /admin HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
            f"{datetime.now().isoformat()}Z nginx: 192.168.1.100 - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"POST /login HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54323 DF PROTO=TCP SPT=12347 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0",
            f"{datetime.now().isoformat()}Z sshd[1235]: Accepted password for userA from 192.168.1.101 port 12348 ssh2",
            f"{datetime.now().isoformat()}Z sshd[1235]: session opened for user userA by (uid=0)",
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54324 DF PROTO=TCP SPT=12349 DPT=21 WINDOW=29200 RES=0x00 SYN URGP=0"
        ]
        
        with open(syslog_file, 'w', encoding='utf-8') as f:
            for entry in syslog_entries:
                f.write(entry + '\n')
        
        # Generate messages log
        messages_file = self.config.messages_log
        messages_entries = [
            f"{datetime.now().isoformat()}Z systemd[1]: Started SecurityLogs Web Application.",
            f"{datetime.now().isoformat()}Z systemd[1]: Started nginx - A high performance web server and a reverse proxy server.",
            f"{datetime.now().isoformat()}Z systemd[1]: Started OpenSSH server daemon.",
            f"{datetime.now().isoformat()}Z systemd[1]: Started PHP-FPM 7.4.",
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54325 DF PROTO=TCP SPT=12350 DPT=3306 WINDOW=29200 RES=0x00 SYN URGP=0",
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54326 DF PROTO=TCP SPT=12351 DPT=5432 WINDOW=29200 RES=0x00 SYN URGP=0",
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54327 DF PROTO=TCP SPT=12352 DPT=6379 WINDOW=29200 RES=0x00 SYN URGP=0",
            f"{datetime.now().isoformat()}Z systemd[1]: Started tcpdump - network packet analyzer.",
            f"{datetime.now().isoformat()}Z systemd[1]: Started rsyslog - System Logging Service.",
            f"{datetime.now().isoformat()}Z kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:05:00:15:5d:01:ca:06:08:00 SRC=192.168.1.100 DST=172.16.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54328 DF PROTO=TCP SPT=12353 DPT=27017 WINDOW=29200 RES=0x00 SYN URGP=0"
        ]
        
        with open(messages_file, 'w', encoding='utf-8') as f:
            for entry in messages_entries:
                f.write(entry + '\n')
        
        # Generate user.log
        user_log_file = self.config.user_log
        user_entries = [
            f"{datetime.now().isoformat()}Z userA: session opened for user userA by (uid=0)",
            f"{datetime.now().isoformat()}Z userA: session closed for user userA",
            f"{datetime.now().isoformat()}Z userB: session opened for user userB by (uid=0)",
            f"{datetime.now().isoformat()}Z userB: session closed for user userB",
            f"{datetime.now().isoformat()}Z userA: session opened for user userA by (uid=0)",
            f"{datetime.now().isoformat()}Z userA: session closed for user userA",
            f"{datetime.now().isoformat()}Z userB: session opened for user userB by (uid=0)",
            f"{datetime.now().isoformat()}Z userB: session closed for user userB",
            f"{datetime.now().isoformat()}Z userA: session opened for user userA by (uid=0)",
            f"{datetime.now().isoformat()}Z userA: session closed for user userA"
        ]
        
        with open(user_log_file, 'w', encoding='utf-8') as f:
            for entry in user_entries:
                f.write(entry + '\n')
        
        print(f"✅ Generated system logs:")
        print(f"   - Syslog: {syslog_file}")
        print(f"   - Messages: {messages_file}")
        print(f"   - User log: {user_log_file}")
        
        return syslog_file
    
    def generate_attack_logs(self) -> str:
        """Generate comprehensive attack logs"""
        output_file = self.config.container_attack_log
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        attack_data = {
            "container_attack_timestamp": datetime.now().isoformat(),
            "container_id": "securitylogs-attacker",
            "target_url": "http://172.16.0.5",
            "attack_type": "SQL_INJECTION",
            "attack_phase": "COMPLETE",
            "attack_start_time": (datetime.now().timestamp() - 300),
            "attack_end_time": datetime.now().timestamp(),
            "results": {
                "total_requests": 150,
                "successful_injections": 23,
                "failed_injections": 127,
                "data_extracted": True,
                "databases_discovered": ["victim_db", "admin_db"],
                "tables_discovered": ["users", "products", "orders", "config"],
                "columns_discovered": ["id", "username", "password", "email", "role"]
            },
            "custom_tests": {
                "login_injections": [
                    {"payload": "admin' OR '1'='1", "success": True, "response_time": 0.15},
                    {"payload": "admin' OR 1=1--", "success": True, "response_time": 0.12},
                    {"payload": "admin' UNION SELECT * FROM users--", "success": False, "response_time": 0.25},
                    {"payload": "admin' AND SLEEP(5)--", "success": True, "response_time": 5.1},
                    {"payload": "admin' OR 'x'='x", "success": True, "response_time": 0.11}
                ],
                "search_injections": [
                    {"payload": "' OR 1=1--", "success": True, "response_time": 0.18},
                    {"payload": "' UNION SELECT username,password FROM users--", "success": False, "response_time": 0.22},
                    {"payload": "' AND (SELECT COUNT(*) FROM users)>0--", "success": True, "response_time": 0.16},
                    {"payload": "' OR EXISTS(SELECT * FROM users)--", "success": True, "response_time": 0.14},
                    {"payload": "' AND (SELECT LENGTH(username) FROM users LIMIT 1)>0--", "success": True, "response_time": 0.17}
                ],
                "union_injections": [
                    {"payload": "' UNION SELECT NULL,NULL,NULL--", "success": True, "response_time": 0.19},
                    {"payload": "' UNION SELECT username,NULL,NULL FROM users--", "success": True, "response_time": 0.21},
                    {"payload": "' UNION SELECT username,password,NULL FROM users--", "success": False, "response_time": 0.24},
                    {"payload": "' UNION SELECT filename,path,size FROM files--", "success": True, "response_time": 0.20},
                    {"payload": "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "success": True, "response_time": 0.23}
                ]
            },
            "dns_attacks": {
                "timestamp": datetime.now().isoformat(),
                "target_domain": "victim-web.local",
                "attack_type": "DNS_RECONNAISSANCE",
                "results": {
                    "dns_reconnaissance": {
                        "discovered_subdomains": [
                            "www.victim-web.local",
                            "admin.victim-web.local", 
                            "api.victim-web.local",
                            "db.victim-web.local",
                            "mail.victim-web.local",
                            "ftp.victim-web.local",
                            "ssh.victim-web.local",
                            "vpn.victim-web.local",
                            "jenkins.victim-web.local",
                            "gitlab.victim-web.local"
                        ],
                        "total_subdomains": 10,
                        "scan_duration": 45.2
                    },
                    "data_exfiltration": {
                        "method": "DNS_TUNNELING",
                        "records_exfiltrated": 150,
                        "data_size": "2.3KB",
                        "tunnel_domains": [
                            "cmd.attacker.local",
                            "exfil.attacker.local", 
                            "tunnel.attacker.local",
                            "data.attacker.local",
                            "cc.attacker.local"
                        ]
                    }
                }
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(attack_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Generated comprehensive attack logs: {output_file}")
        print(f"   - SQL injection attempts: {len(attack_data['custom_tests']['login_injections']) + len(attack_data['custom_tests']['search_injections']) + len(attack_data['custom_tests']['union_injections'])}")
        print(f"   - DNS reconnaissance: {len(attack_data['dns_attacks']['results']['dns_reconnaissance']['discovered_subdomains'])} subdomains")
        print(f"   - Data exfiltration: {attack_data['dns_attacks']['results']['data_exfiltration']['records_exfiltrated']} records")
        return output_file
    
    def generate_all_logs(self):
        """Generate all types of logs"""
        print(f"🚀 Generating logs for variant: {self.variant_id}")
        
        # Generate DNS proxy logs
        self.generate_dns_proxy_logs(1000)
        
        # Generate HTTP proxy logs  
        self.generate_http_proxy_logs(1000)
        
        # Generate system logs
        self.generate_system_logs()
        
        # Generate attack logs
        self.generate_attack_logs()
        
        print("✅ All logs generated successfully!")
        
        # List available logs
        available_logs = self.config.list_available_logs()
        print("\n📁 Available logs:")
        for log_type, files in available_logs.items():
            if files:
                print(f"  {log_type}: {len(files)} files")
                for file in files[:3]:  # Show first 3 files
                    print(f"    - {os.path.basename(file)}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate logs for ETL processing")
    parser.add_argument("--variant-id", required=True, help="Variant ID")
    parser.add_argument("--dns-count", type=int, default=1000, help="Number of DNS proxy logs to generate")
    parser.add_argument("--http-count", type=int, default=1000, help="Number of HTTP proxy logs to generate")
    
    args = parser.parse_args()
    
    generator = LogGenerator(args.variant_id)
    generator.generate_dns_proxy_logs(args.dns_count)
    generator.generate_http_proxy_logs(args.http_count)
    generator.generate_system_logs()
    generator.generate_attack_logs()
    
    print("✅ Log generation completed!")

if __name__ == "__main__":
    main() 