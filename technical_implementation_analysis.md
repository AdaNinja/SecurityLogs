# SecurityLogs 技术实现详细分析报告

## 老师问题解答

### 问题1: 低扫描+慢速SQLi是在哪些文件，如何实现的四阶段攻击链的？

#### 核心实现文件

**1. 攻击链主控制器**
- **文件**: `scripts/attack/container_attack.py`
- **功能**: 协调整个五阶段攻击链的执行
- **实现方式**: Python脚本，按顺序执行各个攻击阶段

**2. 四阶段攻击链实现**

##### 阶段1: 网络侦察 (Network Reconnaissance)
- **文件**: `scripts/attack/network_scan.py`
- **实现方式**: 
  ```python
  class NetworkScanner:
      def __init__(self, target_host, scan_rate=0.016):
          self.scan_rate = scan_rate  # 可配置的扫描速率
          
      def perform_host_discovery(self):
          # 使用nmap进行超慢速主机发现
          scan_args = f"-sn -PE -n --max-retries 1 --min-rate {self.scan_rate}"
          
      def perform_port_scan(self, hosts):
          # 慢速端口扫描
          scan_args = f"-sS -p- --min-rate {self.scan_rate} --max-retries 2"
  ```
- **低扫描特征**: 扫描速率可配置为0.008-0.05 packets/sec

##### 阶段2: Web枚举 (Web Enumeration)
- **文件**: `scripts/attack/container_attack.py` (web_enumeration_phase方法)
- **实现方式**:
  ```bash
  # 使用dirb进行目录枚举
  dirb "$TARGET_URL" /usr/share/dirb/wordlists/common.txt -o /opt/output/dirb_results.txt -S -r
  
  # 使用nikto进行漏洞扫描
  nikto -h "$TARGET_URL" -o /opt/output/nikto_results.txt -Format txt
  ```

##### 阶段3: SQL注入 (SQL Injection)
- **文件**: `scripts/attack/container_attack.py` (custom_sql_injection_phase方法)
- **实现方式**:
  ```python
  class SQLInjectionAttacker:
      def __init__(self, target_url, delay=120, threads=1):
          self.delay = delay  # 可配置的注入延迟
          
      def test_login_injection(self, payload):
          # 测试登录表单SQL注入
          params = {'user': payload, 'pass': 'dummy'}
          
      def test_search_injection(self, payload):
          # 测试搜索表单SQL注入
          params = {'q': payload}
  ```
- **慢速注入特征**: SQL注入延迟可配置为60-300秒

##### 阶段4: 数据提取 (Data Extraction)
- **文件**: `scripts/attack/container_attack.py` (sqlmap_phase和data_extraction_phase方法)
- **实现方式**:
  ```bash
  # 使用SQLMap进行自动化SQL注入测试
  sqlmap -u "$TARGET_URL/login.php?user=*&pass=*" \
      --batch \
      --random-agent \
      --threads="$SQLMAP_THREADS" \
      --delay="$SQL_DELAY" \
      --output-dir=/opt/output/sqlmap_login
      
  # 使用SQLMap提取数据库信息
  sqlmap -u "$TARGET_URL/search.php?q=*" \
      --batch \
      --random-agent \
      --threads="$SQLMAP_THREADS" \
      --delay="$SQL_DELAY" \
      --dbs \
      --tables \
      --dump \
      --output-dir=/opt/output/sqlmap_advanced
  ```

#### 低扫描+慢速SQLi的技术实现

**低扫描实现**:
- **配置参数**: `NMAP_RATE=0.008-0.05` (packets/sec)
- **技术手段**: 使用nmap的`--min-rate`参数控制扫描速率
- **代码位置**: `scripts/attack/network_scan.py`第25行

**慢速SQLi实现**:
- **配置参数**: `SQL_DELAY=60-300` (seconds)
- **技术手段**: 使用SQLMap的`--delay`参数控制请求间隔
- **代码位置**: `scripts/attack/container_attack.py`第25行

### 问题2: 用了哪些container，每个container的功能是什么，如何实现的这些功能？

#### 容器架构分析

**1. Web应用容器 (securitylogs-webapp)**
- **Dockerfile**: `containers/webapp/Dockerfile`
- **功能**: 作为攻击目标，提供有漏洞的Web应用
- **实现方式**:
  ```dockerfile
  # 安装Web服务组件
  RUN apt-get install -y nginx php7.4-fpm php7.4-sqlite3
  
  # 复制有漏洞的Web应用
  COPY webapp/ /var/www/html/
  
  # 初始化SQLite数据库
  RUN sqlite3 /var/www/html/database.sqlite < /tmp/init_db.sql
  ```
- **漏洞实现**: 
  - **文件**: `containers/webapp/webapp/login.php`
  - **漏洞代码**: `$sql = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";`
  - **特点**: 直接拼接用户输入，存在SQL注入漏洞

**2. 攻击者容器 (securitylogs-attacker)**
- **Dockerfile**: `containers/attacker/Dockerfile`
- **功能**: 执行各种攻击工具和脚本
- **实现方式**:
  ```dockerfile
  # 安装Python环境
  RUN pip3 install requests colorama
  
  # 创建脚本目录
  RUN mkdir -p /opt/scripts /opt/output /opt/logs
  ```
- **攻击工具集成**:
  - SQLMap: 自动化SQL注入测试
  - Nmap: 网络扫描
  - 自定义Python脚本: 攻击逻辑实现

**3. 网络抓包容器 (securitylogs-tcpdump)**
- **Dockerfile**: `containers/tcpdump/Dockerfile`
- **功能**: 捕获网络流量，生成PCAP文件
- **实现方式**:
  ```dockerfile
  # 安装网络工具
  RUN apt-get install -y tcpdump iproute2
  
  # 复制抓包脚本
  COPY scripts/capture_traffic.sh /usr/local/bin/capture_traffic.sh
  ```
- **抓包配置**: 
  ```bash
  # 在docker-compose.yml中配置
  command: ["/bin/bash", "-c", "tcpdump -i any -w \"/pcaps/${SCENARIO_NAME}_${VARIANT_NAME}_${TIMESTAMP}.pcap\" -s 65535 -v"]
  ```

**4. 日志聚合容器 (securitylogs-log-aggregator)**
- **配置**: `scenarios/low-and-slow-sqli/docker-compose.yml`第75-90行
- **功能**: 收集和转发所有容器的日志
- **实现方式**:
  ```yaml
  log-aggregator:
    image: ubuntu:20.04
    volumes:
      - ../../control:/opt/control
    command: ["/bin/bash", "-c", "python3 /opt/control/multi_source_logger.py --continuous"]
  ```

#### 容器间协作机制

**网络配置**:
```yaml
networks:
  attacknet:
    driver: bridge
```

**依赖关系**:
- webapp → tcpdump (依赖)
- attacker → webapp (依赖)
- log-aggregator → 所有容器 (日志收集)

### 问题3: 为什么设计了这三种良性背景流量，如何实现的这些流量？

#### 设计原理

**为什么选择这三种流量**:
1. **HTTP流量**: 模拟正常用户访问Web应用的行为
2. **DNS查询**: 模拟网络中的DNS解析活动
3. **SMTP会话**: 模拟邮件传输，增加网络复杂性

#### 实现方式

**1. HTTP流量实现**
- **文件**: `scripts/attack/http_traffic.sh`
- **实现方式**:
  ```bash
  # 真实User-Agent列表
  USER_AGENTS=(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  )
  
  # 多样化端点
  ENDPOINTS=(
      "/" "/about" "/contact" "/products" "/services"
  )
  
  # 随机化请求
  local endpoint=$(get_random_endpoint)
  local user_agent=$(get_random_user_agent)
  ```

**2. DNS查询实现**
- **文件**: `scripts/attack/dns_traffic.sh`
- **实现方式**:
  ```bash
  # 真实域名列表
  DOMAINS=(
      "google.com" "facebook.com" "youtube.com" "amazon.com"
  )
  
  # 多种记录类型
  RECORD_TYPES=("A" "AAAA" "MX" "NS" "TXT" "CNAME")
  
  # 随机化查询
  local domain=${DOMAINS[$((RANDOM % ${#DOMAINS[@]}))]}
  local record_type=${RECORD_TYPES[$((RANDOM % ${#RECORD_TYPES[@]}))]}
  ```

**3. SMTP会话实现**
- **文件**: `scripts/attack/smtp_traffic.sh`
- **实现方式**:
  ```bash
  # 真实邮件域
  EMAIL_DOMAINS=(
      "gmail.com" "yahoo.com" "hotmail.com" "outlook.com"
  )
  
  # 多样化主题
  EMAIL_SUBJECTS=(
      "Meeting reminder" "Weekly report" "Project update"
  )
  
  # 协议模拟
  (
      echo "EHLO localhost"
      echo "MAIL FROM: <$from_email>"
      echo "RCPT TO: <$to_email>"
      echo "DATA"
      echo "Subject: $subject"
      echo "."
      echo "QUIT"
  ) | telnet $SMTP_SERVER $SMTP_PORT
  ```

#### 流量混合策略

**配置方式**: 通过YAML配置文件定义不同变体的协议混合比例
```yaml
variants:
  stealthy:
    protocol_mix: "HTTP:0.8,DNS:0.15,SMTP:0.05"
  moderate:
    protocol_mix: "HTTP:0.7,DNS:0.2,SMTP:0.1"
  aggressive:
    protocol_mix: "HTTP:0.6,DNS:0.25,SMTP:0.15"
```

**实现原理**: 
- **文件**: `scripts/attack/run_benign.sh`
- **解析逻辑**: 解析协议混合配置，按比例启动不同类型的流量生成器

### 问题4: 变体到底是三个还是五个，在哪里定义的？

#### 变体定义位置

**主要定义文件**:
1. `scenarios/low-and-slow-sqli/config/variants.yml` - 3个变体
2. `scripts/automation/variants.yml` - 3个变体

#### 变体数量分析

**3个变体定义** (在`scenarios/low-and-slow-sqli/config/variants.yml`):
```yaml
variants:
  stealthy:      # 隐秘型
    nmap_rate: 0.008
    sql_delay: 300
    sqlmap_risk: 1
    sqlmap_level: 1
    
  moderate:      # 中等型
    nmap_rate: 0.016
    sql_delay: 120
    sqlmap_risk: 1
    sqlmap_level: 2
    
  aggressive:    # 激进型
    nmap_rate: 0.05
    sql_delay: 60
    sqlmap_risk: 2
    sqlmap_level: 3
```

**3个变体定义** (在`scripts/automation/variants.yml`):
```yaml
variants:
  lowscan_stealthy:    # 隐秘型
    attack_params:
      nmap_rate: 0.008
      sql_delay: 300
      
  lowscan_moderate:    # 中等型
    attack_params:
      nmap_rate: 0.016
      sql_delay: 120
      
  lowscan_aggressive:  # 激进型
    attack_params:
      nmap_rate: 0.032
      sql_delay: 60
```

#### 变体使用情况

**实际运行的变体**: 3个 (stealthy, moderate, aggressive)
- **证据**: 在`data/logs/`目录下只有3个变体目录
- **原因**: 项目设计为3个核心变体，覆盖不同的攻击强度级别

**变体参数差异**:

| 变体 | Nmap速率 | SQL延迟 | SQLMap RISK | SQLMap LEVEL | 网络延迟 |
|------|----------|---------|-------------|--------------|----------|
| stealthy | 0.008 | 300s | 1 | 1 | 5ms |
| moderate | 0.016 | 120s | 1 | 2 | 50ms |
| aggressive | 0.05 | 60s | 2 | 3 | 200ms |

#### 变体隔离机制

**目录隔离**:
```
data/logs/
├── lowscan_stealthy/
├── lowscan_moderate/
└── lowscan_aggressive/
```

**网络隔离**:
```yaml
environment:
  ports:
    webapp: 8081  # stealthy
    webapp: 8083  # moderate  
    webapp: 8085  # aggressive
  network: "lowscan_stealthy_net"
  network: "lowscan_moderate_net"
  network: "lowscan_aggressive_net"
```

## 总结

### 技术架构特点
1. **模块化设计**: 每个攻击阶段独立实现，便于维护和扩展
2. **容器化隔离**: 确保不同变体的数据独立性和环境隔离
3. **真实工具集成**: 使用SQLMap、Nmap等真实安全工具
4. **配置驱动**: 通过YAML文件管理变体配置，支持灵活调整

### 创新点
1. **低扫描+慢速SQLi**: 通过参数化配置实现不同强度的攻击
2. **多协议背景流量**: 模拟真实网络环境，提高数据真实性
3. **变体隔离**: 确保不同攻击变体数据的独立性和可重现性
4. **统一数据格式**: 支持多源日志的统一分析和处理

这个项目成功实现了一个高质量的安全实验平台，为安全研究和机器学习提供了有价值的数据集。 