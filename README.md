# 安全日志数据集 - 钓鱼攻击场景

这是一个用于生成安全日志数据集的钓鱼邮件攻击场景，实现了完整的攻击链：Reconnaissance → Delivery → Exploitation。

## 项目结构

```
.
├── docker/
│   ├── docker-compose.yml          # Docker编排文件
│   ├── victim1/                    # 受害者1容器（客户端）
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh
│   │   └── raw/                    # 日志存储目录
│   └── victim2/                    # 受害者2容器（服务器）
│       ├── Dockerfile
│       ├── entrypoint.sh
│       ├── credential_collector.py # 凭证收集服务器
│       └── raw/                    # 日志存储目录
├── scenarios/
│   └── phishing/                   # 钓鱼攻击场景
│       ├── scenario.yaml           # 场景配置
│       ├── benign.py               # 良性行为脚本
│       ├── attack.py               # 攻击脚本
│       └── labels.py               # 标签函数
├── logger_utils.py                 # 日志工具
├── run_scenario.py                 # 场景调度器
├── start_attack.py                 # 一键启动脚本
└── requirements.txt                # Python依赖
```

## 攻击场景说明

### 钓鱼邮件攻击链

1. **Reconnaissance（侦察）阶段**
   - 模拟正常的网络浏览行为
   - 访问良性网站（example.com, httpbin.org等）
   - 生成正常的网络流量日志

2. **Delivery（投递）阶段**
   - 发送钓鱼邮件到目标邮箱
   - 模拟邮件打开行为
   - 使用浏览器自动化点击钓鱼链接

3. **Exploitation（利用）阶段**
   - 访问钓鱼页面
   - 填写并提交登录表单
   - 窃取用户凭证
   - 将凭证发送到C2服务器

## 快速开始

### 方法1：一键启动（推荐）

```bash
# 安装Python依赖
pip3 install -r requirements.txt

# 一键启动攻击场景
python3 start_attack.py
```

### 方法2：手动步骤

```bash
# 1. 安装依赖
pip3 install -r requirements.txt

# 2. 构建并启动容器
cd docker
docker-compose up -d

# 3. 等待服务就绪（约30秒）
sleep 30

# 4. 运行攻击场景
cd ..
python3 run_scenario.py --config scenarios/phishing/scenario.yaml
```

## 验证结果

### 1. 查看MailHog邮件界面
访问 http://localhost:8025 查看发送的钓鱼邮件

### 2. 查看收集的凭证
访问 http://localhost:9000/credentials 查看窃取的凭证

### 3. 查看容器日志
```bash
# 查看victim1日志
docker logs docker_victim1_1

# 查看victim2日志
docker logs docker_victim2_1
```

### 4. 查看网络流量
```bash
# 查看victim1的pcap文件
ls docker/victim1/raw/

# 查看victim2的pcap文件
ls docker/victim2/raw/
```

## 重复演练

### 清理环境
```bash
# 停止并删除容器
docker-compose -f docker/docker-compose.yml down

# 清理日志文件
sudo truncate -s0 /var/log/audit/audit.log
sudo truncate -s0 /var/log/syslog
```

### 重新演练
```bash
# 重新启动
python3 start_attack.py
```

## 日志分析

### 系统日志标签
攻击过程中会在系统日志中注入以下标签：
- `phase=Reconnaissance` - 侦察阶段
- `phase=Delivery` - 投递阶段  
- `phase=Exploitation` - 利用阶段
- `attack_event=*` - 各种攻击事件

### 网络流量
- victim1容器：捕获所有网络流量
- victim2容器：捕获服务器端流量
- 包含HTTP请求、凭证提交等

### 审计日志
- Python进程执行记录
- 系统调用审计
- 文件访问记录

## 自定义配置

### 修改攻击参数
编辑 `scenarios/phishing/scenario.yaml`：
```yaml
parameters:
  attack_delay_s: 30          # 攻击延迟
  benign_sites:               # 良性网站列表
    - "http://example.com"
  phishing_email:             # 钓鱼邮件配置
    subject: "重要通知"
```

### 添加新的攻击场景
1. 在 `scenarios/` 下创建新目录
2. 实现 `benign.py`、`attack.py`、`labels.py`
3. 创建 `scenario.yaml` 配置文件
4. 运行：`python3 run_scenario.py --config scenarios/新场景/scenario.yaml`

## 故障排除

### 常见问题

1. **容器启动失败**
   ```bash
   # 检查Docker服务
   sudo systemctl status docker
   
   # 清理Docker缓存
   docker system prune -a
   ```

2. **浏览器自动化失败**
   ```bash
   # 检查Firefox和geckodriver
   docker exec docker_victim1_1 which firefox
   docker exec docker_victim1_1 which geckodriver
   ```

3. **网络连接问题**
   ```bash
   # 检查容器网络
   docker network ls
   docker network inspect docker_phishnet
   ```

## 安全注意事项

⚠️ **重要提醒**：
- 此项目仅用于安全研究和教育目的
- 请在隔离的测试环境中运行
- 不要在生产环境或真实网络中使用
- 遵守当地法律法规

## 技术栈

- **容器化**: Docker + Docker Compose
- **邮件服务器**: MailHog
- **浏览器自动化**: Selenium + Firefox
- **Web框架**: Flask
- **日志工具**: rsyslog + auditd
- **网络抓包**: tcpdump
- **编程语言**: Python 3

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。
