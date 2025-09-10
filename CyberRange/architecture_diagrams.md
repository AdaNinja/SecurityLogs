# CyberRange 架构图

## 图1：网络通信架构（修正版）

```mermaid
flowchart LR
  subgraph ext["external-net（外部网络）<br/>172.28.0.0/16"]
    n1["nginx<br/>反向代理"]
    a1["attacker_1<br/>SQL注入"]
    a2["attacker_2<br/>XSS攻击"]
    a3["attacker_3<br/>命令注入"]
    u1["benign_user_1<br/>浏览器用户"]
    u2["benign_user_2<br/>购物用户"]
    u3["benign_user_3<br/>搜索用户"]
  end
  
  subgraph int["internal-net（内部网络）<br/>172.27.0.0/16"]
    js["juice-shop<br/>目标应用<br/>:3000"]
    n1
  end
  
  subgraph host["宿主机监控<br/>（非容器内）"]
    tcp["tcpdump<br/>网络流量捕获<br/>（宿主机侧抓包）"]
    log["日志收集器<br/>LogCollector<br/>（宿主机侧）"]
  end

  client["外部客户端"] -- "80/443" --> n1
  n1 -- "HTTP代理" --> js
  
  a1 -- "攻击流量" --> n1
  a2 -- "攻击流量" --> n1
  a3 -- "攻击流量" --> n1
  
  u1 -- "正常流量" --> n1
  u2 -- "正常流量" --> n1
  u3 -- "正常流量" --> n1

  %% 监控侧：从宿主机采集
  n1 -- "访问日志" --> log
  js -- "应用日志" --> log
  ext -- "网络流量" --> tcp
  int -- "网络流量" --> tcp
```

## 图2：容器化部署架构（修正版）

```mermaid
flowchart TB
  subgraph host["Linux 宿主机"]
    os["Ubuntu 22.04"]
    docker["Docker Engine"]
    orch["CyberRange<br/>编排器"]
  end

  subgraph containers["Docker 容器"]
    nginx["nginx:alpine<br/>反向代理"]
    juice["bkimminich/juice-shop<br/>目标应用"]
    attacker1["ras-attacker:latest<br/>攻击者1"]
    attacker2["ras-attacker:latest<br/>攻击者2"]
    attacker3["ras-attacker:latest<br/>攻击者3"]
    user1["python:3.9-slim<br/>用户1"]
    user2["python:3.9-slim<br/>用户2"]
    user3["python:3.9-slim<br/>用户3"]
  end

  subgraph networks["Docker 网络"]
    ext_net["external-net<br/>外部网络<br/>172.28.0.0/16"]
    int_net["internal-net<br/>内部网络<br/>172.27.0.0/16"]
  end

  subgraph volumes["数据卷"]
    nginx_logs["nginx日志"]
    attack_logs["攻击日志"]
    user_logs["用户日志"]
    shared_data["共享数据"]
  end

  subgraph monitoring["监控系统<br/>（宿主机侧）"]
    tcpdump["tcpdump<br/>（宿主机侧抓包）"]
    log_collector["LogCollector<br/>（宿主机侧）"]
    parsers["日志解析器<br/>（宿主机侧）"]
  end

  os --> docker --> orch
  orch --> nginx
  orch --> juice
  orch --> attacker1
  orch --> attacker2
  orch --> attacker3
  orch --> user1
  orch --> user2
  orch --> user3

  nginx --- ext_net
  nginx --- int_net
  juice --- int_net
  attacker1 --- ext_net
  attacker2 --- ext_net
  attacker3 --- ext_net
  user1 --- ext_net
  user2 --- ext_net
  user3 --- ext_net

  nginx --- nginx_logs
  attacker1 --- attack_logs
  attacker2 --- attack_logs
  attacker3 --- attack_logs
  user1 --- user_logs
  user2 --- user_logs
  user3 --- user_logs

  nginx_logs --> log_collector
  attack_logs --> log_collector
  user_logs --> log_collector
  ext_net --> tcpdump
  int_net --> tcpdump
  log_collector --> parsers
  tcpdump --> parsers
```

## 图3：数据流和处理管道

```mermaid
flowchart TD
  subgraph collection["数据收集层"]
    nginx_logs["Nginx访问日志"]
    app_logs["应用日志"]
    attack_logs["攻击脚本日志"]
    user_logs["用户行为日志"]
    network_pcap["网络流量<br/>PCAP文件"]
  end

  subgraph processing["数据处理层"]
    nginx_parser["Nginx解析器"]
    attack_parser["攻击解析器"]
    user_parser["用户解析器"]
    network_parser["网络解析器"]
  end

  subgraph labeling["标签生成层"]
    ground_truth["真实标签提取"]
    mitre_mapping["MITRE ATT&CK映射"]
    ip_attribution["IP归属分析"]
  end

  subgraph output["输出层"]
    csv_files["CSV文件"]
    json_files["JSON文件"]
    pcap_files["PCAP文件"]
    metadata["实验元数据"]
  end

  nginx_logs --> nginx_parser
  app_logs --> nginx_parser
  attack_logs --> attack_parser
  user_logs --> user_parser
  network_pcap --> network_parser

  nginx_parser --> ground_truth
  attack_parser --> ground_truth
  user_parser --> ground_truth
  network_parser --> ground_truth

  ground_truth --> mitre_mapping
  ground_truth --> ip_attribution

  mitre_mapping --> csv_files
  ip_attribution --> csv_files
  ground_truth --> json_files
  network_pcap --> pcap_files
  ground_truth --> metadata
```

## 使用建议

### 对于Chapter 4，建议使用：

1. **图1（网络通信架构）** - 展示攻击流和正常流的网络路径
2. **图2（容器化部署架构）** - 展示完整的系统架构和组件关系
3. **图3（数据流和处理管道）** - 展示数据处理和标签生成的完整流程

### 每个图的用途：

- **图1**：解释网络隔离和流量路由
- **图2**：解释容器编排和资源管理
- **图3**：解释数据收集和处理流程

这样的三个图能够完整地展示CyberRange系统的技术架构，适合放在Chapter 4中。
