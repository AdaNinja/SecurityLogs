# Unified Log Schema for SecurityLogs Dataset

## 设计目标
- 支持多源日志（主机、容器、应用、攻防、网络）统一检索、分析与可视化
- 便于后续自动化标注、事件溯源、模型训练

## 推荐字段
| 字段名      | 类型     | 说明                         | 示例 |
|-------------|----------|------------------------------|------|
| timestamp   | string   | 事件时间（ISO-8601 UTC）     | 2025-07-14T09:10:00Z |
| host        | string   | 主机名/容器名                | webapp-01 |
| source_type | string   | 日志来源类型（syslog/nginx/attack/pkt等） | syslog |
| event_type  | string   | 事件类型（login/attack/conn等） | login |
| severity    | string   | 日志级别（info/warn/error等） | info |
| process     | string   | 进程名/服务名                | sshd |
| user        | string   | 用户名/UID                   | root |
| is_attack   | bool/enum| 是否为攻击流量/事件          | true/false/Recon/Exploit |
| network_quintuple | object | 网络五元组信息              | 见下方详细说明 |
| mitre_attack | object  | MITRE ATT&CK映射信息         | 见下方详细说明 |
| details     | object   | 源日志原文或结构化内容        | {"msg": "Accepted password for root..."} |

## 网络五元组字段 (network_quintuple)
| 字段名      | 类型     | 说明                         | 示例 |
|-------------|----------|------------------------------|------|
| src_ip      | string   | 源IP地址                     | "192.168.1.100" |
| src_port    | int      | 源端口                       | 12345 |
| dst_ip      | string   | 目标IP地址                   | "192.168.1.200" |
| dst_port    | int      | 目标端口                     | 80 |
| protocol    | string   | 协议类型                     | "TCP" |
| connection_id | string | 连接标识符                   | "tcp_192.168.1.100_12345_192.168.1.200_80" |
| connection_state | string | 连接状态                   | "ESTABLISHED" |
| session_duration | float | 会话持续时间(秒)            | 120.5 |

## MITRE ATT&CK字段 (mitre_attack)
| 字段名      | 类型     | 说明                         | 示例 |
|-------------|----------|------------------------------|------|
| tactic      | string   | 攻击战术                     | "Initial Access" |
| technique   | string   | 攻击技术ID                   | "T1190" |
| technique_name | string | 攻击技术名称                 | "Exploit Public-Facing Application" |
| sub_technique | string | 子技术ID                     | "T1190.001" |
| sub_technique_name | string | 子技术名称               | "SQL Injection" |
| confidence  | string   | 置信度                       | "high" |
| attack_chain | array   | 攻击链技术序列               | ["T1595.002", "T1190.001", "T1005"] |

## 说明
- 所有日志建议转为JSON Lines格式，每行为一条事件
- PCAP建议用Zeek/Suricata等工具转为JSON后合并
- details字段可嵌入原始日志内容或协议特有字段
- network_quintuple字段仅在网络相关事件中填充
- mitre_attack字段仅在攻击事件中填充

## 示例
```jsonl
{"timestamp": "2025-07-14T09:10:00Z", "host": "webapp-01", "source_type": "syslog", "event_type": "login", "severity": "info", "process": "sshd", "user": "root", "is_attack": false, "network_quintuple": {"src_ip": "192.168.1.100", "src_port": 12345, "dst_ip": "192.168.1.200", "dst_port": 22, "protocol": "TCP", "connection_id": "tcp_192.168.1.100_12345_192.168.1.200_22", "connection_state": "ESTABLISHED", "session_duration": 30.5}, "details": {"msg": "Accepted password for root from 1.2.3.4 port 12345 ssh2"}}
{"timestamp": "2025-07-14T09:11:00Z", "host": "attacker", "source_type": "attack", "event_type": "sql_injection", "severity": "info", "process": "sqlmap", "user": "attacker", "is_attack": "Exploit", "network_quintuple": {"src_ip": "192.168.1.50", "src_port": 54321, "dst_ip": "192.168.1.200", "dst_port": 80, "protocol": "TCP", "connection_id": "tcp_192.168.1.50_54321_192.168.1.200_80", "connection_state": "ESTABLISHED", "session_duration": 45.2}, "mitre_attack": {"tactic": "Initial Access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "sub_technique": "T1190.001", "sub_technique_name": "SQL Injection", "confidence": "high", "attack_chain": ["T1595.002", "T1190.001"]}, "details": {"payload": "' OR 1=1--"}}
```

## 后续建议
- 所有采集脚本输出均按此Schema落盘
- ETL脚本负责格式转换、字段补全、时区统一
- 标注脚本自动补充is_attack/attack_stage等标签
- 网络分析脚本自动提取五元组信息
- MITRE映射脚本自动识别和标注攻击技术 