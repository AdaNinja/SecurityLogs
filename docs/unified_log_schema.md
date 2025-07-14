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
| details     | object   | 源日志原文或结构化内容        | {"msg": "Accepted password for root..."} |

## 说明
- 所有日志建议转为JSON Lines格式，每行为一条事件
- PCAP建议用Zeek/Suricata等工具转为JSON后合并
- details字段可嵌入原始日志内容或协议特有字段

## 示例
```jsonl
{"timestamp": "2025-07-14T09:10:00Z", "host": "webapp-01", "source_type": "syslog", "event_type": "login", "severity": "info", "process": "sshd", "user": "root", "is_attack": false, "details": {"msg": "Accepted password for root from 1.2.3.4 port 12345 ssh2"}}
{"timestamp": "2025-07-14T09:11:00Z", "host": "attacker", "source_type": "attack", "event_type": "sql_injection", "severity": "info", "process": "sqlmap", "user": "attacker", "is_attack": "Exploit", "details": {"payload": "' OR 1=1--"}}
```

## 后续建议
- 所有采集脚本输出均按此Schema落盘
- ETL脚本负责格式转换、字段补全、时区统一
- 标注脚本自动补充is_attack/attack_stage等标签 