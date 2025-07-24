# Unified Log Schema for SecurityLogs Dataset

## Design Goals
- Support unified retrieval, analysis, and visualization of multi-source logs (host, container, application, attack/defense, network)
- Facilitate subsequent automated labeling, event tracing, and model training

## Recommended Fields
| Field Name  | Type     | Description                    | Example |
|-------------|----------|--------------------------------|---------|
| timestamp   | string   | Event time (ISO-8601 UTC)      | 2025-07-14T09:10:00Z |
| host        | string   | Hostname/container name        | webapp-01 |
| source_type | string   | Log source type (syslog/nginx/attack/pkt etc.) | syslog |
| event_type  | string   | Event type (login/attack/conn etc.) | login |
| severity    | string   | Log level (info/warn/error etc.) | info |
| process     | string   | Process name/service name      | sshd |
| user        | string   | Username/UID                   | root |
| is_attack   | bool/enum| Whether it's attack traffic/event | true/false/Recon/Exploit |
| network_quintuple | object | Network quintuple information | See detailed description below |
| mitre_attack | object  | MITRE ATT&CK mapping information | See detailed description below |
| details     | object   | Original log content or structured content | {"msg": "Accepted password for root..."} |

## Network Quintuple Fields (network_quintuple)
| Field Name  | Type     | Description                    | Example |
|-------------|----------|--------------------------------|---------|
| src_ip      | string   | Source IP address              | "192.168.1.100" |
| src_port    | int      | Source port                    | 12345 |
| dst_ip      | string   | Destination IP address         | "192.168.1.200" |
| dst_port    | int      | Destination port               | 80 |
| protocol    | string   | Protocol type                  | "TCP" |
| connection_id | string | Connection identifier          | "tcp_192.168.1.100_12345_192.168.1.200_80" |
| connection_state | string | Connection state             | "ESTABLISHED" |
| session_duration | float | Session duration (seconds)   | 120.5 |

## MITRE ATT&CK Fields (mitre_attack)
| Field Name  | Type     | Description                    | Example |
|-------------|----------|--------------------------------|---------|
| tactic      | string   | Attack tactic                  | "Initial Access" |
| technique   | string   | Attack technique ID            | "T1190" |
| technique_name | string | Attack technique name        | "Exploit Public-Facing Application" |
| sub_technique | string | Sub-technique ID             | "T1190.001" |
| sub_technique_name | string | Sub-technique name         | "SQL Injection" |
| confidence  | string   | Confidence level               | "high" |
| attack_chain | array   | Attack chain technique sequence | ["T1595.002", "T1190.001", "T1005"] |

## Notes
- All logs should be converted to JSON Lines format, with one event per line
- PCAP files should be converted to JSON using tools like Zeek/Suricata and then merged
- The details field can embed original log content or protocol-specific fields
- The network_quintuple field is only filled for network-related events
- The mitre_attack field is only filled for attack events

## Examples
```jsonl
{"timestamp": "2025-07-14T09:10:00Z", "host": "webapp-01", "source_type": "syslog", "event_type": "login", "severity": "info", "process": "sshd", "user": "root", "is_attack": false, "network_quintuple": {"src_ip": "192.168.1.100", "src_port": 12345, "dst_ip": "192.168.1.200", "dst_port": 22, "protocol": "TCP", "connection_id": "tcp_192.168.1.100_12345_192.168.1.200_22", "connection_state": "ESTABLISHED", "session_duration": 30.5}, "details": {"msg": "Accepted password for root from 1.2.3.4 port 12345 ssh2"}}
{"timestamp": "2025-07-14T09:11:00Z", "host": "attacker", "source_type": "attack", "event_type": "sql_injection", "severity": "info", "process": "sqlmap", "user": "attacker", "is_attack": "Exploit", "network_quintuple": {"src_ip": "192.168.1.50", "src_port": 54321, "dst_ip": "192.168.1.200", "dst_port": 80, "protocol": "TCP", "connection_id": "tcp_192.168.1.50_54321_192.168.1.200_80", "connection_state": "ESTABLISHED", "session_duration": 45.2}, "mitre_attack": {"tactic": "Initial Access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application", "sub_technique": "T1190.001", "sub_technique_name": "SQL Injection", "confidence": "high", "attack_chain": ["T1595.002", "T1190.001"]}, "details": {"payload": "' OR 1=1--"}}
```

## Implementation Recommendations
- All collection scripts should output according to this schema
- ETL scripts are responsible for format conversion, field completion, and timezone unification
- Labeling scripts automatically supplement is_attack/attack_stage and other labels
- Network analysis scripts automatically extract quintuple information
- MITRE mapping scripts automatically identify and label attack techniques
