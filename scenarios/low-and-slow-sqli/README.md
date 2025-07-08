# Low-and-Slow SQL Injection Attack Scenario

## Overview

This scenario implements "Low-and-Slow Web Scanning + Covert SQL Injection" attacks, strictly designed according to the four dimensions required by the paper:

- **Variation**: Multi-protocol mixing, adjustable rate variants, network perturbation combinations
- **Ground Truth**: Declarative configuration, single scenario identification
- **Modularity**: Container and script decoupling, pluggable script modules
- **Scalability**: Batch variant execution, parallelization, lightweight container startup

## Architecture Design

### Container Topology
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   webapp        │    │   attacker      │    │   tcpdump       │
│   (victim)      │    │   (kali tools)  │    │   (sidecar)     │
│                 │    │                 │    │                 │
│ - nginx + php   │    │ - sqlmap        │    │ - tcpdump       │
│ - mysql         │    │ - nmap          │    │ - wireshark     │
│ - ssh           │    │ - hydra         │    │                 │
│ - vulnerable    │    │ - metasploit    │    │                 │
│   web app       │    │ - python        │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Attack Chain
1. **Network Reconnaissance**: Use nmap for ultra-slow port scanning
2. **Web Enumeration**: Use dirb, nikto for directory and vulnerability scanning
3. **SQL Injection**: Use sqlmap for automated SQL injection testing
4. **Data Extraction**: Extract database information and sensitive data

### Benign Traffic Background
- **HTTP Traffic**: Simulate normal user website access
- **DNS Queries**: Simulate DNS resolution requests
- **SMTP Sessions**: Simulate email transmission activities

## Configuration

### Scenario Configuration (`config/scenario.env`)
```bash
# Scenario Identity
SCENARIO_NAME=low-and-slow-sqli
SCENARIO_VERSION=1.0.0

# Attack Parameters
DEFAULT_NMAP_RATE=0.016
DEFAULT_SQL_DELAY=120
DEFAULT_SQLMAP_THREADS=1

# Benign Traffic Configuration
DEFAULT_PROTOCOL_MIX=HTTP:0.7,DNS:0.2,SMTP:0.1
BENIGN_TOTAL_DURATION=2400

# Network Emulation Configuration
DEFAULT_NETEM_PROFILE=low_latency
```

### Variant Configuration (`config/variants.yml`)
```yaml
variants:
  stealthy:
    description: "Very slow and stealthy attack using official SQLMap RISK=1, LEVEL=1"
    nmap_rate: 0.008
    sql_delay: 300
    sqlmap_risk: 1      # SQLMap official RISK level (1-3)
    sqlmap_level: 1     # SQLMap official LEVEL (1-5)
    protocol_mix: "HTTP:0.8,DNS:0.15,SMTP:0.05"
    netem_profile: "low_latency"
    
  moderate:
    description: "Balanced attack using official SQLMap RISK=1, LEVEL=2"
    nmap_rate: 0.016
    sql_delay: 120
    sqlmap_risk: 1      # SQLMap official RISK level
    sqlmap_level: 2     # SQLMap official LEVEL
    protocol_mix: "HTTP:0.7,DNS:0.2,SMTP:0.1"
    netem_profile: "medium_latency"
    
  aggressive:
    description: "Faster attack using official SQLMap RISK=2, LEVEL=3"
    nmap_rate: 0.05
    sql_delay: 60
    sqlmap_risk: 2      # SQLMap official RISK level
    sqlmap_level: 3     # SQLMap official LEVEL
    protocol_mix: "HTTP:0.6,DNS:0.25,SMTP:0.15"
    netem_profile: "high_latency"
```

## Usage

### 1. Single Run
```bash
# Build containers
make build

# Start scenario
cd scenarios/low-and-slow-sqli
docker-compose up -d

# Apply network emulation
bash ../../control/apply_netem.sh --profile low_latency

# Run benign traffic
docker exec securitylogs-webapp bash /opt/scripts/run_benign.sh

# Run attack
docker exec securitylogs-attacker bash /opt/scripts/run_attack.sh

# View results
ls -la ../../pcap_data/low-and-slow-sqli/
ls -la ../../logs/low-and-slow-sqli/
ls -la ../../output/low-and-slow-sqli/
```

### 2. Batch Run All Variants
```bash
# Execute all variants sequentially
bash run_all_variants.sh

# Execute all variants in parallel
bash run_all_variants.sh --parallel

# Custom timeout
bash run_all_variants.sh --timeout 7200
```

### 3. Using Makefile
```bash
# Quick start SQL injection scenario
make sqli-quick

# View logs
make logs

# View status
make status
```

## Output Files

### PCAP Files
- `pcap_data/low-and-slow-sqli/traffic.pcap`: Complete network traffic
- `pcap_data/low-and-slow-sqli/webapp_traffic.pcap`: Web application traffic

### Log Files
- `logs/low-and-slow-sqli/webapp/`: Web application logs
- `logs/low-and-slow-sqli/attacker/`: Attacker logs
- `logs/low-and-slow-sqli/tcpdump/`: Packet capture logs

### Result Files
- `output/low-and-slow-sqli/network_scan_results.json`: Network scan results
- `output/low-and-slow-sqli/sql_injection_results.txt`: SQL injection results
- `output/low-and-slow-sqli/attack_summary.txt`: Attack summary

## Modular Design

### Benign Traffic Modules (`scripts/benign_modules/`)
- `http_traffic.sh`: HTTP traffic generation
- `dns_traffic.sh`: DNS query generation
- `smtp_traffic.sh`: SMTP session generation

### Attack Modules (`scripts/attack_modules/`)
- `network_recon.py`: Network reconnaissance
- `sql_injection.py`: SQL injection attacks
- `web_enumeration.py`: Web application enumeration

### Network Emulation Configurations (`control/netem_profiles/`)
- `low_latency.json`: Low latency configuration
- `medium_latency.json`: Medium latency configuration
- `high_latency.json`: High latency configuration

## Reproducibility

### Environment Consistency
- All container versions fixed
- Configuration files version controlled
- Random seeds fixed

### Experiment Identification
- Scenario name: `low-and-slow-sqli`
- Variant identifiers: `stealthy`, `moderate`, `aggressive`
- Timestamp recording

### Data Integrity
- Checksums enabled
- Timestamp recording
- Complete log preservation

## Scalability

### Adding New Variants
1. Add new variant configuration in `config/variants.yml` using official tool grades:
   ```yaml
   new_variant:
     description: "Custom variant using official SQLMap RISK=2, LEVEL=4"
     sqlmap_risk: 2      # SQLMap RISK (1-3)
     sqlmap_level: 4     # SQLMap LEVEL (1-5)
     nmap_timing: "T2"   # Nmap timing template (T0-T5)
   ```
2. Add network configuration in `control/netem_profiles/`
3. Run `run_all_variants.sh` to automatically include new variants

### Adding New Protocols
1. Add new protocol script in `scripts/benign_modules/`
2. Add protocol handling logic in `run_benign.sh`
3. Update protocol mix configuration in `config/scenario.env`

### Adding New Attack Modules
1. Add new attack script in `scripts/attack_modules/`
2. Add module call in `run_attack.sh`
3. Update attack parameter configuration

## Troubleshooting

### Common Issues
1. **Container startup failure**: Check Docker and port occupancy
2. **Network emulation failure**: Check tc command and container permissions
3. **Attack script failure**: Check target container health status
4. **Traffic capture failure**: Check tcpdump permissions and disk space

### Debugging Methods
```bash
# View container logs
docker-compose logs -f

# Enter container for debugging
docker exec -it securitylogs-attacker bash

# Check network configuration
docker network ls
docker network inspect securitylogs_attacknet
```

## Performance Optimization

### Resource Usage
- Container memory limit: 512MB-1GB
- CPU limit: 0.5-1.0 cores
- Disk space: At least 10GB available space

### Parallel Optimization
- Use `--parallel` parameter for parallel variant execution
- Adjust container count to avoid resource competition
- Monitor system resource usage

## Security Considerations

⚠️ **Warning**: This scenario is for security research and educational purposes only

- All attacks are conducted in isolated Docker environments
- No real malicious code or data is included
- Do not use in production environments
- Comply with local laws and regulations 