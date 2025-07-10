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

## Quick Start

### 1. Basic Usage with Makefile

```bash
# View all available commands
make help

# Quick start - build, start containers, and run basic attack
make sqli-quick

# Check container status
make status

# View container logs
make logs
```

### 2. Individual Attack Variants

```bash
# Run stealthy attack (RISK=1, LEVEL=1)
make attack-stealthy

# Run moderate attack (RISK=1, LEVEL=2)
make attack-moderate

# Run aggressive attack (RISK=2, LEVEL=3)
make attack-aggressive
```

### 3. Complete Workflow

```bash
# Run all variants sequentially
make run-all-variants

# Complete workflow with data collection and analysis
make all
```

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

## Container Architecture

### Container Roles

- **securitylogs-webapp**: Vulnerable web application (target)
- **securitylogs-attacker**: Attack execution container
- **securitylogs-tcpdump**: Network traffic capture
- **securitylogs-log-aggregator**: Log collection and analysis

### Container Status Check

```bash
# Check all container status
make status

# Expected output:
# NAMES                         STATUS                   PORTS
# securitylogs-attacker         Up X minutes             
# securitylogs-webapp           Up X minutes (healthy)   22/tcp, 0.0.0.0:8080->80/tcp
# securitylogs-tcpdump          Up X minutes             
# securitylogs-log-aggregator   Up X minutes
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
bash ../../control/network/apply_netem.sh --profile low_latency

# Run benign traffic
docker exec securitylogs-webapp bash /opt/scripts/run_benign.sh

# Run attack
docker exec securitylogs-attacker bash /opt/scripts/run_attack.sh

# View results
ls -la ../../data/pcap/low-and-slow-sqli/
ls -la ../../data/logs/low-and-slow-sqli/
ls -la ../../data/output/low-and-slow-sqli/
```

### 2. Batch Run All Variants
```bash
# Execute all variants sequentially
bash ../../control/automation/run_all_variants.sh

# Execute all variants in parallel
bash ../../control/automation/run_all_variants.sh --parallel

# Custom timeout
bash ../../control/automation/run_all_variants.sh --timeout 7200
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
- `data/pcap/low-and-slow-sqli/traffic.pcap`: Complete network traffic
- `data/pcap/low-and-slow-sqli/webapp_traffic.pcap`: Web application traffic

### Log Files
- `data/logs/low-and-slow-sqli/webapp/`: Web application logs
- `data/logs/low-and-slow-sqli/attacker/`: Attacker logs
- `data/logs/low-and-slow-sqli/tcpdump/`: Packet capture logs

### Result Files
- `data/output/low-and-slow-sqli/network_scan_results.json`: Network scan results
- `data/output/low-and-slow-sqli/sql_injection_results.txt`: SQL injection results
- `data/output/low-and-slow-sqli/attack_summary.txt`: Attack summary

## Modular Design

### Benign Traffic Modules (`scripts/benign_modules/`)
- `http_traffic.sh`: HTTP traffic generation
- `dns_traffic.sh`: DNS query generation
- `smtp_traffic.sh`: SMTP session generation

### Attack Modules (`scripts/attack_modules/`)
- `network_recon.py`: Network reconnaissance
- `sql_injection.py`: SQL injection attacks
- `web_enumeration.py`: Web application enumeration

### Network Emulation Configurations (`control/network/netem_profiles/`)
- `low_latency.json`: Low latency configuration
- `medium_latency.json`: Medium latency configuration
- `high_latency.json`: High latency configuration

## Automation Scripts

### 1. Makefile Commands

```bash
# Container Management
make build          # Build all containers
make start          # Start all containers
make stop           # Stop all containers
make clean          # Stop and remove all containers

# Attack Execution
make attack         # Run basic SQL injection attack
make attack-stealthy    # Run stealthy variant
make attack-moderate    # Run moderate variant
make attack-aggressive  # Run aggressive variant

# Data Collection
make collect-logs   # Collect all logs and PCAP files
make analyze        # Analyze collected data
make report         # Generate analysis report

# Utility Commands
make sqli-quick     # Quick start scenario
make logs           # View container logs
make status         # Check container status
make all            # Complete workflow
```

### 2. Automated Variants Runner

```bash
# Run all attack variants with data collection
bash ../../control/automation/run_all_variants.sh

# The script will:
# 1. Check container status
# 2. Wait for webapp to be ready
# 3. Run all three variants sequentially
# 4. Collect logs and PCAP files
# 5. Generate summary report
```

## Log Aggregator Container

The `securitylogs-log-aggregator` container provides:

- **Continuous log collection** from all containers
- **Multi-source data aggregation** using `multi_source_logger.py`
- **Automatic log retention** management
- **Real-time analysis** capabilities

### Log Aggregator Features

- Collects container logs every 60 seconds
- Maintains 7-day log retention
- Provides continuous monitoring
- Generates analysis reports

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
2. Add network configuration in `control/network/netem_profiles/`
3. Run `control/automation/run_all_variants.sh` to automatically include new variants

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

1. **Container Startup Issues**
   ```bash
   # Check container logs
   make logs
   
   # Restart containers
   make stop && make start
   ```

2. **Webapp Not Responding**
   ```bash
   # Check webapp health
   curl -f http://localhost:8080/
   
   # Check webapp logs
   docker logs securitylogs-webapp
   ```

3. **Attack Script Failures**
   ```bash
   # Check attacker container
   docker exec -it securitylogs-attacker bash
   
   # Test connectivity
   python3 -c "import requests; print(requests.get('http://victim-web:80').status_code)"
   ```

4. **PCAP Capture Issues**
   ```bash
   # Check tcpdump container
   docker logs securitylogs-tcpdump
   
   # Verify PCAP files
   ls -lh ../../data/pcap/
   ```

### Debug Commands

```bash
# Enter containers for debugging
docker exec -it securitylogs-webapp bash
docker exec -it securitylogs-attacker bash
docker exec -it securitylogs-tcpdump bash

# Check network connectivity
docker network inspect low-and-slow-sqli_attacknet

# View real-time logs
docker-compose logs -f
```

## Performance Optimization

### Resource Requirements

- **Memory**: Minimum 4GB RAM
- **CPU**: 2+ cores recommended
- **Disk**: 10GB+ free space
- **Network**: Stable internet connection

### Optimization Tips

1. **Container Resource Limits**
   - Monitor resource usage: `docker stats`
   - Adjust limits in `docker-compose.yml` if needed

2. **Parallel Execution**
   - Use `--parallel` flag for faster execution
   - Monitor system resources during parallel runs

3. **Data Management**
   - Regular cleanup of old logs and PCAP files
   - Compress large PCAP files for storage

## Security Considerations

⚠️ **Important**: This scenario is for security research and educational purposes only.

### Safety Measures

- All attacks run in isolated Docker environments
- No real malicious code or data included
- Do not use in production environments
- Comply with local laws and regulations 

### Best Practices

1. **Isolation**: Always run in isolated environments
2. **Monitoring**: Monitor resource usage during attacks
3. **Cleanup**: Clean up data after experiments
4. **Documentation**: Document all experiments and findings

## Advanced Usage

### Custom Attack Variants

1. **Add new variant** in `config/variants.yml`:
   ```yaml
   custom_variant:
     description: "Custom attack variant"
     nmap_rate: 0.02
     sql_delay: 150
     sqlmap_risk: 1
     sqlmap_level: 2
     protocol_mix: "HTTP:0.7,DNS:0.2,SMTP:0.1"
     netem_profile: "custom_profile"
   ```

2. **Add corresponding Makefile target**:
   ```makefile
   attack-custom:
       @echo "Running custom attack variant..."
       @mkdir -p ../../data/output/variants/custom
       @docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py --variant custom --output ../../data/output/variants/custom/
   ```

### Integration with External Tools

The scenario can be integrated with:
- SIEM systems for log analysis
- Network monitoring tools
- Security testing frameworks
- Academic research platforms

## Support and Documentation

### Additional Resources

- `config/`: Configuration files and examples
- `scripts/`: Attack and benign traffic modules
- `../../control/`: Control and analysis scripts

### Getting Help

1. Check container logs: `make logs`
2. Verify configuration: Review `config/` files
3. Test connectivity: Use provided debug commands
4. Review documentation: Read this README for details

## Version Information

- **Scenario Version**: 1.0.0
- **Last Updated**: July 2025
- **Compatibility**: Docker 20.10+, Docker Compose 2.0+
- **Tested Platforms**: Ubuntu 20.04+, CentOS 8+ 