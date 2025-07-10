# Usage Guide

This document provides comprehensive usage instructions for the SecurityLogs project.

## Quick Start

### Basic Workflow
```bash
# 1. Build containers
make build

# 2. Start scenario
make sqli-quick

# 3. Check status
make status

# 4. View logs
make logs
```

### Advanced Workflow
```bash
# 1. Build and start
make build && make up

# 2. Apply network conditions
make apply-netem

# 3. Run interleaved attack
make interleaved

# 4. Collect and analyze data
make collect-logs && make analyze
```

## Attack Variants

### Available Variants
The project supports three attack variants with different intensity levels:

1. **Stealthy** (RISK=1, LEVEL=1)
   - Very slow and covert attack
   - Nmap rate: 0.008
   - SQL delay: 300 seconds
   - Protocol mix: HTTP:0.8, DNS:0.15, SMTP:0.05

2. **Moderate** (RISK=1, LEVEL=2)
   - Balanced attack approach
   - Nmap rate: 0.016
   - SQL delay: 120 seconds
   - Protocol mix: HTTP:0.7, DNS:0.2, SMTP:0.1

3. **Aggressive** (RISK=2, LEVEL=3)
   - Faster but still slow attack
   - Nmap rate: 0.05
   - SQL delay: 60 seconds
   - Protocol mix: HTTP:0.6, DNS:0.25, SMTP:0.15

### Running Variants
```bash
# Run specific variant
make attack-stealthy
make attack-moderate
make attack-aggressive

# Run all variants sequentially
make interleaved

# Run with custom parameters
make interleaved ARGS='--attack-variants stealthy,aggressive'
```

## Container Management

### Container Status
```bash
# Check all containers
make status

# Expected output:
# NAMES                         STATUS                   PORTS
# securitylogs-attacker         Up X minutes             
# securitylogs-webapp           Up X minutes (healthy)   22/tcp, 0.0.0.0:8080->80/tcp
# securitylogs-tcpdump          Up X minutes             
# securitylogs-log-aggregator   Up X minutes
```

### Container Operations
```bash
# Start containers
make up

# Stop containers
make down

# Restart containers
make down && make up

# Clean up everything
make clean
```

### Container Access
```bash
# Enter containers for debugging
docker exec -it securitylogs-webapp bash
docker exec -it securitylogs-attacker bash
docker exec -it securitylogs-tcpdump bash
```

## Network Emulation

### Applying Network Conditions
```bash
# Apply default network conditions
make apply-netem

# Apply specific profile
bash control/network/apply_netem.sh --profile low_latency

# Apply custom conditions
bash control/network/apply_netem.sh --latency 50 --loss 2
```

### Available Profiles
- **low_latency**: Minimal latency (5ms)
- **medium_latency**: Moderate latency (50ms)
- **high_latency**: High latency (200ms)

### Resetting Network
```bash
# Reset to normal conditions
make reset-netem

# Or directly
bash control/network/reset_netem.sh
```

## Data Collection

### Output Structure
```
data/
├── logs/           # Application and container logs
├── pcap/           # Network traffic captures
└── output/         # Analysis results and reports
    └── variants/   # Per-variant attack results
```

### Collected Data Types

1. **Container Logs**
   - Webapp application logs
   - Attacker execution logs
   - Tcpdump capture logs
   - Log aggregator analysis

2. **Network Traffic**
   - Complete network traffic (traffic.pcap)
   - Web application traffic (webapp_traffic.pcap)

3. **Attack Results**
   - SQL injection attempt logs
   - Vulnerability detection results
   - Attack timing and success rates

### Data Collection Commands
```bash
# Collect all logs and PCAP files
make collect-logs

# Analyze collected data
make analyze

# Generate analysis report
make report

# Complete data workflow
make all
```

## Automation Scripts

### Control Center Scripts
```bash
# Run all variants with data collection
bash control/automation/run_all_variants.sh

# Complete capture workflow
bash control/automation/capture.sh

# Multi-source log analysis
python3 control/automation/multi_source_logger.py
```

### Script Parameters
```bash
# Run variants in parallel
bash control/automation/run_all_variants.sh --parallel

# Custom timeout
bash control/automation/run_all_variants.sh --timeout 7200

# Specific variants
bash control/automation/run_all_variants.sh --variants stealthy,aggressive
```

## Configuration

### Scenario Configuration
Main configuration file: `scenarios/low-and-slow-sqli/config/scenario.env`

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
```

### Variant Configuration
Variant definitions: `scenarios/low-and-slow-sqli/config/variants.yml`

```yaml
variants:
  stealthy:
    description: "Very slow and stealthy attack"
    nmap_rate: 0.008
    sql_delay: 300
    sqlmap_risk: 1
    sqlmap_level: 1
    protocol_mix: "HTTP:0.8,DNS:0.15,SMTP:0.05"
    netem_profile: "low_latency"
```

### Docker Compose Configuration
Container orchestration: `scenarios/low-and-slow-sqli/docker-compose.yml`

```yaml
services:
  webapp:
    build: ../../containers/webapp
    ports:
      - "8080:80"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Monitoring and Debugging

### Real-time Monitoring
```bash
# View container logs
make logs

# Monitor specific container
docker logs -f securitylogs-webapp

# Monitor resource usage
docker stats

# Monitor network traffic
docker exec securitylogs-tcpdump tcpdump -i any -w -
```

### Debugging Commands
```bash
# Check container health
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check network connectivity
docker network inspect low-and-slow-sqli_attacknet

# Test webapp accessibility
curl -f http://localhost:8080/

# Check attack script connectivity
docker exec securitylogs-attacker python3 -c "import requests; print(requests.get('http://victim-web:80').status_code)"
```

### Log Analysis
```bash
# View webapp logs
docker logs securitylogs-webapp

# View attacker logs
docker logs securitylogs-attacker

# View tcpdump logs
docker logs securitylogs-tcpdump

# Analyze PCAP files
docker exec securitylogs-tcpdump tshark -r /data/traffic.pcap -q -z io,stat,1
```

## Performance Optimization

### Resource Management
```bash
# Monitor resource usage
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Set resource limits in docker-compose.yml
services:
  webapp:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
```

### Parallel Execution
```bash
# Run variants in parallel
bash control/automation/run_all_variants.sh --parallel

# Monitor parallel execution
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

### Data Management
```bash
# Clean old data
make clean-all

# Compress large files
gzip data/pcap/*.pcap

# Archive old experiments
tar -czf experiment_$(date +%Y%m%d).tar.gz data/
```

## Troubleshooting

### Common Issues

1. **Container Startup Issues**
   ```bash
   # Check container logs
   make logs
   
   # Restart containers
   make down && make up
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
   ls -lh data/pcap/
   ```

### Debug Procedures

1. **Container Debugging**
   ```bash
   # Enter container
   docker exec -it securitylogs-webapp bash
   
   # Check processes
   ps aux
   
   # Check network
   netstat -tlnp
   ```

2. **Network Debugging**
   ```bash
   # Check network interfaces
   docker exec securitylogs-tcpdump ip addr
   
   # Test connectivity
   docker exec securitylogs-attacker ping victim-web
   ```

3. **Application Debugging**
   ```bash
   # Check webapp configuration
   docker exec securitylogs-webapp cat /etc/nginx/nginx.conf
   
   # Check PHP configuration
   docker exec securitylogs-webapp php -m
   ```

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
       @mkdir -p data/output/variants/custom
       @docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py --variant custom
   ```

### Integration with External Tools

The project can be integrated with:
- SIEM systems for log analysis
- Network monitoring tools
- Security testing frameworks
- Academic research platforms

### Custom Network Profiles

1. **Create custom profile** in `control/network/netem_profiles/`:
   ```json
   {
     "name": "custom_profile",
     "latency": 100,
     "jitter": 10,
     "loss": 1,
     "bandwidth": "10mbit"
   }
   ```

2. **Apply custom profile**:
   ```bash
   bash control/network/apply_netem.sh --profile custom_profile
   ```

## Best Practices

### Experiment Design
1. **Documentation**: Document all experiments and parameters
2. **Reproducibility**: Use fixed random seeds and timestamps
3. **Isolation**: Run experiments in isolated environments
4. **Monitoring**: Monitor resource usage during experiments

### Data Management
1. **Backup**: Regular backup of configuration and data
2. **Cleanup**: Clean up old data and logs
3. **Compression**: Compress large PCAP files
4. **Archiving**: Archive completed experiments

### Security
1. **Isolation**: Always run in isolated Docker environments
2. **Monitoring**: Monitor for unexpected behavior
3. **Cleanup**: Clean up after experiments
4. **Compliance**: Follow local laws and regulations

## Support

For additional support:
1. Check container logs: `make logs`
2. Review configuration files
3. Use debug commands provided
4. Check troubleshooting section
5. Review project documentation 