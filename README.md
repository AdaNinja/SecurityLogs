# Security Logs Attack Scenarios

This repository contains a collection of containerised attack scenarios used for generating security log datasets. Each scenario provides Docker configurations and helper scripts to reproduce specific network intrusions in a controlled environment.

## Project Structure

```
.
├── containers/            # Docker images used across scenarios
│   ├── webapp/           # Vulnerable web application
│   ├── attacker/         # Attack execution container
│   └── tcpdump/          # Network traffic capture
├── control/              # Control center and automation
│   ├── network/          # Network emulation tools
│   └── automation/       # Experiment automation scripts
├── scenarios/            # Individual attack scenarios
│   └── low-and-slow-sqli/ # SQL injection attack scenario
├── data/                 # Generated data and logs
│   ├── logs/            # Application and container logs
│   ├── pcap/            # Network traffic captures
│   └── output/          # Analysis results and reports
├── docs/                 # Project documentation
├── Makefile              # Unified project management
└── README.md
```

## Available Scenarios

- **low-and-slow-sqli** – Simulates a slow SQL injection attack with background web traffic.

## Quick Start

### 1. Basic Usage
   ```bash
# Build all Docker images
   make build

# Start containers and run basic attack
make sqli-quick

# Check container status
make status

# View logs
make logs
```

### 2. Advanced Usage
   ```bash
# Run specific attack variants
make attack-stealthy    # Stealthy attack (RISK=1, LEVEL=1)
make attack-moderate    # Moderate attack (RISK=1, LEVEL=2)
make attack-aggressive  # Aggressive attack (RISK=2, LEVEL=3)

# Run interleaved attack with benign traffic
make interleaved

# Complete workflow with data collection
make all
```

### 3. Network Emulation
   ```bash
# Apply network conditions
make apply-netem

# Reset network conditions
make reset-netem
```

## Control Center

The `control/` directory contains centralized tools for experiment management:

### Network Tools (`control/network/`)
- **`apply_netem.sh`** - Apply network conditions (latency, packet loss)
- **`reset_netem.sh`** - Reset network conditions to normal
- **`netem_profiles/`** - Network condition configurations

### Automation Tools (`control/automation/`)
- **`run_all_variants.sh`** - Execute all attack variants with data collection
- **`capture.sh`** - Complete traffic capture and analysis workflow
- **`multi_source_logger.py`** - Multi-source log collection and analysis

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
1. **Container Logs** - Application and system logs from all containers
2. **Network Traffic** - Complete PCAP captures with traffic analysis
3. **Attack Results** - Vulnerability detection and attack success rates

## Container Architecture

### Container Roles
- **securitylogs-webapp**: Vulnerable web application (target)
- **securitylogs-attacker**: Attack execution container with Kali tools
- **securitylogs-tcpdump**: Network traffic capture and analysis
- **securitylogs-log-aggregator**: Log collection and analysis

## Documentation

- **`scenarios/low-and-slow-sqli/README.md`** - Detailed scenario documentation
- **`control/README.md`** - Control center documentation
- **`docs/`** - Additional project documentation

## Security Considerations

⚠️ **Important Reminder**
- These scenarios are for research and education purposes only.
- Run them in an isolated test environment.
- Do not use on production systems or real networks.
- Always comply with local laws and regulations.

## System Requirements

- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Memory**: 4GB+ RAM
- **Disk**: 10GB+ free space
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+)

## Troubleshooting

### Common Issues
1. **Container startup failure**: Check Docker and port occupancy
2. **Network emulation failure**: Check tc command and container permissions
3. **Attack script failure**: Check target container health status
4. **Traffic capture failure**: Check tcpdump permissions and disk space

### Debug Commands
```bash
# Check container status
make status

# View container logs
make logs

# Enter containers for debugging
docker exec -it securitylogs-webapp bash
docker exec -it securitylogs-attacker bash
docker exec -it securitylogs-tcpdump bash
```

## Contributing

Contributions and issues are welcome. Feel free to open a PR to improve the scenarios or documentation.

## License

This project is for educational and research purposes only.
