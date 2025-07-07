# Security Log Dataset - Phishing Attack Scenario

This is a phishing email attack scenario for generating security log datasets, implementing a complete attack chain: Reconnaissance → Delivery → Exploitation.

## Project Structure

```
.
├── docker/
│   ├── docker-compose.yml          # Docker orchestration file
│   ├── victim1/                    # Victim1 container (client)
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh
│   │   └── raw/                    # Log storage directory
│   └── victim2/                    # Victim2 container (server)
│       ├── Dockerfile
│       ├── entrypoint.sh
│       ├── credential_collector.py # Credential collection server
│       └── raw/                    # Log storage directory
├── scenarios/
│   └── phishing/                   # Phishing attack scenario
│       ├── scenario.yaml           # Scenario configuration
│       ├── benign.py               # Benign behavior script
│       ├── attack.py               # Attack script
│       └── labels.py               # Label functions
├── logger_utils.py                 # Logging utilities
├── run_scenario.py                 # Scenario scheduler
├── start_attack.py                 # One-click startup script
└── requirements.txt                # Python dependencies
```

## Attack Scenario Description

### Phishing Email Attack Chain

1. **Reconnaissance Phase**
   - Simulate normal web browsing behavior
   - Visit benign websites (example.com, httpbin.org, etc.)
   - Generate normal network traffic logs

2. **Delivery Phase**
   - Send phishing emails to target mailboxes
   - Simulate email opening behavior
   - Use browser automation to click phishing links

3. **Exploitation Phase**
   - Access phishing pages
   - Fill and submit login forms
   - Steal user credentials
   - Send credentials to C2 server

## Quick Start

### Method 1: One-click Startup (Recommended)

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# One-click attack scenario startup
python3 start_attack.py
```

### Method 2: Manual Steps

```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Build and start containers
cd docker
docker-compose up -d

# 3. Wait for services to be ready (about 30 seconds)
sleep 30

# 4. Run attack scenario
cd ..
python3 run_scenario.py --config scenarios/phishing/scenario.yaml
```

## Verify Results

### 1. View MailHog Email Interface
Visit http://localhost:8025 to view sent phishing emails

### 2. View Collected Credentials
Visit http://localhost:9000/credentials to view stolen credentials

### 3. View Container Logs
```bash
# View victim1 logs
docker logs docker_victim1_1

# View victim2 logs
docker logs docker_victim2_1
```

### 4. View Network Traffic
```bash
# View victim1 pcap files
ls docker/victim1/raw/

# View victim2 pcap files
ls docker/victim2/raw/
```

## Repeat Exercise

### Clean Environment
```bash
# Stop and remove containers
docker-compose -f docker/docker-compose.yml down

# Clean log files
sudo truncate -s0 /var/log/audit/audit.log
sudo truncate -s0 /var/log/syslog
```

### Re-run Exercise
```bash
# Restart
python3 start_attack.py
```

## Log Analysis

### System Log Labels
During the attack process, the following labels will be injected into system logs:
- `phase=Reconnaissance` - Reconnaissance phase
- `phase=Delivery` - Delivery phase  
- `phase=Exploitation` - Exploitation phase
- `attack_event=*` - Various attack events

### Network Traffic
- victim1 container: Captures all network traffic
- victim2 container: Captures server-side traffic
- Includes HTTP requests, credential submissions, etc.

### Audit Logs
- Python process execution records
- System call audits
- File access records

## Custom Configuration

### Modify Attack Parameters
Edit `scenarios/phishing/scenario.yaml`:
```yaml
parameters:
  attack_delay_s: 30          # Attack delay
  benign_sites:               # Benign website list
    - "http://example.com"
  phishing_email:             # Phishing email configuration
    subject: "Important Notice"
```

### Add New Attack Scenarios
1. Create new directory under `scenarios/`
2. Implement `benign.py`, `attack.py`, `labels.py`
3. Create `scenario.yaml` configuration file
4. Run: `python3 run_scenario.py --config scenarios/new_scenario/scenario.yaml`

## Troubleshooting

### Common Issues

1. **Container Startup Failure**
   ```bash
   # Check Docker service
   sudo systemctl status docker
   
   # Clean Docker cache
   docker system prune -a
   ```

2. **Browser Automation Failure**
   ```bash
   # Check Firefox and geckodriver
   docker exec docker_victim1_1 which firefox
   docker exec docker_victim1_1 which geckodriver
   ```

3. **Network Connection Issues**
   ```bash
   # Check container network
   docker network ls
   docker network inspect docker_phishnet
   ```

## Security Considerations

⚠️ **Important Reminder**:
- This project is for security research and educational purposes only
- Please run in an isolated test environment
- Do not use in production environments or real networks
- Comply with local laws and regulations

## Technology Stack

- **Containerization**: Docker + Docker Compose
- **Mail Server**: MailHog
- **Browser Automation**: Selenium + Firefox
- **Web Framework**: Flask
- **Logging Tools**: rsyslog + auditd
- **Network Capture**: tcpdump
- **Programming Language**: Python 3

## Contributing

Welcome to submit Issues and Pull Requests to improve this project.
