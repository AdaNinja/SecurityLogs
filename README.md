# SecurityLogs - Security Attack Experiment Platform

A Docker-based security attack experiment platform focused on data collection and analysis of low-scan and slow SQL injection attacks.

## 🚀 Features

### Core Features
- **SQL Injection Attack Simulation**: Multiple SQL injection techniques (Union, Boolean, Time-based, etc.)
- **DNS Attack Module**: Complete DNS attack toolkit
- **Network Traffic Capture**: Real-time PCAP data collection
- **Automated ETL Processing**: Unified data format processing
- **MITRE ATT&CK Mapping**: Attack technique classification

### DNS Attack Techniques
- **DNS Reconnaissance**: Subdomain enumeration, DNS record queries, zone transfer attempts
- **DNS Brute Force**: Random subdomain brute force attacks
- **DNS Cache Poisoning**: Simulated DNS cache poisoning attacks
- **DNS Amplification**: Simulated DNS amplification attacks
- **DNS Tunneling**: Multiple encoding methods for DNS tunneling
- **DNS Data Exfiltration**: Data exfiltration through DNS tunnels

### Attack Variants
- **Stealthy**: Low-intensity attacks with subtle patterns
- **Moderate**: Balanced attack intensity with mixed techniques
- **Aggressive**: High-intensity attacks with obvious patterns

## 🏗️ Architecture

### Container Structure
- **Web Application Container**: Target application with SQL injection vulnerabilities
- **Attacker Container**: Automated attack execution engine
- **DNS Server Container**: Realistic C&C communication simulation
- **TCPDump Container**: Network traffic capture and analysis

### Data Processing Pipeline
1. **Raw Log Collection**: Multi-source log aggregation
2. **ETL Processing**: Variant-specific data transformation
3. **Unified Dataset Creation**: Standardized data format
4. **Simplified View Generation**: Auto-labeling for ML training

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.8+
- Git

### Installation
```bash
git clone https://github.com/AdaNinja/SecurityLogs.git
cd SecurityLogs
```

### Build Containers
```bash
# Build all containers
make build

# Or build specific containers
./scripts/build_attacker_only.sh
./scripts/build_dns_server.sh
```

### Run Experiments
```bash
# Run single variant
python3 scripts/run_variant.py stealthy
python3 scripts/run_variant.py moderate
python3 scripts/run_variant.py aggressive

# Run all variants
python3 scripts/run_all_variants.py
```

## 📊 Data Output

### Raw Logs
- **DNS Proxy Logs**: `data/logs/{variant}/attacks/proxy/dns_proxy_raw.jsonl`
- **HTTP Proxy Logs**: `data/logs/{variant}/attacks/proxy/http_proxy_raw.jsonl`
- **System Logs**: `data/logs/{variant}/system/`
- **PCAP Files**: `data/logs/{variant}/pcap/`

### Processed Data
- **Unified Dataset**: `data/processed/{variant}/datasets/unified_dataset.csv`
- **Simplified View**: `data/processed/{variant}/datasets/simplified_view.csv`
- **Analysis Results**: `data/processed/{variant}/analysis/`

## 🔧 Configuration

### Variant Configuration
Each attack variant has specific configurations:
- **Attack Intensity**: Low, Medium, High
- **Delay Settings**: Between attack phases
- **Technique Selection**: Subset of attack techniques
- **Data Volume**: Number of generated log entries

### ETL Processing
- **Variant-Specific Processing**: Automatic adjustment based on variant type
- **Risk Scoring**: Dynamic risk assessment based on attack patterns
- **Auto-Labeling**: Intelligent classification of attack vs benign traffic

## 📈 Results

### Expected Data Volumes
- **Stealthy Variant**: ~22 DNS records, subtle attack patterns
- **Moderate Variant**: ~57 DNS records, balanced attack patterns
- **Aggressive Variant**: ~77 DNS records, obvious attack patterns

### Label Distribution
- **Benign Traffic**: Normal application and network traffic
- **Attack Traffic**: SQL injection, DNS attacks, reconnaissance
- **Suspicious Traffic**: Requires manual review

