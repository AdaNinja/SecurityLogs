# RAS - Research Attack Simulation Environment

A versatile, containerized framework for replicating diverse attack scenarios and capturing artifacts for security analysis and defensive system development, featuring modular definitions of scenarios and built-in network packet capture capabilities.

## 🏗️ Definitions

RAS revolves around **scenarios** that define the environment and attack vectors. Each scenario consists of:
- **Containers**: Docker images for services (e.g., nginx, Juice Shop)
- **Networks**: Docker networks for communication
- **Configurations**: Nginx and ModSecurity configurations
- **Artifacts**: Output directories for logs and packet captures

We provide two example scenarios:
1. **Vanilla**: Basic setup with nginx proxying to Juice Shop, no WAF.
2. **WAF**: Same setup with ModSecurity WAF enabled, preventing suspicious payloads from reaching the application.


## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- sudo access (for packet capture)

### Basic Usage

```bash
# Start vanilla scenario
./ras.sh vanilla start

# Stop scenario and cleanup
./ras.sh vanilla stop

# Start WAF scenario with packet capture
./ras.sh waf start --sniff edge

./ras.sh waf stop
```

## 📋 Commands

### Scenario Management
```bash
./ras.sh <scenario> <command> [options]
```

**Scenarios:** 
- `vanilla` - No WAF protection
- `waf` - ModSecurity WAF enabled

**Commands:**
- `start [--sniff BRIDGE]` - Start containers (optionally with packet capture)
- `stop` - Stop containers and packet capture
- `restart` - Restart containers
- `logs` - Show container logs
- `bridges` - Show available network bridges
- `clean` - Remove all containers and data

### Packet Capture Options
Use `--sniff` with start command:
- `edge` - Capture attacker/shopper ↔ nginx traffic
- `appnet` - Capture nginx ↔ web service traffic  
- `both` - Capture both networks

## 📁 Output Structure

```
scenario-vanilla/
└── out/
    ├── nginx/     # Nginx access/error logs
    └── pcap/      # Packet captures (timestamped)

scenario-waf/
└── out/
    ├── nginx/     # Nginx logs
    ├── waf/       # ModSecurity logs
    └── pcap/      # Packet captures (timestamped)
```

### Packet Capture
Must be enabled with `--sniff` option. Captures are stored in:
- `scenario-<name>/out/pcap/`
- Timestamped PCAP files (YYYYMMDD-HHMMSS format)
- Automatic cleanup when stopping containers

## 🔧 Examples

```bash
# Start vanilla with full network capture
./ras.sh vanilla start --sniff both

# View WAF scenario logs in real-time
./ras.sh waf logs

# Check available bridges for waf scenario
./ras.sh waf bridges

# Clean everything for vanilla scenario
./ras.sh vanilla clean

# Restart waf scenario with edge capture
./ras.sh waf restart
./ras.sh waf start --sniff edge
```

## 🐛 Troubleshooting

**Containers won't start:**
```bash
./ras.sh <scenario> clean
./ras.sh <scenario> start
```

**Permission issues:**
```bash
./ras.sh <scenario> fix-permissions
```

**Can't find networks:**
- Ensure containers are running before using `--sniff` or `bridges` commands