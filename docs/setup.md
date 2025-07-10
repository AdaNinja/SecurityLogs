# Setup Guide

This document provides detailed setup instructions for the SecurityLogs project.

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+)
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Memory**: 4GB+ RAM
- **Disk**: 10GB+ free space
- **Network**: Stable internet connection

### Software Installation

#### Docker Installation
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose

# CentOS/RHEL
sudo yum install docker docker-compose

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
```

#### Python Dependencies
```bash
# Install Python 3.8+
sudo apt install python3 python3-pip

# Install required Python packages
pip3 install requests beautifulsoup4 pyyaml
```

## Project Setup

### 1. Clone Repository
```bash
git clone <repository-url>
cd SecurityLogs
```

### 2. Build Docker Images
```bash
# Build all containers
make build

# Verify images
docker images | grep securitylogs
```

### 3. Create Data Directories
```bash
# Create data directories
mkdir -p data/logs data/pcap data/output

# Set permissions
chmod 755 data/
```

### 4. Verify Setup
```bash
# Check container status
make status

# Test basic functionality
make sqli-quick
```

## Configuration

### Network Configuration
The project uses Docker networks for container communication:

```bash
# View networks
docker network ls

# Inspect network
docker network inspect low-and-slow-sqli_attacknet
```

### Container Configuration
Each container has specific configuration files:

- **Webapp**: `containers/webapp/config/`
- **Attacker**: `containers/attacker/scripts/`
- **Tcpdump**: `containers/tcpdump/scripts/`

### Scenario Configuration
Scenario-specific configurations are in:

- **Main config**: `scenarios/low-and-slow-sqli/config/scenario.env`
- **Variants**: `scenarios/low-and-slow-sqli/config/variants.yml`
- **Docker compose**: `scenarios/low-and-slow-sqli/docker-compose.yml`

## Troubleshooting

### Common Setup Issues

1. **Docker Permission Issues**
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   newgrp docker
   ```

2. **Port Conflicts**
   ```bash
   # Check port usage
   sudo netstat -tlnp | grep :8080
   
   # Kill conflicting processes
   sudo kill -9 <PID>
   ```

3. **Disk Space Issues**
   ```bash
   # Check disk space
   df -h
   
   # Clean Docker images
   docker system prune -a
   ```

4. **Network Issues**
   ```bash
   # Check Docker networks
   docker network ls
   
   # Recreate networks
   docker network prune
   ```

### Verification Commands

```bash
# Check Docker installation
docker --version
docker-compose --version

# Check container images
docker images

# Check container status
docker ps -a

# Check network connectivity
ping -c 3 8.8.8.8
```

## Advanced Setup

### Custom Network Configuration
```bash
# Create custom network
docker network create --driver bridge custom-attacknet

# Update docker-compose.yml to use custom network
```

### Resource Limits
```bash
# Set container resource limits in docker-compose.yml
services:
  webapp:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
```

### Logging Configuration
```bash
# Configure log drivers in docker-compose.yml
services:
  webapp:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

## Security Setup

### Firewall Configuration
```bash
# Allow Docker traffic
sudo ufw allow 8080/tcp
sudo ufw allow 22/tcp

# Check firewall status
sudo ufw status
```

### SELinux Configuration (CentOS/RHEL)
```bash
# Configure SELinux for Docker
sudo setsebool -P container_manage_cgroup 1
sudo setsebool -P container_use_cgroup 1
```

## Performance Optimization

### System Tuning
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize Docker daemon
sudo tee /etc/docker/daemon.json <<EOF
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
sudo systemctl restart docker
```

### Container Optimization
- Use multi-stage builds for smaller images
- Implement health checks for containers
- Configure proper resource limits
- Use volume mounts for persistent data

## Monitoring Setup

### Basic Monitoring
```bash
# Monitor container resources
docker stats

# Monitor disk usage
df -h

# Monitor network traffic
iftop
```

### Log Monitoring
```bash
# View real-time logs
make logs

# Monitor specific container
docker logs -f securitylogs-webapp
```

## Backup and Recovery

### Data Backup
```bash
# Backup configuration files
tar -czf config_backup_$(date +%Y%m%d).tar.gz scenarios/ containers/

# Backup data directory
tar -czf data_backup_$(date +%Y%m%d).tar.gz data/
```

### Recovery Procedures
```bash
# Restore from backup
tar -xzf config_backup_YYYYMMDD.tar.gz
tar -xzf data_backup_YYYYMMDD.tar.gz

# Rebuild containers
make build
make up
```

## Support

For additional support:
1. Check container logs: `make logs`
2. Review configuration files
3. Verify system requirements
4. Check troubleshooting section 