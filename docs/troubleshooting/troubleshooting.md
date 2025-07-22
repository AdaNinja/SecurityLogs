# Troubleshooting Guide

This document provides comprehensive troubleshooting information for common issues in the SecurityLogs project.

## Quick Diagnostic Commands

### System Health Check
```bash
# Check Docker status
docker --version && docker-compose --version

# Check container status
make status

# Check disk space
df -h

# Check memory usage
free -h

# Check network connectivity
ping -c 3 8.8.8.8
```

### Container Health Check
```bash
# Check all containers
docker ps -a

# Check container logs
make logs

# Check container resources
docker stats --no-stream
```

## Common Issues and Solutions

### 1. Container Startup Issues

#### Problem: Containers fail to start
```bash
# Error: Cannot connect to the Docker daemon
```

**Solutions:**
```bash
# 1. Check Docker service
sudo systemctl status docker

# 2. Start Docker service
sudo systemctl start docker

# 3. Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# 4. Restart Docker daemon
sudo systemctl restart docker
```

#### Problem: Port conflicts
```bash
# Error: Bind for 0.0.0.0:8080 failed: port is already allocated
```

**Solutions:**
```bash
# 1. Check port usage
sudo netstat -tlnp | grep :8080

# 2. Kill conflicting process
sudo kill -9 <PID>

# 3. Or change port in docker-compose.yml
ports:
  - "8081:80"  # Change from 8080 to 8081
```

#### Problem: Container health check failures
```bash
# Error: Container is unhealthy
```

**Solutions:**
```bash
# 1. Check container logs
docker logs securitylogs-webapp

# 2. Check health check configuration
docker inspect securitylogs-webapp | grep -A 10 Health

# 3. Restart container
docker restart securitylogs-webapp
```

### 2. Network Issues

#### Problem: Containers cannot communicate
```bash
# Error: Connection refused
```

**Solutions:**
```bash
# 1. Check Docker networks
docker network ls

# 2. Inspect network
docker network inspect low-and-slow-sqli_attacknet

# 3. Recreate network
docker network prune
docker-compose up -d

# 4. Test connectivity
docker exec securitylogs-attacker ping victim-web
```

#### Problem: Network emulation not working
```bash
# Error: tc command not found or permission denied
```

**Solutions:**
```bash
# 1. Install tc (traffic control)
sudo apt install iproute2

# 2. Check tc permissions
sudo tc qdisc show

# 3. Run with sudo
sudo bash control/network/apply_netem.sh

# 4. Or run container with privileged mode
docker run --privileged ...
```

### 3. Attack Script Issues

#### Problem: Attack scripts fail to connect
```bash
# Error: Connection timeout
```

**Solutions:**
```bash
# 1. Check webapp accessibility
curl -f http://localhost:8080/

# 2. Test from attacker container
docker exec securitylogs-attacker python3 -c "import requests; print(requests.get('http://victim-web:80').status_code)"

# 3. Check DNS resolution
docker exec securitylogs-attacker nslookup victim-web

# 4. Check network connectivity
docker exec securitylogs-attacker ping victim-web
```

#### Problem: Python dependencies missing
```bash
# Error: ModuleNotFoundError: No module named 'requests'
```

**Solutions:**
```bash
# 1. Install dependencies in attacker container
docker exec securitylogs-attacker pip3 install requests beautifulsoup4

# 2. Rebuild attacker container
docker build -t securitylogs-attacker containers/attacker

# 3. Or add to Dockerfile
RUN pip3 install requests beautifulsoup4
```

### 4. PCAP Capture Issues

#### Problem: PCAP files are empty
```bash
# Error: No traffic captured
```

**Solutions:**
```bash
# 1. Check tcpdump container
docker logs securitylogs-tcpdump

# 2. Check tcpdump permissions
docker exec securitylogs-tcpdump ls -la /data/

# 3. Test tcpdump manually
docker exec securitylogs-tcpdump tcpdump -i any -c 10

# 4. Check network interfaces
docker exec securitylogs-tcpdump ip addr
```

#### Problem: Insufficient disk space
```bash
# Error: No space left on device
```

**Solutions:**
```bash
# 1. Check disk space
df -h

# 2. Clean Docker images
docker system prune -a

# 3. Clean old PCAP files
rm -f data/pcap/*.pcap

# 4. Compress large files
gzip data/pcap/*.pcap
```

### 5. Log Collection Issues

#### Problem: Log files not generated
```bash
# Error: Log directory not found
```

**Solutions:**
```bash
# 1. Create log directories
mkdir -p data/logs data/pcap data/output

# 2. Set permissions
chmod 755 data/

# 3. Check log configuration
docker exec securitylogs-webapp ls -la /var/log/

# 4. Restart log aggregator
docker restart securitylogs-log-aggregator
```

#### Problem: Log aggregator container issues
```bash
# Error: Log aggregator not collecting logs
```

**Solutions:**
```bash
# 1. Check log aggregator status
docker logs securitylogs-log-aggregator

# 2. Check log aggregator configuration
docker exec securitylogs-log-aggregator cat /opt/config/logging.conf

# 3. Restart log aggregator
docker restart securitylogs-log-aggregator

# 4. Check log retention settings
docker exec securitylogs-log-aggregator ls -la /opt/logs/
```

### 6. Performance Issues

#### Problem: High CPU/Memory usage
```bash
# Error: System becomes unresponsive
```

**Solutions:**
```bash
# 1. Monitor resource usage
docker stats

# 2. Set resource limits in docker-compose.yml
services:
  webapp:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'

# 3. Reduce parallel processes
# Use --no-parallel flag in scripts

# 4. Clean up resources
docker system prune
```

#### Problem: Slow attack execution
```bash
# Error: Attacks take too long
```

**Solutions:**
```bash
# 1. Check network conditions
bash control/network/reset_netem.sh

# 2. Reduce attack delays in config
# Edit config/variants.yml

# 3. Use faster attack variants
make attack-aggressive

# 4. Monitor system resources
htop
```

### 7. Configuration Issues

#### Problem: Configuration files not found
```bash
# Error: File not found
```

**Solutions:**
```bash
# 1. Check file paths
ls -la scenarios/low-and-slow-sqli/config/

# 2. Verify configuration syntax
python3 -c "import yaml; yaml.safe_load(open('config/variants.yml'))"

# 3. Check environment variables
docker exec securitylogs-webapp env | grep SCENARIO

# 4. Rebuild containers with new config
make build
```

#### Problem: Environment variables not set
```bash
# Error: Variable not defined
```

**Solutions:**
```bash
# 1. Check .env file
cat scenarios/low-and-slow-sqli/.env

# 2. Set environment variables
export SCENARIO_NAME=low-and-slow-sqli

# 3. Pass variables to containers
docker-compose --env-file .env up -d

# 4. Check container environment
docker exec securitylogs-webapp env
```

## Debug Procedures

### Step-by-Step Debugging

#### 1. Container Debugging
```bash
# Enter container
docker exec -it securitylogs-webapp bash

# Check processes
ps aux

# Check network
netstat -tlnp

# Check logs
tail -f /var/log/nginx/error.log

# Check configuration
cat /etc/nginx/nginx.conf
```

#### 2. Network Debugging
```bash
# Check network interfaces
docker exec securitylogs-tcpdump ip addr

# Test connectivity
docker exec securitylogs-attacker ping victim-web

# Check DNS resolution
docker exec securitylogs-attacker nslookup victim-web

# Check routing
docker exec securitylogs-tcpdump ip route
```

#### 3. Application Debugging
```bash
# Check webapp configuration
docker exec securitylogs-webapp cat /etc/nginx/nginx.conf

# Check PHP configuration
docker exec securitylogs-webapp php -m

# Check MySQL connection
docker exec securitylogs-webapp mysql -u root -p -e "SHOW DATABASES;"

# Check attack script
docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py --help
```

### Advanced Debugging

#### 1. Packet Analysis
```bash
# Capture packets manually
docker exec securitylogs-tcpdump tcpdump -i any -w /tmp/debug.pcap

# Analyze packets
docker exec securitylogs-tcpdump tshark -r /tmp/debug.pcap -q -z io,stat,1

# Filter specific traffic
docker exec securitylogs-tcpdump tcpdump -i any 'host victim-web' -w /tmp/webapp.pcap
```

#### 2. Log Analysis
```bash
# View real-time logs
docker logs -f securitylogs-webapp

# Search for errors
docker logs securitylogs-webapp 2>&1 | grep -i error

# Analyze log patterns
docker logs securitylogs-webapp | grep -E "(ERROR|WARN|CRITICAL)"

# Check log rotation
docker exec securitylogs-webapp ls -la /var/log/
```

#### 3. Performance Analysis
```bash
# Monitor container resources
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Profile container processes
docker exec securitylogs-webapp top

# Check disk I/O
docker exec securitylogs-webapp iostat

# Monitor network usage
docker exec securitylogs-tcpdump iftop
```

## Recovery Procedures

### Complete Reset
```bash
# Stop all containers
make down

# Remove all containers and images
make clean

# Clean data directories
rm -rf data/logs/* data/pcap/* data/output/*

# Rebuild everything
make build
make up
```

### Partial Reset
```bash
# Restart specific container
docker restart securitylogs-webapp

# Rebuild specific container
docker build -t securitylogs-webapp containers/webapp

# Reset network conditions
bash control/network/reset_netem.sh
```

### Data Recovery
```bash
# Backup current data
tar -czf backup_$(date +%Y%m%d_%H%M%S).tar.gz data/

# Restore from backup
tar -xzf backup_YYYYMMDD_HHMMSS.tar.gz

# Verify data integrity
ls -la data/logs/ data/pcap/ data/output/
```

## Prevention

### Best Practices
1. **Regular Monitoring**: Monitor system resources and container health
2. **Backup Configuration**: Regularly backup configuration files
3. **Resource Limits**: Set appropriate resource limits for containers
4. **Log Rotation**: Implement proper log rotation and retention
5. **Health Checks**: Use health checks for critical containers
6. **Documentation**: Document all changes and configurations

### Maintenance Schedule
```bash
# Daily checks
make status
df -h

# Weekly maintenance
docker system prune
make clean-all

# Monthly maintenance
docker system prune -a
tar -czf monthly_backup_$(date +%Y%m).tar.gz data/
```

## Support Resources

### Documentation
- `README.md` - Project overview
- `docs/setup.md` - Setup instructions
- `docs/usage.md` - Usage guide
- `scenarios/low-and-slow-sqli/README.md` - Scenario documentation

### Debug Tools
- `make logs` - View container logs
- `make status` - Check container status
- `docker stats` - Monitor resource usage
- `docker exec` - Execute commands in containers

### External Resources
- Docker documentation: https://docs.docker.com/
- Docker Compose documentation: https://docs.docker.com/compose/
- Linux networking: https://www.kernel.org/doc/html/latest/networking/
- Security testing: https://owasp.org/ 