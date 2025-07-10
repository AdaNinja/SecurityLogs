FROM ubuntu:20.04

# Change to Chinese mirrors for better network access
RUN sed -i 's/ports.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

# Install tcpdump and network tools
RUN apt-get update && \
    apt-get install -y \
      tcpdump \
      wireshark \
      tshark \
      netcat \
      curl \
      wget \
      rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Create directories for pcap storage
RUN mkdir -p /pcaps /logs /data/raw

# Copy capture scripts
COPY scripts/capture_traffic.sh /usr/local/bin/capture_traffic.sh
RUN chmod +x /usr/local/bin/capture_traffic.sh

# Set environment variables
ENV SERVICE_NAME=securitylogs-tcpdump

# Default command
CMD ["/usr/local/bin/capture_traffic.sh"]
