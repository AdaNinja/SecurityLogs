FROM ubuntu:20.04

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
COPY scripts/analyze_pcap.py /usr/local/bin/analyze_pcap.py
RUN chmod +x /usr/local/bin/capture_traffic.sh

# Set environment variables
ENV SERVICE_NAME=securitylogs-tcpdump

# Default command
CMD ["/usr/local/bin/capture_traffic.sh"]
