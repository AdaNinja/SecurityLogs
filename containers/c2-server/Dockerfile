FROM python:3.9-slim

# Install system packages
RUN apt-get update && \
    apt-get install -y \
      curl \
      wget \
      rsyslog \
      tcpdump \
      net-tools \
      procps \
      vim \
      nano \
      openssh-client \
      autossh \
      socat \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install \
    flask \
    fastapi \
    uvicorn \
    websockets \
    paramiko \
    cryptography \
    requests \
    beautifulsoup4 \
    lxml \
    colorama \
    tabulate \
    python-nmap \
    scapy

# Create necessary directories
RUN mkdir -p /opt/c2 /opt/logs /opt/output /opt/scripts /data/raw

# Copy C2 server files
COPY c2_server/ /opt/c2/
COPY scripts/start_c2.sh /usr/local/bin/start_c2.sh
COPY scripts/tunnel_handler.py /opt/scripts/tunnel_handler.py
COPY scripts/command_executor.py /opt/scripts/command_executor.py
RUN chmod +x /usr/local/bin/start_c2.sh

# Set up SSH keys for reverse tunnels
RUN mkdir -p /root/.ssh && \
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" && \
    cat /root/.ssh/id_rsa.pub > /root/.ssh/authorized_keys

# Expose ports
EXPOSE 8080 2222 8443 9000

# Set environment variables
ENV SERVICE_NAME=securitylogs-c2-server
ENV SCENARIO_TYPE=c2-server
ENV C2_PROTOCOL=http
ENV C2_PORT=8080

# Start C2 server
CMD ["/usr/local/bin/start_c2.sh"] 