FROM ubuntu:22.04

# Install Suricata and dependencies
RUN apt-get update && apt-get install -y \
    suricata \
    iptables \
    net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create Suricata directories
RUN mkdir -p /var/log/suricata \
    && mkdir -p /var/lib/suricata/rules \
    && mkdir -p /etc/suricata

# Copy Suricata configuration and rules
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY custom.rules /var/lib/suricata/rules/custom.rules

# Create a startup script for Suricata
RUN echo '#!/bin/bash\n\
echo "Starting Suricata in IDS monitoring mode..."\n\
\n\
# Start Suricata with pcap mode\n\
suricata -c /etc/suricata/suricata.yaml -i any\n\
' > /start-suricata.sh && chmod +x /start-suricata.sh

# Expose port for management (if needed)
EXPOSE 8080

# Set working directory for logs
WORKDIR /var/log/suricata

# Default command to run Suricata
CMD ["/start-suricata.sh"]