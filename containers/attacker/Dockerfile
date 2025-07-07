FROM kalilinux/kali-rolling

# Avoid interactive prompts
ARG DEBIAN_FRONTEND=noninteractive

# Update and install essential tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      nmap \
      sqlmap \
      metasploit-framework \
      nikto \
      dirb \
      hydra \
      john \
      hashcat \
      aircrack-ng \
      wireshark \
      tcpdump \
      curl \
      wget \
      git \
      python3 \
      python3-pip \
      python3-requests \
      python3-beautifulsoup4 \
      python3-lxml \
      rsyslog \
      supervisor \
      tmux \
      vim \
      nano \
    && rm -rf /var/lib/apt/lists/*

# Install additional Python tools
RUN pip3 install \
    requests \
    beautifulsoup4 \
    lxml \
    selenium \
    paramiko \
    scapy \
    python-nmap \
    colorama \
    tabulate

# Create necessary directories
RUN mkdir -p /opt/scripts /opt/output /opt/logs /data/raw

# Copy attack scripts
COPY scripts/run_recon.sh /opt/scripts/run_recon.sh
COPY scripts/run_attack.sh /opt/scripts/run_attack.sh
COPY scripts/sql_injection.py /opt/scripts/sql_injection.py
COPY scripts/network_scan.py /opt/scripts/network_scan.py
RUN chmod +x /opt/scripts/*.sh

# Set up sqlmap configuration
RUN mkdir -p /root/.local/share/sqlmap
COPY config/sqlmap.conf /root/.local/share/sqlmap/sqlmap.conf

# Set up environment
ENV PATH="/opt/scripts:$PATH"
ENV PYTHONPATH="/opt/scripts:$PYTHONPATH"

# Set working directory
WORKDIR /opt/scripts

# Default command to keep container running
CMD ["tail", "-f", "/dev/null"]
