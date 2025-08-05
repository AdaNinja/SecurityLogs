# RAS/scenario-securitylogs/confs/attacker/Dockerfile
# Recommended to use host network for faster build:
# docker build --network=host -t ras-attacker:latest .

FROM ubuntu:22.04

# Set environment variables to avoid interactive installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package sources and install basic system dependencies
RUN apt-get update && \
    apt-get install -y \
      curl \
      nmap \
      git \
      python3 \
      python3-pip \
      wget \
      unzip \
      build-essential \
      && rm -rf /var/lib/apt/lists/*

# Install sqlmap
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install dirb (using apt to avoid compilation issues)
RUN apt-get update && \
    apt-get install -y dirb && \
    rm -rf /var/lib/apt/lists/*

# Install gobuster (using apt)
RUN apt-get update && \
    apt-get install -y gobuster && \
    rm -rf /var/lib/apt/lists/*

# Install hydra
RUN apt-get update && \
    apt-get install -y hydra && \
    rm -rf /var/lib/apt/lists/*

# Python tools
RUN pip3 install \
      xsstrike commix

# Create necessary directories
RUN mkdir -p /opt/scripts /logs

# Set working directory
WORKDIR /opt

# Set environment variables
ENV TARGET_HOST=fancystore.com
ENV TARGET_PORT=80
ENV ATTACK_PHASE=automated
ENV VARIANT_ID=full_attack_suite

# Copy attack scripts and configuration files
COPY attack.sh /opt/scripts/
COPY attacks/ /opt/scripts/attacks/
COPY detection_rules.yaml /opt/scripts/

# Set execution permissions
RUN chmod +x /opt/scripts/attack.sh

# Default command - keep container running
CMD ["tail", "-f", "/dev/null"] 