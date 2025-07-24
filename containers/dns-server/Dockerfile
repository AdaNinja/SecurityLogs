FROM ubuntu:22.04

# Use host network for build
ENV DEBIAN_FRONTEND=noninteractive

# Install only essential packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9 \
    bind9utils \
    dnsutils \
    python3 \
    python3-pip \
    && pip3 install --no-cache-dir dnspython \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/*

# Create DNS configuration directory
RUN mkdir -p /etc/bind/zones

# Create necessary directories for BIND9
RUN mkdir -p /var/cache/bind /var/run/named /var/log/named \
    && chown -R bind:bind /var/cache/bind /var/run/named /var/log/named

# Copy DNS configuration files
COPY named.conf.local /etc/bind/
COPY named.conf.options /etc/bind/
COPY attacker.local.zone /etc/bind/zones/
COPY dns_handler.py /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/dns_handler.py
RUN chown -R bind:bind /etc/bind

# Create log directory
RUN mkdir -p /var/log/dns-server
RUN chown bind:bind /var/log/dns-server

# Expose DNS ports
EXPOSE 53/udp 53/tcp

# Start DNS server with proper working directory
CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "bind", "-d", "1"] 