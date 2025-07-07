FROM python:3.9-slim

# Avoid interactive prompts
ARG DEBIAN_FRONTEND=noninteractive

# Use domestic mirror sources
RUN echo "deb http://mirrors.aliyun.com/debian/ bookworm main" > /etc/apt/sources.list \
 && echo "deb http://mirrors.aliyun.com/debian/ bookworm-updates main" >> /etc/apt/sources.list \
 && echo "deb http://mirrors.aliyun.com/debian-security bookworm-security main" >> /etc/apt/sources.list

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tcpdump \
      rsyslog \
      curl \
      wget \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install flask requests

# Skip MailHog for now, use simple mail simulation
RUN echo "MailHog not available for ARM64, using simple mail simulation"

# Create log directory
RUN mkdir -p /data/raw

# Copy credential collector
COPY credential_collector.py /usr/local/bin/credential_collector.py

# Copy entrypoint and make executable
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default environment variables
ENV SERVICE_NAME=victim2

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
