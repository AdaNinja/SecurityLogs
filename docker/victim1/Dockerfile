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
      firefox-esr \
      xvfb \
      gnupg \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install requests selenium beautifulsoup4 lxml flask

# Download and install geckodriver
RUN wget -q https://github.com/mozilla/geckodriver/releases/download/v0.33.0/geckodriver-v0.33.0-linux64.tar.gz \
 && tar -xzf geckodriver-v0.33.0-linux64.tar.gz \
 && mv geckodriver /usr/local/bin/ \
 && rm geckodriver-v0.33.0-linux64.tar.gz

# Create log directory
RUN mkdir -p /data/raw

# Copy entrypoint and make executable
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default environment variables
ENV SERVICE_NAME=victim1
ENV DISPLAY=:99

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
