FROM ubuntu:20.04

# Avoid interactive prompts
ARG DEBIAN_FRONTEND=noninteractive

# Install system packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      openssh-server \
      nginx \
      curl \
      wget \
      rsyslog \
      tcpdump \
      python3 \
      python3-pip \
      cron \
      rsync \
      nfs-common \
      net-tools \
      procps \
      vim \
      nano \
      git \
      nodejs \
      npm \
      supervisor \
      mysql-client \
      postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install requests flask fastapi uvicorn

# Create necessary directories
RUN mkdir -p /var/log /data/raw /opt/scripts /opt/output /home/userA /home/userB /backup /app

# Copy configuration files
COPY config/sshd_config /etc/ssh/sshd_config
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy scripts
COPY scripts/start.sh /usr/local/bin/start.sh
COPY scripts/backup_script.sh /opt/scripts/backup_script.sh
COPY scripts/simulate_benign.sh /opt/scripts/simulate_benign.sh
RUN chmod +x /usr/local/bin/start.sh /opt/scripts/backup_script.sh /opt/scripts/simulate_benign.sh

# Set up SSH users and keys
RUN useradd -m -s /bin/bash userA && \
    useradd -m -s /bin/bash userB && \
    echo "userA:password123" | chpasswd && \
    echo "userB:password456" | chpasswd && \
    mkdir -p /home/userA/.ssh /home/userB/.ssh && \
    chown -R userA:userA /home/userA && \
    chown -R userB:userB /home/userB

# Set up cron jobs for backup simulation
RUN echo "0 2 * * * /opt/scripts/backup_script.sh" | crontab -

# Expose ports
EXPOSE 22 80 443 3000

# Set environment variables
ENV SERVICE_NAME=securitylogs-victim
ENV SCENARIO_TYPE=victim

# Start services
CMD ["/usr/local/bin/start.sh"] 