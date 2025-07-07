FROM ubuntu:20.04

# Avoid interactive prompts
ARG DEBIAN_FRONTEND=noninteractive

# Install system packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      nginx \
      php7.4-fpm \
      php7.4-mysql \
      php7.4-curl \
      php7.4-json \
      mysql-server \
      curl \
      wget \
      supervisor \
      rsyslog \
      tcpdump \
      python3 \
      python3-pip \
      python3-selenium \
      firefox \
      xvfb \
      geckodriver \
      openssh-server \
      cron \
      rsync \
      nfs-common \
      net-tools \
      procps \
      vim \
      nano \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for user simulation
RUN pip3 install selenium requests beautifulsoup4 lxml

# Create necessary directories
RUN mkdir -p /var/www/html /var/log /data/raw /opt/scripts /opt/output /home/userA /home/userB /backup

# Copy web application files
COPY webapp/ /var/www/html/
COPY config/nginx.conf /etc/nginx/sites-available/default
COPY config/php.ini /etc/php/7.4/fpm/php.ini
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY config/sshd_config /etc/ssh/sshd_config

# Copy startup and simulation scripts
COPY scripts/start.sh /usr/local/bin/start.sh
COPY scripts/run_benign.sh /opt/scripts/run_benign.sh
COPY scripts/simulate_user.py /opt/scripts/simulate_user.py
COPY scripts/backup_script.sh /opt/scripts/backup_script.sh
RUN chmod +x /usr/local/bin/start.sh /opt/scripts/run_benign.sh /opt/scripts/backup_script.sh

# Initialize MySQL database with vulnerable data
COPY scripts/init_db.sql /tmp/init_db.sql
RUN service mysql start && \
    mysql < /tmp/init_db.sql && \
    service mysql stop

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

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

# Expose ports
EXPOSE 80 22

# Set environment variables
ENV SERVICE_NAME=securitylogs-webapp
ENV DISPLAY=:99
ENV SCENARIO_TYPE=webapp

# Start services
CMD ["/usr/local/bin/start.sh"]
