#!/bin/bash

# Start script for web application container
set -e

echo "[$(date)] Starting SecurityLogs Web Application..."

# Initialize SQLite database if needed
if [ ! -f /var/www/html/database.sqlite ]; then
    echo "[$(date)] Initializing SQLite database..."
    sqlite3 /var/www/html/database.sqlite < /tmp/init_db.sql
    echo "[$(date)] Database initialized"
fi

# Create PHP-FPM socket directory and set permissions
echo "[$(date)] Setting up PHP-FPM socket directory..."
mkdir -p /run/php
chown www-data:www-data /run/php
chmod 755 /run/php

# Create logs directory structure
echo "[$(date)] Creating logs directory structure..."
mkdir -p /var/log/logs
mkdir -p /var/log/nginx

# Configure rsyslog to output to logs subdirectory
echo "[$(date)] Configuring rsyslog..."
cat > /etc/rsyslog.d/securitylogs.conf << EOF
# SecurityLogs rsyslog configuration
# Output system logs to logs subdirectory
*.info;mail.none;authpriv.none;cron.none /var/log/logs/messages
auth,authpriv.* /var/log/logs/auth.log
*.emerg /var/log/logs/emergency.log
kern.* /var/log/logs/kern.log
mail.* /var/log/logs/mail.log
cron.* /var/log/logs/cron.log
*.=debug /var/log/logs/debug.log
*.=info /var/log/logs/info.log
*.=notice /var/log/logs/notice.log
*.=warn /var/log/logs/warn.log
*.=err /var/log/logs/error.log
*.=crit /var/log/logs/crit.log
*.=alert /var/log/logs/alert.log
*.=emerg /var/log/logs/emerg.log
EOF

# Configure PHP-FPM to log to logs subdirectory
echo "[$(date)] Configuring PHP-FPM logging..."
sed -i 's|^error_log = .*|error_log = /var/log/logs/php7.4-fpm.log|' /etc/php/7.4/fpm/php-fpm.conf
sed -i 's|^access.log = .*|access.log = /var/log/logs/php7.4-fpm-access.log|' /etc/php/7.4/fpm/pool.d/www.conf

# Start PHP-FPM
echo "[$(date)] Starting PHP-FPM..."
service php7.4-fpm start

# Wait for PHP-FPM socket to be created
echo "[$(date)] Waiting for PHP-FPM socket..."
for i in {1..30}; do
    if [ -S /run/php/php7.4-fpm.sock ]; then
        echo "[$(date)] PHP-FPM socket created successfully"
        break
    fi
    sleep 1
done

# Set socket permissions
if [ -S /run/php/php7.4-fpm.sock ]; then
    chmod 666 /run/php/php7.4-fpm.sock
    echo "[$(date)] PHP-FPM socket permissions set"
else
    echo "[$(date)] ERROR: PHP-FPM socket not created"
    exit 1
fi

# Ensure nginx log directory and files exist
mkdir -p /var/log/nginx
[ -f /var/log/nginx/access.log ] || touch /var/log/nginx/access.log
[ -f /var/log/nginx/error.log ] || touch /var/log/nginx/error.log
chown -R www-data:www-data /var/log/nginx

# Start Nginx
echo "[$(date)] Starting Nginx..."
service nginx start

# Start Xvfb for headless browser
echo "[$(date)] Starting Xvfb..."
Xvfb :99 -screen 0 1024x768x24 > /dev/null 2>&1 &
export DISPLAY=:99

# Start rsyslog for logging
echo "[$(date)] Starting rsyslog..."
service rsyslog start

# Start tcpdump for network capture
echo "[$(date)] Starting tcpdump..."
tcpdump -i any -w /data/raw/webapp_traffic.pcap -s 262144 -v > /dev/null 2>&1 &

# Create application-specific log files
echo "[$(date)] Creating application log files..."
touch /var/log/logs/login_attempts.log
touch /var/log/logs/search_attempts.log

# Set proper permissions for logs directory and files
chown -R www-data:www-data /var/log/logs
chmod -R 755 /var/log/logs
chmod 666 /var/log/logs/*.log

# Set proper permissions for web application
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

echo "[$(date)] Web application is ready!"
echo "[$(date)] Access the application at: http://localhost:8080"

# Keep container running
tail -f /dev/null 