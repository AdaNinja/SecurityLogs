#!/bin/bash

# Start script for web application container
set -e

echo "[$(date)] Starting SecurityLogs Web Application..."

# Start MySQL service
echo "[$(date)] Starting MySQL..."
service mysql start

# Wait for MySQL to be ready
echo "[$(date)] Waiting for MySQL to be ready..."
while ! mysqladmin ping -h"localhost" --silent; do
    sleep 1
done
echo "[$(date)] MySQL is ready"

# Initialize database if needed
if [ ! -f /var/lib/mysql/vulnerable_db ]; then
    echo "[$(date)] Initializing database..."
    mysql < /tmp/init_db.sql
    echo "[$(date)] Database initialized"
fi

# Start PHP-FPM
echo "[$(date)] Starting PHP-FPM..."
service php7.4-fpm start

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
tcpdump -i any -w /data/raw/webapp_traffic.pcap -s 65535 > /dev/null 2>&1 &

# Create log files
touch /var/log/login_attempts.log
touch /var/log/search_attempts.log
touch /var/log/access.log
touch /var/log/error.log

# Set proper permissions
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

echo "[$(date)] Web application is ready!"
echo "[$(date)] Access the application at: http://localhost:8080"

# Keep container running
tail -f /dev/null 