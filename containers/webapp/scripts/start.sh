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