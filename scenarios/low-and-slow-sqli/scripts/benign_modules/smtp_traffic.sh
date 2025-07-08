#!/bin/bash

# SMTP Traffic Module for Benign Traffic Generation
# Generates realistic SMTP traffic to simulate email activity

set -e

# Load configuration
source /opt/config/scenario.env 2>/dev/null || true

# Default values
SMTP_SERVER=${SMTP_SERVER:-"smtp.gmail.com"}
SMTP_PORT=${SMTP_PORT:-587}
REQUEST_INTERVAL=${REQUEST_INTERVAL:-10}
TOTAL_DURATION=${BENIGN_TOTAL_DURATION:-2400}
LOG_FILE="/var/log/benign_smtp.log"

# Common email domains
EMAIL_DOMAINS=(
    "gmail.com"
    "yahoo.com"
    "hotmail.com"
    "outlook.com"
    "icloud.com"
    "protonmail.com"
    "mail.com"
    "aol.com"
    "live.com"
    "msn.com"
)

# Email subjects for realistic traffic
EMAIL_SUBJECTS=(
    "Meeting reminder"
    "Weekly report"
    "Project update"
    "System notification"
    "Account verification"
    "Password reset"
    "Newsletter"
    "Invoice"
    "Receipt"
    "Welcome message"
)

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SMTP: $1" >> "$LOG_FILE"
}

generate_smtp_traffic() {
    local start_time=$(date +%s)
    local end_time=$((start_time + TOTAL_DURATION))
    
    log_message "Starting SMTP traffic generation for ${TOTAL_DURATION} seconds"
    
    while [ $(date +%s) -lt $end_time ]; do
        # Select random email domain
        local domain=${EMAIL_DOMAINS[$((RANDOM % ${#EMAIL_DOMAINS[@]}))]}
        
        # Select random subject
        local subject=${EMAIL_SUBJECTS[$((RANDOM % ${#EMAIL_SUBJECTS[@]}))]}
        
        # Generate random email addresses
        local from_user="user$((RANDOM % 1000))"
        local to_user="recipient$((RANDOM % 1000))"
        local from_email="${from_user}@${domain}"
        local to_email="${to_user}@${domain}"
        
        # Simulate SMTP connection using telnet or nc
        if command -v telnet >/dev/null 2>&1; then
            # Use telnet for SMTP simulation
            (
                echo "EHLO localhost"
                echo "MAIL FROM: <$from_email>"
                echo "RCPT TO: <$to_email>"
                echo "DATA"
                echo "Subject: $subject"
                echo "From: $from_email"
                echo "To: $to_email"
                echo ""
                echo "This is a test email for benign traffic generation."
                echo "."
                echo "QUIT"
            ) | timeout 5 telnet $SMTP_SERVER $SMTP_PORT > /dev/null 2>&1 || true
            
            log_message "SMTP: $from_email -> $to_email ($subject)"
        elif command -v nc >/dev/null 2>&1; then
            # Use netcat for SMTP simulation
            (
                echo "EHLO localhost"
                echo "MAIL FROM: <$from_email>"
                echo "RCPT TO: <$to_email>"
                echo "DATA"
                echo "Subject: $subject"
                echo "From: $from_email"
                echo "To: $to_email"
                echo ""
                echo "This is a test email for benign traffic generation."
                echo "."
                echo "QUIT"
            ) | timeout 5 nc $SMTP_SERVER $SMTP_PORT > /dev/null 2>&1 || true
            
            log_message "SMTP: $from_email -> $to_email ($subject) [nc]"
        else
            # Fallback: just log the attempt
            log_message "SMTP simulation attempted: $from_email -> $to_email ($subject) [no telnet/nc]"
        fi
        
        # Random delay between SMTP attempts
        local delay=$((RANDOM % REQUEST_INTERVAL + 5))
        sleep $delay
    done
    
    log_message "SMTP traffic generation completed"
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    generate_smtp_traffic
fi 