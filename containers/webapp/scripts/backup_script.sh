#!/bin/bash

# Backup script for simulating normal user activity
# This creates realistic background traffic for attack scenarios

set -e

BACKUP_DIR="/backup"
USERA_HOME="/home/userA"
USERB_HOME="/home/userB"
LOG_FILE="/var/log/backup.log"

echo "[$(date)] Starting backup simulation..." >> $LOG_FILE

# Create some test files for userA
mkdir -p $USERA_HOME/documents
mkdir -p $USERA_HOME/projects
mkdir -p $USERA_HOME/backup

# Generate some test files
echo "Important document content $(date)" > $USERA_HOME/documents/report.txt
echo "Project source code $(date)" > $USERA_HOME/projects/main.py
echo "Configuration file $(date)" > $USERA_HOME/.config

# Create backup for userA
tar -czf $USERA_HOME/backup/userA_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    $USERA_HOME/documents \
    $USERA_HOME/projects \
    $USERA_HOME/.config 2>/dev/null || true

# Create some test files for userB
mkdir -p $USERB_HOME/data
mkdir -p $USERB_HOME/backup

echo "User B data $(date)" > $USERB_HOME/data/dataset.csv
echo "User B config $(date)" > $USERB_HOME/.profile

# Create backup for userB
tar -czf $USERB_HOME/backup/userB_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    $USERB_HOME/data \
    $USERB_HOME/.profile 2>/dev/null || true

# Simulate rsync to NFS (if available)
if [ -d "/mnt/nfs" ]; then
    echo "[$(date)] Syncing to NFS..." >> $LOG_FILE
    rsync -av $USERA_HOME/backup/ /mnt/nfs/userA/ 2>/dev/null || true
    rsync -av $USERB_HOME/backup/ /mnt/nfs/userB/ 2>/dev/null || true
fi

# Clean up old backups (keep last 5)
find $USERA_HOME/backup -name "*.tar.gz" -mtime +7 -delete 2>/dev/null || true
find $USERB_HOME/backup -name "*.tar.gz" -mtime +7 -delete 2>/dev/null || true

echo "[$(date)] Backup simulation completed" >> $LOG_FILE 