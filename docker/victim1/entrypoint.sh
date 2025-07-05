#!/bin/sh
SERVICE_NAME=${SERVICE_NAME:-$(hostname)}

echo "[*] Starting services for ${SERVICE_NAME}..."

# 1. start rsyslog
echo "[*] Starting rsyslog..."
rsyslogd -n &



# 2. 启动 tcpdump
echo "[*] Starting tcpdump..."
tcpdump -i any -s 65535 -w /data/raw/${SERVICE_NAME}_$(date +%s).pcap &
sleep 2

# 验证 tcpdump 状态
if pgrep -f tcpdump > /dev/null; then
    echo "[+] tcpdump is running successfully"
    echo "[*] Capturing to: /data/raw/${SERVICE_NAME}_*.pcap"
else
    echo "[-] tcpdump failed to start"
fi

# 3. 显示服务状态摘要
echo "[*] Service status summary:"
echo "    - rsyslog: $(service rsyslog status | head -1)"
echo "    - tcpdump: $(pgrep -f tcpdump | wc -l) process(es) running"

# 4. 保持容器存活
echo "[*] Container is ready. Keeping alive..."
touch /data/raw/.keepalive
exec tail -f /data/raw/.keepalive
