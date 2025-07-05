#!/bin/sh
SERVICE_NAME=${SERVICE_NAME:-$(hostname)}

echo "[*] Starting services for ${SERVICE_NAME}..."


# 1. start rsyslog
echo "[*] Starting rsyslog..."
rsyslogd -n &


# 2. 启动 MailHog
echo "[*] Starting MailHog..."
mailhog -api-bind-addr 0.0.0.0:8025 -ui-bind-addr 0.0.0.0:8025 -smtp-bind-addr 0.0.0.0:1025 &
sleep 2


# 3. 启动凭证收集服务器
echo "[*] Starting credential collector..."
python3 /usr/local/bin/credential_collector.py &
sleep 2


# 4. 启动 tcpdump
echo "[*] Starting tcpdump..."
tcpdump -i any -s 65535 -w /data/raw/${SERVICE_NAME}_$(date +%s).pcap &
sleep 2


# 验证服务状态
if pgrep -f mailhog > /dev/null; then
    echo "[+] MailHog is running successfully"
else
    echo "[-] MailHog failed to start"
fi

if pgrep -f tcpdump > /dev/null; then
    echo "[+] tcpdump is running successfully"
    echo "[*] Capturing to: /data/raw/${SERVICE_NAME}_*.pcap"
else
    echo "[-] tcpdump failed to start"
fi


# 5. 显示服务状态摘要
echo "[*] Service status summary:"
echo "    - rsyslog: $(service rsyslog status | head -1)"
echo "    - mailhog: $(pgrep -f mailhog | wc -l) process(es) running"
echo "    - collector: $(pgrep -f credential_collector | wc -l) process(es) running"
echo "    - tcpdump: $(pgrep -f tcpdump | wc -l) process(es) running"


# 6. 保持容器存活
echo "[*] Container is ready. Keeping alive..."
touch /data/raw/.keepalive
exec tail -f /data/raw/.keepalive
