FROM debian:bullseye-slim

# 安装 tcpdump 及常用工具
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tcpdump \
      iproute2 \
      iputils-ping \
      procps \
      bash \
      ca-certificates \
      curl \
    && rm -rf /var/lib/apt/lists/*

# ─── 目录和脚本 ─────────────────────────────────────────────────────────────────
RUN mkdir -p /pcaps /logs /data/raw

COPY scripts/capture_traffic.sh /usr/local/bin/capture_traffic.sh
RUN chmod +x /usr/local/bin/capture_traffic.sh

ENV SERVICE_NAME=securitylogs-tcpdump

CMD ["/usr/local/bin/capture_traffic.sh"]
