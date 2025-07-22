FROM debian:bullseye-slim

# 使用默认镜像源，避免网络问题
# RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
#     sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list

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
