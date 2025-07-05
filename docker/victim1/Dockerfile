FROM ubuntu:22.04

# 避免互动提示
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      auditd \
      tcpdump \
      curl \
      rsyslog \
 && rm -rf /var/lib/apt/lists/*

# 创建日志目录
RUN mkdir -p /data/raw

# 复制 entrypoint 并赋可执行权限
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 默认环境变量
ENV SERVICE_NAME=victim1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
