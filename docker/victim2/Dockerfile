FROM ubuntu:22.04

# 避免互动提示
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      auditd \
      tcpdump \
      curl \
      rsyslog \
      python3 \
      python3-pip \
      python3-flask \
      python3-requests \
      wget \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
RUN pip3 install flask requests

# 下载并安装MailHog
RUN wget -q https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64 \
 && chmod +x MailHog_linux_amd64 \
 && mv MailHog_linux_amd64 /usr/local/bin/mailhog

# 创建日志目录
RUN mkdir -p /data/raw

# 复制 entrypoint 并赋可执行权限
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 默认环境变量
ENV SERVICE_NAME=victim2

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
