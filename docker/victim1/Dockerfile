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
      python3-requests \
      python3-selenium \
      firefox \
      xvfb \
      xdotool \
      wget \
      gnupg \
      software-properties-common \
 && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
RUN pip3 install requests selenium beautifulsoup4 lxml

# 下载并安装geckodriver
RUN wget -q https://github.com/mozilla/geckodriver/releases/download/v0.33.0/geckodriver-v0.33.0-linux64.tar.gz \
 && tar -xzf geckodriver-v0.33.0-linux64.tar.gz \
 && mv geckodriver /usr/local/bin/ \
 && rm geckodriver-v0.33.0-linux64.tar.gz

# 创建日志目录
RUN mkdir -p /data/raw

# 复制 entrypoint 并赋可执行权限
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 默认环境变量
ENV SERVICE_NAME=victim1
ENV DISPLAY=:99

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
