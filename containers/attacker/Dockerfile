# Lightweight Attacker Container
FROM debian:bullseye-slim

# 避免交互式提示
ARG DEBIAN_FRONTEND=noninteractive

# 安装基础包
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      curl \
      wget \
      bash \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 使用中国 PyPI 镜像
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple/

# 安装 Python 依赖
RUN pip3 install --no-cache-dir \
    requests \
    colorama

# Create necessary directories
RUN mkdir -p /opt/scripts /opt/output /opt/logs /data/raw

# Set up environment
ENV PATH="/opt/scripts:$PATH"
ENV PYTHONPATH="/opt/scripts:$PYTHONPATH"

# Set working directory
WORKDIR /opt/scripts

# Default command to keep container running
CMD ["tail", "-f", "/dev/null"]
