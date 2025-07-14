FROM debian:bullseye-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      curl \
      bash \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
RUN pip3 install --no-cache-dir requests

WORKDIR /opt/control

CMD ["/bin/bash", "-c", "python3 /opt/control/multi_source_logger.py --continuous"] 