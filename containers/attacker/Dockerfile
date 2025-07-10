# Lightweight Attacker Container
FROM alpine:latest

# Use Chinese mirrors for better network access
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

# Update package index and install basic packages
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
      curl \
      wget \
    bash \
    && rm -rf /var/cache/apk/*

# Use Chinese PyPI mirror
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple/

# Install Python dependencies
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
