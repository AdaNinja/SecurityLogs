# Lightweight Attacker Container with Security Tools
FROM debian:bullseye-slim

# 避免交互式提示
ARG DEBIAN_FRONTEND=noninteractive

# 使用默认镜像源，避免网络问题
# RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
#     sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list

# 安装基础包和安全测试工具（含Perl及Nikto依赖）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      python3-setuptools \
      curl \
      wget \
      bash \
      ca-certificates \
      nmap \
      dirb \
      git \
      perl \
      libnet-ssleay-perl \
      libio-socket-ssl-perl \
      libwww-perl \
      liblwp-protocol-https-perl \
      libnet-dns-perl \
      libjson-perl \
      libstring-crc32-perl \
      libnet-ip-perl \
      libhtml-parser-perl \
      libhtml-tableextract-perl \
      libhtml-tree-perl \
      libhtml-form-perl \
      libhtml-format-perl \
      libxml-simple-perl \
      libnet-whois-ip-perl \
      libdigest-sha-perl \
      libdata-dump-perl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/* \
    && echo "Base packages and Perl modules installed successfully"

# 使用中国 PyPI 镜像并优化Python安装
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple/ \
    && pip3 install --no-cache-dir --timeout 60 --retries 3 \
        requests \
        colorama \
        urllib3 \
        idna \
        chardet \
        charset-normalizer \
        certifi \
        dnspython \
    && rm -rf ~/.cache/pip

# 安装 SQLMap 和 Nikto (最小化安装)
RUN git clone --depth 1 --single-branch --no-tags https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py \
    && rm -rf /opt/sqlmap/.git \
    && rm -rf /opt/sqlmap/doc \
    && rm -rf /opt/sqlmap/tamper \
    && rm -rf /opt/sqlmap/udf \
    && sed -i '/from extra.beep.beep import beep/d' /opt/sqlmap/lib/core/common.py \
    && sed -i '/from extra.cloak.cloak import decloak/d' /opt/sqlmap/lib/core/common.py \
    && sed -i 's/beep()/pass/' /opt/sqlmap/lib/core/common.py \
    && sed -i '/from extra.beep.beep import beep/d' /opt/sqlmap/lib/controller/checks.py \
    && sed -i 's/beep()/pass/' /opt/sqlmap/lib/controller/checks.py \
    && echo "SQLMap installed successfully" \
    && git clone --depth 1 --single-branch --no-tags https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && rm -rf /opt/nikto/.git \
    && echo "Nikto installed successfully"

# Create necessary directories
RUN mkdir -p /opt/scripts /opt/output /opt/logs /data/raw

# Set up environment
ENV PATH="/opt/scripts:/opt/sqlmap:/opt/nikto/program:$PATH"
ENV PYTHONPATH="/opt/scripts:$PYTHONPATH"

# Set working directory
WORKDIR /opt/scripts

# Default command to keep container running
CMD ["tail", "-f", "/dev/null"]

RUN ln -s /usr/bin/python3 /usr/bin/python
