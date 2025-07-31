# RAS/scenario-securitylogs/confs/attacker/Dockerfile

FROM ubuntu:22.04

# 设置环境变量避免交互式安装
ENV DEBIAN_FRONTEND=noninteractive

# 更新软件源并安装基础系统依赖
RUN apt-get update && \
    apt-get install -y \
      curl \
      nmap \
      git \
      python3 \
      python3-pip \
      wget \
      unzip \
      build-essential \
      && rm -rf /var/lib/apt/lists/*

# 安装sqlmap
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# 安装dirb (使用apt安装，避免编译问题)
RUN apt-get update && \
    apt-get install -y dirb && \
    rm -rf /var/lib/apt/lists/*

# 安装gobuster (使用apt安装)
RUN apt-get update && \
    apt-get install -y gobuster && \
    rm -rf /var/lib/apt/lists/*

# 安装hydra
RUN apt-get update && \
    apt-get install -y hydra && \
    rm -rf /var/lib/apt/lists/*

# Python 工具
RUN pip3 install \
      xsstrike commix

# 创建必要的目录
RUN mkdir -p /opt/scripts /log

# 设置工作目录
WORKDIR /opt

# 设置环境变量
ENV TARGET_HOST=fancystore.com
ENV TARGET_PORT=80
ENV ATTACK_TYPE=comprehensive
ENV ATTACK_PHASE=automated
ENV VARIANT_ID=full_attack_suite

# 默认命令 - 保持容器运行
CMD ["tail", "-f", "/dev/null"] 