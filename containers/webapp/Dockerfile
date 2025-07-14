FROM debian:bullseye-slim

# 避免交互式提示
ARG DEBIAN_FRONTEND=noninteractive

# 使用默认镜像源，避免网络问题
# RUN sed -i 's/ports.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
#     sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
#     sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

# 安装基础包
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      nginx \
      php7.4-fpm \
      php7.4-sqlite3 \
      php7.4-curl \
      php7.4-json \
      sqlite3 \
      curl \
      wget \
      rsyslog \
      tcpdump \
      python3 \
      python3-pip \
      openssh-server \
      cron \
      net-tools \
      procps \
      vim \
      nano \
      bc \
    && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
RUN pip3 install requests beautifulsoup4

# 创建必要目录
RUN mkdir -p /var/www/html /var/log /data/raw /opt/scripts /opt/output /home/userA /home/userB /backup /var/log/nginx

# 复制web应用文件
COPY webapp/ /var/www/html/
COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/sshd_config /etc/ssh/sshd_config
COPY config/pool.d/www.conf /etc/php/7.4/fpm/pool.d/www.conf

# 复制启动脚本
COPY scripts/start.sh /usr/local/bin/start.sh
COPY scripts/backup_script.sh /opt/scripts/backup_script.sh
RUN chmod +x /usr/local/bin/start.sh /opt/scripts/backup_script.sh

# 初始化SQLite数据库
COPY scripts/init_db.sql /tmp/init_db.sql
RUN sqlite3 /var/www/html/database.sqlite < /tmp/init_db.sql

# 设置SSH用户
RUN useradd -m -s /bin/bash userA && \
    useradd -m -s /bin/bash userB && \
    echo "userA:password123" | chpasswd && \
    echo "userB:password456" | chpasswd && \
    mkdir -p /home/userA/.ssh /home/userB/.ssh && \
    chown -R userA:userA /home/userA && \
    chown -R userB:userB /home/userB

# 设置cron任务
RUN echo "0 2 * * * /opt/scripts/backup_script.sh" | crontab -

# 设置权限
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

# 暴露端口
EXPOSE 80 22

# 设置环境变量
ENV SERVICE_NAME=securitylogs-webapp
ENV SCENARIO_TYPE=webapp

# 启动服务
CMD ["/usr/local/bin/start.sh"]
