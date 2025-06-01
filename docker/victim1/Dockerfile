FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y auditd tcpdump iputils-ping curl procps \
 && rm -rf /var/lib/apt/lists/*


# 拷贝 entrypoint 脚本
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]