# 网络问题解决方案

## 问题描述

在构建Docker镜像时经常遇到网络超时问题，特别是在下载Debian包和Python依赖时。

## 解决方案

### 方案1: 使用Host网络构建（推荐）

这是最简单有效的解决方案，已经在Makefile中配置：

```bash
# 构建所有镜像
make build

# 或者手动构建
docker build --network=host -t securitylogs-webapp containers/webapp
docker build --network=host -t securitylogs-attacker containers/attacker
docker build --network=host -t securitylogs-tcpdump containers/tcpdump
```

### 方案2: 使用国内镜像源（备选）

如果host网络方案不可用，可以启用国内镜像源：

#### 修改Dockerfile

在Dockerfile中取消注释以下行：

```dockerfile
# 使用国内镜像源，解决网络问题
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list
```

#### 修改Python包源

```dockerfile
# 使用中国 PyPI 镜像
RUN pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple requests beautifulsoup4 urllib3
```

### 方案3: 清理缓存后重试

如果遇到缓存问题：

```bash
# 清理Docker缓存
docker system prune -a -f
docker builder prune -a -f

# 重新构建
make build
```

## 当前配置

项目已配置为使用host网络构建，这是最稳定的解决方案：

- ✅ Makefile已配置 `--network=host` 参数
- ✅ 所有Dockerfile保持原始配置（使用官方源）
- ✅ 构建过程稳定可靠

## 使用说明

1. **正常构建**: `make build`
2. **清理后构建**: `docker system prune -a -f && make build`
3. **单个镜像构建**: `docker build --network=host -t securitylogs-webapp containers/webapp`

## 注意事项

- Host网络方案需要Docker守护进程支持
- 如果host网络不可用，可以临时启用国内镜像源方案
- 建议定期清理Docker缓存以避免空间问题 