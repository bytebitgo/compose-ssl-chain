# Compose SSL Chain

[![构建和测试](https://github.com/compose-ssl-chain/ssl-chain-analyzer/actions/workflows/build.yml/badge.svg)](https://github.com/compose-ssl-chain/ssl-chain-analyzer/actions/workflows/build.yml)
[![发布](https://github.com/compose-ssl-chain/ssl-chain-analyzer/actions/workflows/release.yml/badge.svg)](https://github.com/compose-ssl-chain/ssl-chain-analyzer/actions/workflows/release.yml)
[![安全扫描](https://github.com/compose-ssl-chain/ssl-chain-analyzer/actions/workflows/security.yml/badge.svg)](https://github.com/compose-ssl-chain/ssl-chain-analyzer/actions/workflows/security.yml)

一个用于下载和分析SSL/TLS证书链的工具，支持RSA和ECC双证书分析。

## 功能特点

- 支持下载RSA和ECC双证书及其证书链
- 支持读取本地PEM/CRT证书文件并分析证书链
- 分析证书链的完整性和可信性
- 检测证书是否过期
- 检测证书链是否包含吊销信息
- 导出证书为PEM格式
- 详细的证书信息展示

## 安装

### 从源码安装

```bash
git clone https://github.com/compose-ssl-chain.git
cd compose-ssl-chain
go build -o ssl-chain-analyzer ./cmd
```

### 从包安装

#### Debian/Ubuntu

```bash
# 从GitHub Releases下载最新的DEB包
curl -LO https://github.com/compose-ssl-chain/ssl-chain-analyzer/releases/latest/download/ssl-chain-analyzer_1.0.3_linux_amd64.deb
sudo dpkg -i ssl-chain-analyzer_1.0.3_linux_amd64.deb
```

#### CentOS/RHEL/Fedora

```bash
# 从GitHub Releases下载最新的RPM包
curl -LO https://github.com/compose-ssl-chain/ssl-chain-analyzer/releases/latest/download/ssl-chain-analyzer-1.0.3.x86_64.rpm
sudo rpm -i ssl-chain-analyzer-1.0.3.x86_64.rpm
```

## 构建包

### 使用nFPM

```bash
# 安装nFPM
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

# 构建并打包
make package
```

### 使用GoReleaser

```bash
# 安装GoReleaser
go install github.com/goreleaser/goreleaser@latest

# 构建并打包
goreleaser release --snapshot --rm-dist
```

### 使用Docker构建环境

```bash
# 运行Docker构建脚本
./docker-build.sh
```

## 发布新版本

```bash
# 1. 更新版本号
# 在以下文件中更新版本号：
# - nfpm.yaml
# - Makefile
# - README.md
# - CHANGELOG.md

# 2. 提交更改
git add .
git commit -m "发布 v1.0.3"

# 3. 创建标签
git tag -a v1.0.3 -m "v1.0.3"

# 4. 推送到GitHub
git push origin main
git push origin v1.0.3

# GitHub Actions将自动构建并发布新版本
```

## 使用方法

### 分析在线域名

```bash
# 基本用法
./ssl-chain-analyzer -domain example.com

# 指定端口
./ssl-chain-analyzer -domain example.com -port 443

# 导出证书
./ssl-chain-analyzer -domain example.com -export

# 指定输出目录
./ssl-chain-analyzer -domain example.com -export -output ./certs

# 显示详细信息
./ssl-chain-analyzer -domain example.com -verbose
```

### 分析本地证书文件

```bash
# 分析单个证书文件
./ssl-chain-analyzer -cert ./cert.pem

# 分析证书文件并导出证书链
./ssl-chain-analyzer -cert ./cert.pem -export

# 分析证书目录
./ssl-chain-analyzer -cert-dir ./certs

# 显示详细信息
./ssl-chain-analyzer -cert ./cert.pem -verbose
```

## 命令行参数

- `-domain`: 要分析的域名
- `-port`: HTTPS端口（默认：443）
- `-cert`: 本地证书文件路径
- `-cert-dir`: 本地证书目录路径
- `-output`: 证书输出目录（默认：certificates）
- `-export`: 是否导出证书（默认：false）
- `-verbose`: 是否显示详细信息（默认：false）

## 输出示例

```
正在分析域名: example.com (端口: 443)
域名: example.com:443
支持双证书: 否

找到RSA证书链 (3个证书)

未找到ECC证书链

=== RSA证书链摘要 ===
证书链完整性: 是
证书链可信性: 是
未发现问题
证书链长度: 3
叶子证书: example.com (RSA 2048位)
```

## 版本历史

### v1.0.7 (2025-03-08)
- 修复了前端 JavaScript 模块加载的 MIME 类型问题
- 修复了静态文件服务的路径配置
- 优化了前端构建输出目录的配置
- 改进了前端界面的响应性和交互体验

### v1.0.6 (2025-03-07)
- 添加 macOS DMG 安装包支持
- 支持 Intel (amd64) 和 Apple Silicon (arm64) 的通用二进制
- 修复了证书链完整性检查的逻辑错误
- 改进了证书链完整性的判断标准

### v1.0.5 (2025-03-07)
// ... existing code ...

### v1.0.4 (2024-03-07)
- 添加了读取本地PEM/CRT证书文件的功能
- 支持从单个文件或目录构建证书链
- 重构了证书导出功能

### v1.0.3 (2024-03-07)
- 添加了GitHub Actions CI/CD工作流
- 添加了自动构建和测试流程
- 添加了自动发布流程
- 添加了安全扫描工作流

### v1.0.2 (2024-03-07)
- 添加了RPM和DEB包构建支持
- 添加了Docker构建环境
- 添加了GoReleaser配置
- 添加了nFPM配置

### v1.0.1 (2024-03-07)
- 修复了证书类型识别问题
- 修复了未使用的导入包
- 优化了证书链完整性检查

### v1.0.0 (2023-10-01)
- 初始版本发布
- 支持RSA和ECC双证书下载和分析
- 支持证书导出为PEM格式

## 许可证

MIT 