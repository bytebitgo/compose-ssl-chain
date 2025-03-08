#!/bin/sh
set -e

# 创建系统用户和组
if ! getent group ssl-chain >/dev/null; then
    groupadd -r ssl-chain
fi

if ! getent passwd ssl-chain >/dev/null; then
    useradd -r -g ssl-chain -d /var/lib/ssl-chain-analyzer -s /sbin/nologin -c "SSL Chain Analyzer Service" ssl-chain
fi

# 创建必要的目录
mkdir -p /var/lib/ssl-chain-analyzer
mkdir -p /var/log/ssl-chain-analyzer
chown -R ssl-chain:ssl-chain /var/lib/ssl-chain-analyzer
chown -R ssl-chain:ssl-chain /var/log/ssl-chain-analyzer

exit 0 