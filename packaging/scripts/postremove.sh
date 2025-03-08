#!/bin/sh
set -e

# 重新加载 systemd 配置
systemctl daemon-reload

# 清理用户和组（仅在完全卸载时）
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
    # 删除日志和数据目录
    rm -rf /var/log/ssl-chain-analyzer
    rm -rf /var/lib/ssl-chain-analyzer

    # 删除用户和组
    if getent passwd ssl-chain >/dev/null; then
        userdel -r ssl-chain
    fi
    if getent group ssl-chain >/dev/null; then
        groupdel ssl-chain
    fi
fi

exit 0 