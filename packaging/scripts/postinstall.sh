#!/bin/sh
set -e

# 重新加载 systemd 配置
systemctl daemon-reload

# 启用服务
systemctl enable ssl-chain-analyzer.service

# 如果系统正在运行（不是在 chroot 环境中），则启动服务
if [ -d /run/systemd/system ]; then
    systemctl start ssl-chain-analyzer.service
fi

exit 0 