#!/bin/sh
set -e

# 如果系统正在运行（不是在 chroot 环境中），则停止服务
if [ -d /run/systemd/system ]; then
    systemctl stop ssl-chain-analyzer.service
    systemctl disable ssl-chain-analyzer.service
fi

exit 0 