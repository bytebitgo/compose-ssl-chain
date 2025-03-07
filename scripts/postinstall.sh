#!/bin/bash

# 创建证书输出目录
mkdir -p /var/lib/ssl-chain-analyzer/certificates

# 设置权限
chmod 755 /usr/bin/ssl-chain-analyzer
chmod -R 755 /var/lib/ssl-chain-analyzer

echo "SSL Chain Analyzer 已成功安装！"
echo "使用方法: ssl-chain-analyzer -domain example.com" 