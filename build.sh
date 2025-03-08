#!/bin/bash

# 确保脚本在错误时退出
set -e

echo "开始构建..."

# 创建必要的目录
mkdir -p assets/web

# 构建前端
echo "构建前端..."
cd web
npm install
npm run build
cd ..

# 构建后端
echo "构建后端..."
go mod tidy
go build -o ssl-chain-analyzer cmd/main.go

echo "构建完成！"
echo "运行方式: ./ssl-chain-analyzer [--port <端口号>]" 