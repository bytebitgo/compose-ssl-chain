#!/bin/bash

# 构建Docker镜像
docker build -t ssl-chain-analyzer-builder -f Dockerfile.build .

# 创建输出目录
mkdir -p dist

# 运行构建容器
docker run --rm -v $(pwd)/dist:/app/dist ssl-chain-analyzer-builder

echo "构建完成，包文件在 dist 目录中" 