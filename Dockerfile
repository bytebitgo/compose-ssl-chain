FROM golang:1.21-alpine AS builder

WORKDIR /app

# 安装构建依赖
RUN apk add --no-cache git

# 复制Go模块定义
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ssl-chain-analyzer ./cmd

# 使用轻量级的基础镜像
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# 从构建阶段复制二进制文件
COPY --from=builder /app/ssl-chain-analyzer .

# 创建证书输出目录
RUN mkdir -p /var/lib/ssl-chain-analyzer/certificates

# 设置时区
ENV TZ=Asia/Shanghai

# 设置入口点
ENTRYPOINT ["./ssl-chain-analyzer"]

# 默认命令
CMD ["-help"] 