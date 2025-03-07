VERSION := 1.0.3
BINARY := ssl-chain-analyzer
PLATFORMS := linux darwin
ARCHITECTURES := amd64 arm64

.PHONY: all build clean package

all: build

build:
	go build -o $(BINARY) ./cmd

# 交叉编译
cross-build:
	@for platform in $(PLATFORMS); do \
		for arch in $(ARCHITECTURES); do \
			echo "Building for $$platform/$$arch..."; \
			GOOS=$$platform GOARCH=$$arch go build -o $(BINARY)_$${platform}_$${arch} ./cmd; \
		done; \
	done

# 清理
clean:
	rm -f $(BINARY)
	rm -f $(BINARY)_*
	rm -f *.deb *.rpm

# 安装nFPM
install-nfpm:
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

# 打包
package: build install-nfpm
	nfpm package --target ./ --packager deb
	nfpm package --target ./ --packager rpm

# 交叉编译并打包
package-all: cross-build install-nfpm
	BINARY=$(BINARY)_linux_amd64 nfpm package --target ./ --packager deb
	BINARY=$(BINARY)_linux_amd64 nfpm package --target ./ --packager rpm

# 测试
test:
	go test -v ./...

# 运行
run:
	go run ./cmd/main.go 