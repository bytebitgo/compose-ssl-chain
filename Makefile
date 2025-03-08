VERSION := 1.0.6
BINARY := ssl-chain-analyzer
PLATFORMS := linux darwin
ARCHITECTURES := amd64 arm64

.PHONY: all build clean package package-macos

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
	rm -f *.deb *.rpm *.dmg
	rm -rf certificates/
	rm -rf dist/

# 安装nFPM
install-nfpm:
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

# 安装gon (macOS签名和打包工具)
install-gon:
	go install github.com/mitchellh/gon/cmd/gon@latest

# 打包
package: build install-nfpm
	mkdir -p dist
	nfpm package -p deb -t ./dist
	nfpm package -p rpm -t ./dist

# macOS打包
package-macos: build install-gon
	mkdir -p dist
	# 为 amd64 构建
	GOOS=darwin GOARCH=amd64 go build -o ./dist/$(BINARY)_darwin_amd64 ./cmd
	# 为 arm64 构建
	GOOS=darwin GOARCH=arm64 go build -o ./dist/$(BINARY)_darwin_arm64 ./cmd
	# 创建通用二进制
	lipo -create ./dist/$(BINARY)_darwin_amd64 ./dist/$(BINARY)_darwin_arm64 -output ./dist/$(BINARY)
	# 使用 create-dmg 创建 DMG
	create-dmg \
		--volname "$(BINARY) Installer" \
		--volicon "assets/icon.icns" \
		--window-pos 200 120 \
		--window-size 800 400 \
		--icon-size 100 \
		--icon "$(BINARY)" 200 190 \
		--hide-extension "$(BINARY)" \
		--app-drop-link 600 185 \
		"./dist/$(BINARY)-$(VERSION).dmg" \
		"./dist/$(BINARY)"

# 交叉编译并打包所有平台
package-all: cross-build install-nfpm install-gon
	mkdir -p dist
	BINARY=$(BINARY)_linux_amd64 nfpm package -p deb -t ./dist
	BINARY=$(BINARY)_linux_amd64 nfpm package -p rpm -t ./dist
	$(MAKE) package-macos

# 测试
test:
	go test -v ./...

# 运行
run:
	go run ./cmd/main.go 