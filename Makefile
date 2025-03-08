.PHONY: all build clean package

VERSION := 1.0.7
BINARY_NAME := ssl-chain-analyzer
BUILD_DIR := build

all: build

build:
	@echo "执行构建脚本..."
	./build.sh

clean:
	@echo "清理构建目录..."
	rm -rf $(BUILD_DIR)
	rm -rf assets/web
	rm -rf *.deb *.rpm
	rm -f ssl-chain-analyzer
	rm -rf certificates/

package: build
	@echo "创建打包目录..."
	mkdir -p $(BUILD_DIR)
	@echo "复制构建文件..."
	cp ssl-chain-analyzer $(BUILD_DIR)/
	cp -r assets $(BUILD_DIR)/
	chmod +x packaging/scripts/*.sh
	
	@echo "构建 DEB 包..."
	nfpm package \
		--config packaging/nfpm.yaml \
		--target $(BUILD_DIR) \
		--packager deb
	
	@echo "构建 RPM 包..."
	nfpm package \
		--config packaging/nfpm.yaml \
		--target $(BUILD_DIR) \
		--packager rpm

.PHONY: install
install:
	install -d $(DESTDIR)/usr/bin
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/lib/systemd/system
	install -m 644 packaging/systemd/ssl-chain-analyzer.service $(DESTDIR)/lib/systemd/system/
	install -d $(DESTDIR)/usr/share/ssl-chain-analyzer
	cp -r $(BUILD_DIR)/assets/web $(DESTDIR)/usr/share/ssl-chain-analyzer/ 