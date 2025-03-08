#!/bin/bash

# 创建必要的目录
mkdir -p assets/icon.iconset

# 从 SVG 生成不同尺寸的 PNG
for size in 16 32 64 128 256 512 1024; do
  rsvg-convert -w $size -h $size assets/icon.svg > assets/icon.iconset/icon_${size}x${size}.png
  if [ $size -le 512 ]; then
    rsvg-convert -w $((size*2)) -h $((size*2)) assets/icon.svg > assets/icon.iconset/icon_${size}x${size}@2x.png
  fi
done

# 使用 iconutil 创建 icns 文件
iconutil -c icns assets/icon.iconset

# 清理临时文件
rm -rf assets/icon.iconset 