#!/bin/bash

# DGTOTP-TLS 简易构建脚本
# 仅包含编译和生成证书功能（假设依赖已安装）

set -e  # 遇到错误立即退出

# 颜色输出（可选，让信息更清晰）
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. 创建并进入 build 目录
if [ -d "build" ]; then
    print_warning "build 目录已存在"
    read -p "是否清空并重新构建？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "清空 build 目录..."
        rm -rf build
    else
        print_info "使用现有 build 目录"
    fi
fi

if [ ! -d "build" ]; then
    mkdir build
    print_info "创建 build 目录"
fi

cd build

# 2. CMake 配置
print_info "运行 CMake 配置..."
cmake ..

# 3. 编译
print_info "编译项目..."
make -j$(nproc)

print_info "编译完成！"

# 4. 生成 SSL 证书
print_info "生成 SSL 证书..."

# 检查证书是否已存在
if [ -f "server.key" ] && [ -f "server.crt" ]; then
    print_warning "证书已存在"
    read -p "是否重新生成？(y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "使用现有证书"
        cd ..
        echo ""
        echo "========================================="
        echo "构建完成！"
        echo "运行方式："
        echo "  cd build && ./server    # 启动服务器"
        echo "  cd build && ./verifier  # 启动验证器"
        echo "  cd build && ./client    # 运行客户端"
        echo "========================================="
        exit 0
    fi
fi

# 生成私钥
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:3072
# 生成自签名证书
openssl req -new -x509 -key server.key -out server.crt -days 365 \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=localhost" \
    -addext "subjectAltName = DNS:localhost, IP:127.0.0.1"

print_info "证书生成完成：server.key 和 server.crt"

cd ..

# 完成提示
echo ""
echo "========================================="
echo "✓ 构建完成！"
echo "========================================="
echo ""
echo "运行方式："
echo "  1. 启动服务器：  cd build && ./server"
echo "  2. 启动验证器：  cd build && ./verifier"
echo "  3. 运行客户端：  cd build && ./client"
echo ""
echo "注意：请先启动服务器和验证器，再运行客户端"
echo "========================================="