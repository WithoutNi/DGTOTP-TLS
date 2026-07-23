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
if [ -f "RA.key" ] && [ -f "RA.crt" ]; then
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
        echo "  cd build && ./server_RA    # 启动服务器"
        echo "  cd build && ./server_AS    # 启动认证服务器"
        echo "  cd build && ./verifier  # 启动验证器"
        echo "  cd build && ./client    # 运行客户端"
        echo "========================================="
        exit 0
    fi
fi

# Generate CA private key
openssl ecparam -name prime256v1 -genkey -noout -out ca.key

# Generate self-signed CA certificate
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=DGTOTP_Root_CA"

# Generate RA private key
openssl ecparam -name prime256v1 -genkey -noout -out RA.key

# Generate RA Certificate Signing Request (CSR)
openssl req -new -key RA.key -out RA.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=localhost"

# Sign RA CSR using the CA certificate and key (includes localhost/127.0.0.1 SAN)
openssl x509 -req -in RA.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out RA.crt -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Generate AS private key
openssl ecparam -name prime256v1 -genkey -noout -out AS.key

# Generate AS Certificate Signing Request (CSR)
openssl req -new -key AS.key -out AS.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=localhost"

# Sign AS CSR using the CA certificate and key (includes localhost/127.0.0.1 SAN)
openssl x509 -req -in AS.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out AS.crt -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Generate Verifier private key
openssl ecparam -name prime256v1 -genkey -noout -out verifier.key

# Generate Verifier Certificate Signing Request (CSR)
openssl req -new -key verifier.key -out verifier.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=localhost"

# Sign Verifier CSR using the CA certificate and key (adding SAN)
openssl x509 -req -in verifier.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out verifier.crt -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

rm RA.csr AS.csr verifier.csr ca.srl

cd ..

# 完成提示
echo ""
echo "========================================="
echo "✓ 构建完成！"
echo "========================================="
echo ""
echo "运行方式："
echo "  1. 启动注册机构：  cd build && ./server_RA"
echo "  2. 启动认证验证器：  cd build && ./server_AS"
echo "  3. 启动验证器：  cd build && ./verifier"
echo "  4. 运行客户端：  cd build && ./client"
echo ""
echo "========================================="