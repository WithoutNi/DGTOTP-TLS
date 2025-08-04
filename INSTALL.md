# DGTOTP-C 安装和使用指南

本文档提供了如何编译、安装和使用DGTOTP-C库的详细说明。

## 依赖项

DGTOTP-C依赖以下库：

1. **OpenSSL** - 用于加密操作
2. **GMP** - GNU多精度算术库，用于大数运算
3. **Crypto++** - 用于一些加密操作

### 在Windows上安装依赖项

#### 使用vcpkg安装依赖项

```powershell
# 安装vcpkg（如果尚未安装）
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat

# 安装依赖项
.\vcpkg install openssl:x64-windows
.\vcpkg install gmp:x64-windows
.\vcpkg install cryptopp:x64-windows

# 集成到Visual Studio（可选）
.\vcpkg integrate install
```

### 在Linux上安装依赖项

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install libssl-dev libgmp-dev libcrypto++-dev

# Fedora/RHEL/CentOS
sudo dnf install openssl-devel gmp-devel cryptopp-devel
```

## 编译

### 使用CMake编译

```bash
# 创建构建目录
mkdir build
cd build

# 配置项目
cmake ..

# 编译
cmake --build .
```

### 在Windows上使用Visual Studio编译

1. 打开Visual Studio
2. 选择"打开本地文件夹"并选择DGTOTP-C目录
3. Visual Studio将自动检测CMakeLists.txt并配置项目
4. 点击"生成"菜单中的"生成全部"选项

## 运行

编译完成后，可以运行生成的可执行文件：

```bash
# 在Linux/macOS上
./dgtotp

# 在Windows上
.\Debug\dgtotp.exe  # 或 .\Release\dgtotp.exe
```

## 库的使用

要在自己的项目中使用DGTOTP-C库，请包含相应的头文件并链接到编译好的库：

```cpp
#include "Parameter.h"
#include "ChameleonHash.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include "RA.h"
#include "Verifier.h"
#include "DGTOTP_PRF.h"

int main() {
    // 初始化系统
    RA::RASetup(128);
    
    // 创建成员
    Member member;
    std::vector<unsigned char*> memberKeys = RA::Join(nullptr, "user1", getCurrentTimeMillis());
    member.PInit(memberKeys[0], memberKeys[1], getCurrentTimeMillis());
    
    // 生成密码
    std::vector<std::string> password = member.PwGen(getCurrentTimeMillis());
    
    // 验证密码
    int result = Verifier::Verify(password, getCurrentTimeMillis());
    
    return 0;
}
```

## 故障排除

### 常见问题

1. **找不到库文件**
   - 确保所有依赖库都已正确安装
   - 检查CMake配置是否正确指向了库文件位置

2. **编译错误**
   - 确保使用C++11或更高版本
   - 检查是否有缺失的头文件或依赖项

3. **运行时错误**
   - 检查是否所有必要的初始化步骤都已完成
   - 确保参数设置正确

### 调试提示

- 使用`-DCMAKE_BUILD_TYPE=Debug`选项进行调试构建
- 在代码中添加适当的日志输出以跟踪执行流程

## 许可证

请参阅项目根目录中的LICENSE文件了解许可证信息。