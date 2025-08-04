# DGTOTP C/C++ Implementation

这是DGTOTP（Dynamic Group Time-based One-Time Password）的C/C++实现版本，基于原Java项目功能进行移植。DGTOTP是一种基于时间的一次性密码协议，专为动态群组环境设计，提供匿名认证和成员撤销功能。

## 项目背景

DGTOTP协议结合了TOTP（基于时间的一次性密码）和群组签名技术，允许群组成员在不暴露自己身份的情况下证明自己是合法成员。同时，注册机构（RA）可以在必要时撤销成员权限或揭示成员身份。

## 项目结构

```
DGTOTP-C/
├── include/           # 头文件
│   ├── Parameter.h    # 系统参数定义
│   ├── ChameleonHash.h # 变色龙哈希实现
│   ├── DGTOTP_PRF.h   # 伪随机函数实现
│   ├── Member.h       # 成员类定义
│   ├── MerkleTrees.h  # Merkle树实现
│   ├── RA.h           # 注册机构实现
│   ├── TOTP.h         # TOTP协议实现
│   └── Verifier.h     # 验证者实现
├── src/              # 源代码文件
│   ├── Parameter.cpp
│   ├── ChameleonHash.cpp
│   ├── DGTOTP_PRF.cpp
│   ├── Member.cpp
│   ├── MerkleTrees.cpp
│   ├── RA.cpp
│   ├── TOTP.cpp
│   ├── Verifier.cpp
│   └── main.cpp      # 主程序入口
├── lib/              # 第三方库
├── CMakeLists.txt    # CMake构建文件
├── INSTALL.md        # 安装指南
└── README.md         # 项目说明
```

## 依赖库

- **OpenSSL**: 用于加密功能，替代Java中的BouncyCastle
  - 提供SHA256哈希函数
  - 提供AES加密/解密
  - 提供椭圆曲线操作
- **GMP**: GNU Multiple Precision Arithmetic Library，用于大整数运算
- **Crypto++**: 提供额外的密码学功能

## 编译方法

### 使用CMake编译

```bash
mkdir build
cd build
cmake ..
make
```

详细的安装和依赖配置说明请参考 [INSTALL.md](INSTALL.md)。

## 功能对应

本C/C++实现与原Java版本保持相同的功能和接口，包括：

- **TOTP (基于时间的一次性密码)**
  - 生成和验证基于时间的一次性密码
  - 支持可配置的时间窗口和密码长度

- **变色龙哈希 (Chameleon Hash)**
  - 基于椭圆曲线的变色龙哈希实现
  - 支持碰撞生成和验证

- **Merkle树实现**
  - 构建和验证Merkle树
  - 生成和验证包含证明

- **群组管理**
  - 成员加入和撤销
  - 群组密钥更新

- **成员验证**
  - 匿名身份验证
  - 身份揭示（由RA执行）

## 使用示例

```cpp
#include "Parameter.h"
#include "RA.h"
#include "Member.h"
#include "Verifier.h"

int main() {
    // 初始化系统
    RA::RASetup(128);
    
    // 获取当前时间
    long currentTime = getCurrentTimeMillis();
    
    // 更新群组管理消息
    RA::GMUpdate(currentTime);
    
    // 创建成员
    Member member;
    std::string memberId = "user1";
    
    // 成员加入
    std::vector<unsigned char*> memberKeys = RA::Join(nullptr, memberId, currentTime);
    member.PInit(memberKeys[0], memberKeys[1], currentTime);
    
    // 生成DGTOTP密码
    std::vector<std::string> password = member.PwGen(currentTime);
    
    // 验证DGTOTP密码
    int verifyResult = Verifier::Verify(password, currentTime);
    
    // 打开成员身份
    std::string openResult = RA::Open(password, currentTime);
    
    return 0;
}
```

## 实现细节

### 变色龙哈希

变色龙哈希是一种特殊的哈希函数，知道陷门信息的人可以找到碰撞。在DGTOTP中，它用于生成匿名但可验证的密码。

### Merkle树

Merkle树用于高效验证大量数据。在DGTOTP中，它用于验证群组成员的合法性。

### TOTP实现

TOTP基于HMAC算法，使用当前时间作为输入生成一次性密码。DGTOTP扩展了标准TOTP，增加了匿名性和群组管理功能。

## 与Java版本的区别

- 使用OpenSSL替代BouncyCastle进行加密操作
- 使用C++标准库的数据结构替代Java集合类
- 内存管理采用C++方式，需要手动释放资源
- 保持了相同的函数名和参数结构，便于代码对比和理解

## 许可证

请参考原项目的许可证信息。