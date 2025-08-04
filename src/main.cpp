#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include "Parameter.h"
#include "ChameleonHash.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include "RA.h"
#include "Verifier.h"
#include "DGTOTP_PRF.h"

// 辅助函数：获取当前时间戳（毫秒）
long getCurrentTimeMillis() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

// 测试DGTOTP系统
void testDGTOTP() {
    std::cout << "初始化DGTOTP系统..." << std::endl;
    
    // 设置安全参数
    int k = 128;
    
    // 初始化RA
    RA ra; // 创建RA实例
    ra.RASetup(k);
    std::cout << "RA设置完成，群组公钥: " << ra.gpk << std::endl; // 假设有getGPK方法
    
    // 获取当前时间
    long currentTime = getCurrentTimeMillis();
    std::cout << "当前时间戳: " << currentTime << std::endl;
    
    // 更新群组管理消息
    ra.GMUpdate(currentTime);
    std::cout << "群组管理消息已更新" << std::endl;
    
    // 创建成员
    Member member1;
    std::string memberId = "user1";
    
    // 成员加入
    std::vector<unsigned char*> memberKeys = ra.Join(nullptr, memberId, currentTime);
    member1.PInit(memberId); // 修改为匹配的PInit函数
    std::cout << "成员 " << memberId << " 已加入" << std::endl;
    
    // 生成DGTOTP密码
    std::vector<std::string> password = member1.PwGen(memberKeys,currentTime); // 修改为无参数的PwGen
    std::cout << "生成的DGTOTP密码:" << std::endl;
    std::cout << "验证点: " << password[0] << std::endl;
    std::cout << "随机数: " << password[1] << std::endl;
    std::cout << "密文: " << password[2] << std::endl;
    
    // 验证DGTOTP密码
    Verifier verifier;
    int verifyResult = verifier.Verify(password, currentTime);
    std::cout << "验证结果: " << (verifyResult == 1 ? "成功" : "失败") << std::endl;
    
    // 打开成员身份
    std::string openResult = ra.Open(password, currentTime);
    std::cout << "打开的成员身份: " << openResult << std::endl;
    
    // 测试撤销
    int revokeResult = ra.Revoke(memberId, nullptr);
    std::cout << "撤销结果: " << (revokeResult == 1 ? "成功" : "失败") << std::endl;
    
    // 释放资源
    free(memberKeys[0]);
    free(memberKeys[1]);
}

int main() {
    std::cout << "DGTOTP C++ 实现测试程序" << std::endl;
    std::cout << "========================" << std::endl;
    
    try {
        testDGTOTP();
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "发生未知错误" << std::endl;
        return 1;
    }
    
    std::cout << "测试完成" << std::endl;
    return 0;
}