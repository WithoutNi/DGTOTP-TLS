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
#include "util.h"

// 辅助函数：获取当前时间戳（毫秒）
long getCurrentTimeMillis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

// 测试DGTOTP系统
void testDGTOTP()
{
    std::cout << "初始化DGTOTP系统..." << std::endl;

    // 设置安全参数
    int k = 128;

    // 初始化RA
    std::vector<RA> RAVec;
    for (int i = 0; i < 1; i++)
    {
        RA RAi;
        Parameter::init();
        RAi.RASetup(k, Parameter::G, Parameter::U, Parameter::START_TIME, Parameter::END_TIME, Parameter::Δe, Parameter::Δs);
        RAVec.push_back(RAi);
    }
    std::cout << "first RA instance设置完成，群组公钥: " << RAVec[0].getGpk() << std::endl;

    // 获取当前时间
    long currentTime = getCurrentTimeMillis();
    std::cout << "当前时间戳: " << currentTime << std::endl;

    // 创建成员
    Member member1;
    std::string memberId = "uer1";

    member1.PInit(memberId);

    // 成员加入
    std::cout << "----Join Result:----" << std::endl;
    std::vector<unsigned char *> Ax = RAVec[0].Join(nullptr, memberId, currentTime);
    std::cout << "ID of the join member: " << member1.ID_MENBER << std::endl;
    std::cout << "Ks of the join member: ";
    printBytes(Ax[0], 16);
    std::cout << std::endl; // 假设16字节
    std::cout << "Alpha ID of the join member: ";
    printBytes(Ax[1], 4);
    std::cout << std::endl; // 假设4字节
    std::cout << std::endl;

    // 生成DGTOTP密码
    std::cout << "----PwGen Result:----" << std::endl;
    std::vector<std::string> password = member1.PwGen(Ax, currentTime); // 修改为无参数的PwGen
    std::cout << "TOTP password: " << password[0] << std::endl;
    std::cout << "Chameleon Hash collision: " << string_to_hex(password[1]) << std::endl;
    std::cout << "Identity ciphertext: " << string_to_hex(password[2]) << std::endl;
    std::cout << std::endl;

    // 更新群组管理消息
    std::cout << "----GMUpdate Result:----" << std::endl;
    RAVec[0].GMUpdate(Parameter::START_TIME);
    std::cout << "GMUpdate runs successfully" << std::endl;
    std::cout << std::endl;

    // 验证DGTOTP密码
    std::cout << "----Verify Result:----" << std::endl;
    Verifier verifier;
    int verifyResult = verifier.Verify(password, currentTime);
    std::cout << "Verify result for the correct password and verify epoch: " << (verifyResult == 1 ? "success" : "failure") << std::endl;
    std::cout << std::endl;

    // 打开成员身份
    std::cout << "----Open Result:----" << std::endl;
    std::string openResult = RAVec[0].Open(password, currentTime);
    std::cout << "Open ID for the correct password and verify epoch: " << openResult << std::endl;
    std::cout << std::endl;

    // 测试撤销
    std::cout << "----Revoke Result:----" << std::endl;
    int revokeResult = RAVec[0].Revoke(memberId, nullptr);
    std::cout << "Revoke registered member " << memberId << (revokeResult == 1 ? " success" : " failure") << std::endl;

    // 释放资源
    free(Ax[0]);
    free(Ax[1]);
    for (int i = 0; i < RAVec.size(); i++)
    {
        RAVec[i].cleanup();
    }
}

int main()
{
    std::cout << "DGTOTP C++ 实现测试程序" << std::endl;
    std::cout << "========================" << std::endl;

    try
    {
        testDGTOTP();
        Parameter::cleanup();
        ChameleonHash::cleanup();
    }
    catch (const std::exception &e)
    {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "发生未知错误" << std::endl;
        return 1;
    }

    std::cout << "测试完成" << std::endl;
    return 0;
}