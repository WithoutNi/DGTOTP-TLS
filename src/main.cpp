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
void testDGTOTP(int instanceCount)
{
    std::cout << "初始化DGTOTP系统..." << std::endl;

    // 设置安全参数
    int k = 128;

    if (instanceCount <= 0)
    {
        std::cout << "实例数量需大于0，当前值: " << instanceCount << std::endl;
        return;
    }

    // 按可变参数创建多套实例
    std::vector<Parameter> paramsVec(instanceCount);
    std::vector<RA> raVec(instanceCount);
    std::vector<Member> memberVec(instanceCount);
    std::vector<std::string> memberIdVec;
    memberIdVec.reserve(instanceCount);

    for (int idx = 0; idx < instanceCount; idx++)
    {
        paramsVec[idx].init();
        std::string memberId = "uer" + std::to_string(idx + 1);
        memberIdVec.push_back(memberId);

        raVec[idx].RASetup(k, paramsVec[idx].getG(), paramsVec[idx].getU(),
                           paramsVec[idx].getStartTime(), paramsVec[idx].getEndTime(),
                           paramsVec[idx].getDeltaE(), paramsVec[idx].getDeltaS());
        memberVec[idx].PInit(memberId, paramsVec[idx]);
    }

    for (int idx = 0; idx < instanceCount; idx++)
    {
        Parameter &params = paramsVec[idx];
        RA &ra = raVec[idx];
        Member &member = memberVec[idx];
        const std::string &memberId = memberIdVec[idx];

        std::cout << "===== 实例 " << (idx + 1) << " =====" << std::endl;
        std::cout << "RA设置完成，群组公钥: " << ra.getGpk() << std::endl;

        long currentTime = getCurrentTimeMillis();
        std::cout << "当前时间戳: " << currentTime << std::endl;

        // Join
        std::cout << "----Join Result:----" << std::endl;
        std::vector<unsigned char *> Ax = ra.Join(nullptr, memberId, currentTime);
        std::cout << "ID of the join member: " << member.getID() << std::endl;
        std::cout << "Ks of the join member: ";
        printBytes(Ax[0], 16);
        std::cout << std::endl;
        std::cout << "Alpha ID of the join member: ";
        printBytes(Ax[1], 4);
        std::cout << std::endl
                  << std::endl;

        // PwGen
        std::cout << "----PwGen Result:----" << std::endl;
        std::vector<std::string> password = member.PwGen(Ax, currentTime, params);
        std::cout << "TOTP password: " << password[0] << std::endl;
        std::cout << "Chameleon Hash collision: " << string_to_hex(password[1]) << std::endl;
        std::cout << "Identity ciphertext: " << string_to_hex(password[2]) << std::endl;
        std::cout << std::endl;

        // GMUpdate
        std::cout << "----GMUpdate Result:----" << std::endl;
        ra.GMUpdate(params.getStartTime(), params);
        std::cout << "GMUpdate runs successfully" << std::endl;
        std::cout << std::endl;

        // Verify
        std::cout << "----Verify Result:----" << std::endl;
        Verifier verifier;
        int verifyResult = verifier.Verify(password, currentTime, params);
        std::cout << "Verify result for the correct password and verify epoch: "
                  << (verifyResult == 1 ? "success" : "failure") << std::endl;
        std::cout << std::endl;

        // Open
        std::cout << "----Open Result:----" << std::endl;
        std::string openResult = ra.Open(password, currentTime, params);
        std::cout << "Open ID for the correct password and verify epoch: " << openResult << std::endl;
        std::cout << std::endl;

        // Revoke
        std::cout << "----Revoke Result:----" << std::endl;
        int revokeResult = ra.Revoke(memberId, nullptr);
        std::cout << "Revoke registered member " << memberId << (revokeResult == 1 ? " success" : " failure") << std::endl;
        std::cout << std::endl;

        free(Ax[0]);
        free(Ax[1]);
    }

    for (int idx = 0; idx < instanceCount; idx++)
    {
        raVec[idx].cleanup();
        paramsVec[idx].cleanup();
    }
}

int main()
{
    std::cout << "DGTOTP C++ 实现测试程序" << std::endl;
    std::cout << "========================" << std::endl;

    try
    {
        int instanceCount = 2;
        testDGTOTP(instanceCount);
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
