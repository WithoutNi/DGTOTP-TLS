#include <chrono>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include "DGTOTP.h"
#include "util.h"

long getCurrentTimeMillis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

void testDGTOTP(int instanceCount)
{
    std::cout << "Initialize DGTOTP system..." << std::endl;

    const int k = 128;
    const std::string groupName = "DGTOTP";
    const int groupMemberCount = 4;
    const int verificationPeriod = 300000;
    const int passwordGenerationPeriod = 5000;

    if (instanceCount <= 0)
    {
        std::cout << "Instance count must be greater than 0, current value: "
                  << instanceCount << std::endl;
        return;
    }

    std::vector<DGTOTP> dgtotpVec(instanceCount);
    std::vector<std::string> memberIdVec;
    memberIdVec.reserve(instanceCount);
    const long sharedStartTime = getSharedProtocolStartTimeMillis();
    const long endTime = sharedStartTime + EPOCH_COUNT * verificationPeriod;

    for (int idx = 0; idx < instanceCount; idx++)
    {
        std::string memberId = "user" + std::to_string(idx + 1);
        memberIdVec.push_back(memberId);

        dgtotpVec[idx].RASetup(k, groupName, groupMemberCount, sharedStartTime, endTime,
                               verificationPeriod, passwordGenerationPeriod);
        dgtotpVec[idx].PInit(memberId);
    }

    for (int idx = 0; idx < instanceCount; idx++)
    {
        DGTOTP &dgtotp = dgtotpVec[idx];
        const std::string &memberId = memberIdVec[idx];

        std::cout << "===== Instance " << (idx + 1) << " =====" << std::endl;
        std::cout << "RA setup complete, group public key: "
                  << dgtotp.getRA().getGpk() << std::endl;

        long currentTime = getCurrentTimeMillis();
        std::cout << "Current timestamp: " << currentTime << std::endl;

        std::cout << "----Join Result:----" << std::endl;
        dgtotp.Join(memberId, currentTime);
        std::cout << "ID of the joined member: " << memberId << std::endl;
        std::cout << "Join runs successfully" << std::endl;
        std::cout << std::endl;

        std::cout << "----GetSD Result:----" << std::endl;
        std::string secretSeed = dgtotp.GetSD(memberId, currentTime);
        std::cout << "Secret seed: " << secretSeed << std::endl;
        std::cout << std::endl;

        std::cout << "----PwGen Result:----" << std::endl;
        DGTOTP::Password password = dgtotp.PwGen(memberId, currentTime);
        std::cout << "TOTP password: " << string_to_hex(password.totp_password) << std::endl;
        std::cout << "Chameleon hash collision: "
                  << string_to_hex(password.collision_randomness) << std::endl;
        std::cout << "Identity ciphertext: "
                  << string_to_hex(password.identity_ciphertext) << std::endl;
        std::cout << std::endl;

        std::cout << "----Verify Result:----" << std::endl;
        int verifyResult = dgtotp.Verify(password, currentTime);
        std::cout << "Verify result for the correct password and verify epoch: "
                  << (verifyResult == 1 ? "success" : "failure") << std::endl;
        std::cout << std::endl;

        std::cout << "----Open Result:----" << std::endl;
        std::string openResult = dgtotp.Open(password, currentTime);
        std::cout << "Open ID for the correct password and verify epoch: "
                  << openResult << std::endl;
        std::cout << std::endl;

        std::cout << "----Revoke Result:----" << std::endl;
        int revokeResult = dgtotp.Revoke(memberId);
        std::cout << "Revoke registered member " << memberId
                  << (revokeResult == 1 ? " success" : " failure") << std::endl;
        std::cout << std::endl;
    }
}

int main()
{
    std::cout << "DGTOTP C++ implementation test program" << std::endl;
    std::cout << "========================" << std::endl;

    try
    {
        int instanceCount = 2;
        testDGTOTP(instanceCount);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "Unknown error occurred" << std::endl;
        return 1;
    }

    std::cout << "Test completed" << std::endl;
    return 0;
}
