#include "DGTOTP.h"

#include <algorithm>
#include <cstdlib>
#include <stdexcept>

std::vector<std::string> DGTOTP::Password::toVector() const
{
    std::vector<std::string> password(3);
    password[0] = totp_password;
    password[1] = collision_randomness;
    password[2] = identity_ciphertext;
    return password;
}

DGTOTP::Password DGTOTP::Password::fromVector(const std::vector<std::string> &password)
{
    if (password.size() != 3)
    {
        throw std::invalid_argument("DGTOTP password must contain exactly 3 fields");
    }

    Password result;
    result.totp_password = password[0];
    result.collision_randomness = password[1];
    result.identity_ciphertext = password[2];
    return result;
}

DGTOTP::MemberMaterials::~MemberMaterials()
{
    resetJoinReceipt();
}

void DGTOTP::MemberMaterials::resetJoinReceipt()
{
    for (size_t i = 0; i < join_receipt.size(); ++i)
    {
        if (join_receipt[i] != nullptr)
        {
            free(join_receipt[i]);
            join_receipt[i] = nullptr;
        }
    }
    join_receipt.clear();
    joined = false;
}

DGTOTP::DGTOTP()
{
}

DGTOTP::~DGTOTP()
{
    clearState();
}

void DGTOTP::RASetup(int security_parameter, const std::string &group_name,
                     int group_member_count, long start_time, long end_time,
                     int verification_period, int password_generation_period)
{
    clearState();

    params.init(group_name, start_time);
    params.setK(security_parameter);
    params.setU(group_member_count);
    params.setStartTime(start_time);
    params.setEndTime(end_time);
    params.setDeltaE(verification_period);
    params.setDeltaS(password_generation_period);

    if (verification_period > 0)
    {
        params.setE(static_cast<int>((end_time - start_time) / verification_period));
    }
    if (password_generation_period > 0)
    {
        params.setN(verification_period / password_generation_period);
    }

    ra.RASetup(security_parameter, group_name, group_member_count, start_time,
               end_time, verification_period, password_generation_period);
    isSetup = true;
    hasRAState = true;
}

void DGTOTP::ImportParameters(int security_parameter, const std::string &group_name,
                              int group_member_count, long start_time, long end_time,
                              int verification_period, int password_generation_period)
{
    clearState();

    params.init(group_name, start_time);
    params.setK(security_parameter);
    params.setU(group_member_count);
    params.setStartTime(start_time);
    params.setEndTime(end_time);
    params.setDeltaE(verification_period);
    params.setDeltaS(password_generation_period);

    if (verification_period > 0)
    {
        params.setE(static_cast<int>((end_time - start_time) / verification_period));
    }
    if (password_generation_period > 0)
    {
        params.setN(verification_period / password_generation_period);
    }

    isSetup = true;
    hasRAState = false;
}

void DGTOTP::PInit(const std::string &member_id)
{
    ensureSetup();

    std::unique_ptr<MemberMaterials> memberMatarials(new MemberMaterials());
    memberMatarials->member.PInit(member_id, params);
    memberIdToMaterialsMap[member_id] = std::move(memberMatarials);
}

void DGTOTP::Join(const std::string &member_id, long time)
{
    ensureSetup();
    MemberMaterials &memberMaterials = requireMaterials(member_id);

    memberMaterials.resetJoinReceipt();
    memberMaterials.join_receipt = ra.Join(nullptr, member_id, time);
    memberMaterials.joined = true;
}

DGTOTP::JoinReceipt DGTOTP::JoinAndExportReceipt(const std::string &member_id, long time)
{
    Join(member_id, time);

    MemberMaterials &memberMaterials = requireMaterials(member_id);
    if (memberMaterials.join_receipt.size() != 2 ||
        memberMaterials.join_receipt[0] == nullptr ||
        memberMaterials.join_receipt[1] == nullptr)
    {
        throw std::runtime_error("Join receipt is incomplete for member: " + member_id);
    }

    JoinReceipt receipt;
    receipt.shared_key.assign(memberMaterials.join_receipt[0],
                              memberMaterials.join_receipt[0] + 16);
    receipt.alpha_bytes.assign(memberMaterials.join_receipt[1],
                               memberMaterials.join_receipt[1] + 4);
    return receipt;
}

void DGTOTP::ImportJoinReceipt(const std::string &member_id, const JoinReceipt &receipt)
{
    ensureSetup();
    MemberMaterials &memberMaterials = requireMaterials(member_id);

    if (receipt.shared_key.size() != 16 || receipt.alpha_bytes.size() != 4)
    {
        throw std::invalid_argument("Join receipt must contain a 16-byte key and a 4-byte alpha");
    }

    memberMaterials.resetJoinReceipt();

    unsigned char *shared_key = static_cast<unsigned char *>(malloc(receipt.shared_key.size()));
    unsigned char *alpha_bytes = static_cast<unsigned char *>(malloc(receipt.alpha_bytes.size()));
    if (shared_key == nullptr || alpha_bytes == nullptr)
    {
        free(shared_key);
        free(alpha_bytes);
        throw std::bad_alloc();
    }

    std::copy(receipt.shared_key.begin(), receipt.shared_key.end(), shared_key);
    std::copy(receipt.alpha_bytes.begin(), receipt.alpha_bytes.end(), alpha_bytes);

    memberMaterials.join_receipt.push_back(shared_key);
    memberMaterials.join_receipt.push_back(alpha_bytes);
    memberMaterials.joined = true;
}

std::string DGTOTP::GetSD(const std::string &member_id, long time)
{
    ensureSetup();
    MemberMaterials &memberMaterials = requireMaterials(member_id);

    unsigned char *sd = memberMaterials.member.GetSD(nullptr, time, params);
    std::string secret_seed = Member::byte2hex(sd, 32);
    free(sd);
    return secret_seed;
}

DGTOTP::Password DGTOTP::PwGen(const std::string &member_id, long time)
{
    ensureSetup();
    MemberMaterials &memberMaterials = requireMaterials(member_id);

    if (!memberMaterials.joined)
    {
        throw std::runtime_error("Join must be called before PwGen");
    }

    return Password::fromVector(memberMaterials.member.PwGen(memberMaterials.join_receipt, time, params));
}

int DGTOTP::Verify(const Password &password, long time)
{
    ensureSetup();
    return verifier.Verify(password.toVector(), time, params);
}

int DGTOTP::Revoke(const std::string &member_id)
{
    ensureSetup();
    return ra.Revoke(member_id, nullptr);
}

std::string DGTOTP::Open(const Password &password, long time)
{
    ensureSetup();
    return ra.Open(password.toVector(), time, params);
}

const Parameter &DGTOTP::getParameter() const
{
    return params;
}

const RA &DGTOTP::getRA() const
{
    return ra;
}

DGTOTP::MemberMaterials &DGTOTP::requireMaterials(const std::string &member_id)
{
    std::map<std::string, std::unique_ptr<MemberMaterials>>::iterator it =
        memberIdToMaterialsMap.find(member_id);
    if (it == memberIdToMaterialsMap.end())
    {
        throw std::runtime_error("Member session not initialized: " + member_id);
    }
    return *(it->second);
}

void DGTOTP::ensureSetup() const
{
    if (!isSetup)
    {
        throw std::runtime_error("RASetup or ImportParameters must be called before using DGTOTP");
    }
}

void DGTOTP::refreshPublishedState(long time)
{
    ra.GMUpdate(time, params);
}

void DGTOTP::clearState()
{
    memberIdToMaterialsMap.clear();

    if (isSetup)
    {
        if (hasRAState)
        {
            ra.cleanup();
        }
        params.cleanup();
        isSetup = false;
        hasRAState = false;
    }
}
