#include "AS.h"

/// Add Confirmation Key
void AS::AddConfkey(const ConfKey &confKey)
{
    AST.KConfL[confKey.SGId].push_back(confKey);
}

/// Add Password Usage Record
void AS::AddPURec(const PwUsageRecord &pwUsageRecord)
{
    AST.PURecL[pwUsageRecord.SGId].push_back(pwUsageRecord);
}

/// Query Confirmation Keys by SGId
ConfKeyList AS::QueryConfKeyListBySGId(int SGId) const
{
    if (SGId < 0 || SGId >= (int)AST.KConfL.size())
    {
        return ConfKeyList(); // Return empty list
    }
    return AST.KConfL[SGId];
}

/// Query Password Usage Records by SGId
PwUsageRecordList AS::QueryPwUsageRecordListBySGId(int SGId) const
{
    if (SGId < 0 || SGId >= (int)AST.PURecL.size())
    {
        return PwUsageRecordList(); // Return empty list
    }
    return AST.PURecL[SGId];
}

/// Check password usage record existence and insert if not exists
bool AS::CheckAndAddPURec(const PwUsageRecord &pwUsageRecord)
{
    int sgId = pwUsageRecord.SGId;

    // Check if already exists in the corresponding SGId list
    for (const auto &item : AST.PURecL[sgId])
    {
        // Only UCM is needed for deduplication (SGId is already implied)
        if (item.UCM == pwUsageRecord.UCM)
        {
            return false; // already exists
        }
    }

    AST.PURecL[sgId].push_back(pwUsageRecord);
    return true;
}

/// Set the local state of the authentication server
void AS::SetLocalState(const std::string &pk_AS, const std::string &sk_AS)
{
    LSt.pk_AS = pk_AS;
    LSt.sk_AS = sk_AS;
}

void AS::InitAuthState(int I)
{
    AST.KConfL.clear();
    AST.KConfL.resize(I);
    AST.PURecL.clear();
    AST.PURecL.resize(I);
}