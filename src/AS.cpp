#include "AS.h"

/// Add Confirmation Key
void AS::AddConfkey(const ConfKey &confKey)
{
    ast.KConfL.push_back(confKey);
}

/// Add Password Usage Record
void AS::AddPURec(const PwUsageRecord &pwUsageRecord)
{
    ast.PURecL.push_back(pwUsageRecord);
}

/// Query Confirmation Keys by SGId
ConfKeyList AS::QueryConfKeyListBySGId(int SGId) const
{
    ConfKeyList result;
    for (const auto &item : ast.KConfL)
    {
        if (item.SGId == SGId)
        {
            result.push_back(item);
        }
    }
    return result;
}

/// Query Password Usage Records by SGId
PwUsageRecordList AS::QueryPwUsageRecordListBySGId(int SGId) const
{
    PwUsageRecordList result;
    for (const auto &item : ast.PURecL)
    {
        if (item.SGId == SGId)
        {
            result.push_back(item);
        }
    }
    return result;
}

/// Check password usage record existence and insert if not exists
bool AS::CheckAndAddPURec(const PwUsageRecord &pwUsageRecord)
{
    for (const auto &item : ast.PURecL)
    {
        // Only SGId and UCM are used for deduplication
        if (item.SGId == pwUsageRecord.SGId &&
            item.UCM == pwUsageRecord.UCM)
        {
            return false; // already exists
        }
    }

    ast.PURecL.push_back(pwUsageRecord);
    return true;
}
