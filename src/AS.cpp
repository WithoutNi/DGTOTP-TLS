#include "AS.h"

/// Add Skey
void AS::AddSkey(const Skey &skey)
{
    authDB.skeys.push_back(skey);
}

/// Add Com
void AS::AddCom(const Com &com)
{
    authDB.cml.push_back(com);
}

/// Query Skeys by SGId
Skeys AS::QuerySkeysBySGId(int SGId) const
{
    Skeys result;
    for (const auto &sk : authDB.skeys)
    {
        if (sk.SGId == SGId)
        {
            result.push_back(sk);
        }
    }
    return result;
}

/// Query CML by SGId
CML AS::QueryCMLBySGId(int SGId) const
{
    CML result;
    for (const auto &com : authDB.cml)
    {
        if (com.SGId == SGId)
        {
            result.push_back(com);
        }
    }
    return result;
}

/// Check existence and insert if not exists
bool AS::CheckAndAddCM(const Com &com)
{
    for (const auto &existing : authDB.cml)
    {
        // Only SGId and UCM are used for deduplication. SCM is session-bound
        // and may differ across sessions for the same password.
        if (existing.SGId == com.SGId &&
            existing.CM.UCM == com.CM.UCM)
        {
            return false; // already exists
        }
    }

    authDB.cml.push_back(com);
    return true;
}
