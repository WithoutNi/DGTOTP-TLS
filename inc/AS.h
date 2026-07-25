#ifndef AS_H
#define AS_H

#include <vector>
#include <string>

/// @brief Confirmation key
struct ConfKey
{
    /// Subgroup identifier
    int SGId;

    /// confirmation key bytes
    std::vector<unsigned char> key;
};

/// @brief Password commitment pair
struct pw_CM
{
    /// Usage-status commitment of password
    std::string UCM;

    /// Session-bound commitment of password
    std::string SCM;
};

/// @brief Password usage record
struct PwUsageRecord
{
    /// Subgroup identifier
    int SGId;

    /// Usage-status commitment of password
    std::string UCM;
};

/// Confirmation key list
using ConfKeyList = std::vector<ConfKey>;

/// Password usage record list
using PwUsageRecordList = std::vector<PwUsageRecord>;

/**
 * AS class - Stores confirmation keys and password usage record records for subgroup authentication
 */
class AS
{
public:
    /// Constructor
    AS() = default;

    /// Destructor
    ~AS() = default;

    /// Add a confirmation key entry
    /// @param[in] confKey Confirmation key entry
    void AddConfkey(const ConfKey &confKey);

    /// Add a password usage record entry
    /// @param[in] pwUsageRecord Password usage record entry
    void AddPURec(const PwUsageRecord &pwUsageRecord);

    /// Query confirmation keys by SGId
    /// @param[in] SGId Subgroup ID
    /// @return Matching confirmation key entries
    ConfKeyList QueryConfKeyListBySGId(int SGId) const;

    /// Query password usage records by SGId
    /// @param[in] SGId Subgroup ID
    /// @return Matching password usage record entries
    PwUsageRecordList QueryPwUsageRecordListBySGId(int SGId) const;

    /// Check whether a password usage record already exists and insert it if absent
    /// @param[in] pwUsageRecord Password usage record entry to check
    /// @return true if newly inserted, false if already exists
    bool CheckAndAddPURec(const PwUsageRecord &pwUsageRecord);

    /// Initialize the authentication state of the server
    /// @param[in] I the number of subgroups
    /// @return true on success, false on failure
    void InitAuthState(int I);

    /// Set the local state of the authentication server
    /// @param[in] pk_AS Public key of the authentication server
    /// @param[in] sk_AS Private key of the authentication server
    /// @return true on success, false on failure
    void SetLocalState(const std::string &pk_AS, const std::string &sk_AS);

private:
    /// @brief Authentication state
    struct AuthState
    {
        /// @brief The confirmation keys of its enrolled clients
        std::vector<ConfKeyList> KConfL;

        /// @brief The accepted password usage records
        std::vector<PwUsageRecordList> PURecL;
    };

    /// @brief The long term local state of the authentication server
    struct LocalState
    {
        /// @brief public key of the authentication server
        std::string pk_AS;

        /// @brief private key of the authentication server
        std::string sk_AS;
    };

    /// @brief Authentication state instance
    AuthState AST;
    /// @brief Local state instance
    LocalState LSt;
};

#endif // AS_H
