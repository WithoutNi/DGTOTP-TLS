#ifndef AS_H
#define AS_H

#include <vector>
#include <string>

/**
 * Shared key entry stored by the authentication server
 */
struct Skey
{
    /// Subgroup identifier
    int SGId;

    /// Shared key bytes
    std::vector<unsigned char> key;
};

/**
 * Password commitment pair
 */
struct pw_CM
{
    /// Usage-status commitment of password
    std::string UCM;

    /// Session-bound commitment of password
    std::string SCM;
};

/**
 * Commitment entry stored by the authentication server
 */
struct Com
{
    /// Subgroup identifier
    int SGId;

    /// Password commitment pair
    pw_CM CM;
};

/// Shared key collection
using Skeys = std::vector<Skey>;

/// Commitment list
using CML = std::vector<Com>;

/**
 * AS class - Stores shared keys and commitment records for subgroup authentication
 */
class AS
{
public:
    /// Constructor
    AS() = default;

    /// Destructor
    ~AS() = default;

    /// Add a shared key entry
    /// @param[in] skey Shared key entry
    void AddSkey(const Skey &skey);

    /// Add a commitment entry
    /// @param[in] com Commitment entry
    void AddCom(const Com &com);

    /// Query shared keys by SGId
    /// @param[in] SGId Subgroup ID
    /// @return Matching shared key entries
    Skeys QuerySkeysBySGId(int SGId) const;

    /// Query commitments by SGId
    /// @param[in] SGId Subgroup ID
    /// @return Matching commitment entries
    CML QueryCMLBySGId(int SGId) const;

    /// Check whether a commitment already exists and insert it if absent
    /// @param[in] com Commitment entry to check
    /// @return true if newly inserted, false if already exists
    bool CheckAndAddCM(const Com &com);

private:
    /**
     * Internal authentication database
     */
    struct AuthDB
    {
        /// Stored shared keys
        Skeys skeys;

        /// Stored commitments
        CML cml;
    };

    /// Authentication database instance
    AuthDB authDB;
};

#endif // AS_H
