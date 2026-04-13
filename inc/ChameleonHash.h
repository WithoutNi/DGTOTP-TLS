#ifndef CHAMELEON_HASH_H
#define CHAMELEON_HASH_H

#include <string>
#include <openssl/ec.h>
#include <gmp.h>
#include <memory>

/// ChameleonHash class
class ChameleonHash
{
public:
    /// Private key sk (mpz_t)
    mpz_t sk;

    /// Base point G (static EC_POINT*)
    static EC_POINT *G;

    /// Public key pk (EC_POINT*)
    EC_POINT *pk;

    /// Finite field p (mpz_t)
    static mpz_t p;

    /// Group order N (mpz_t)
    static mpz_t N;

    /// Elliptic curve group (EC_GROUP*)
    static EC_GROUP *group;

    /// Constructor
    ChameleonHash();

    /// Destructor
    ~ChameleonHash();

    /// Initialize static parameters required by the class
    static void init();

    /// Set key pair from random seed bytes
    /// @param[in] rk random seed bytes used to derive the key pair.
    void Setup(unsigned char *rk);

    /// Create a copy of the stored public key
    /// @param[out] Returns a newly allocated EC_POINT* that is a deep copy of pk.
    EC_POINT *clonePublicKey() const;

    /// Generate a random big integer in the valid range
    /// @param[out] result mpz_t initialized by caller.
    static void getRand(mpz_t result);

    /// Compute chameleon hash:  CH = m*P + r*G
    /// @param[in] msg message m.
    /// @param[in] msg_len Length of message m.
    /// @param[in] pk Public key point P (EC_POINT*).
    /// @param[in] rand randomness r.
    /// @param[in] rand_len Length of random r.
    static int eval(unsigned char *msg, size_t msg_len, EC_POINT *pk, unsigned char *rand, size_t rand_len);

    /// Verify a chameleon hash value, return 1 if CH2=CH.Eval(pk, msg1, r1), 0 otherwise.
    /// @param[in] msg1 the first message.
    /// @param[in] msg1_len Length of first message.
    /// @param[in] r1  value.
    /// @param[in] r1_len Length of random.
    /// @param[in] pk Public key point to use for verification.
    /// @param[in] CH2 Expected hash value.
    static int Verify(unsigned char *msg1, size_t msg1_len, unsigned char *r1, size_t r1_len,
                      EC_POINT *pk, int CH2);

    /// Compute a random value r2 = r1 + sk*(m1 - m2) mod N, such that CH.Eval(pk, m1, r1) = CH.Eval(pk, m2, r2)
    /// @param[in] msg1 first message.
    /// @param[in] msg1_len Length of first message.
    /// @param[in] r1 first random bytes.
    /// @param[in] r1_len Length of r1 bytes.
    /// @param[in] msg2 target message to collide with.
    /// @param[in] msg2_len Length of target message.
    /// @param[in] sk Private key (mpz_t) used to compute the collision.
    static unsigned char *Collision(unsigned char *msg1, size_t msg1_len,
                                    unsigned char *r1, size_t r1_len,
                                    unsigned char *msg2, size_t msg2_len,
                                    mpz_t sk);

    /// Release static resources allocated by init().
    static void cleanup();
};

#endif // CHAMELEON_HASH_H