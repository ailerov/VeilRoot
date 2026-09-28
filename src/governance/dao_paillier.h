// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "governance/voting_weight.h"

namespace cryptonote {
namespace dao {

// Frozen Paillier parameters, spec §5 and §7.
constexpr size_t PAILLIER_MODULUS_BITS  = 2048;
constexpr size_t PAILLIER_MODULUS_BYTES = 256;   // 2048 / 8
constexpr size_t PAILLIER_CT_BYTES      = 512;   // modulus^2 / 8

// Standard Paillier, s = 1, g = 1 + N.
//
//   Enc(m; r) = (1+N)^m * r^N mod N^2,   m in Z_N, r in Z_N*
//   add:    c1 * c2 mod N^2   ->   m1 + m2 mod N
//   negate: c^{-1} mod N^2    ->   -m mod N
//   scal:   c^k mod N^2       ->   k * m mod N
//
// All ciphertexts are exactly PAILLIER_CT_BYTES big-endian bytes.
// All moduli are exactly PAILLIER_MODULUS_BYTES big-endian bytes.
//
// The implementation is thin around OpenSSL BIGNUM; protocol-level
// structure (signed encoding, threshold shares) is layered above.

class PaillierPublicKey
{
public:
    PaillierPublicKey() = default;
    ~PaillierPublicKey();

    PaillierPublicKey(const PaillierPublicKey&) = delete;
    PaillierPublicKey& operator=(const PaillierPublicKey&) = delete;
    PaillierPublicKey(PaillierPublicKey&&) noexcept;
    PaillierPublicKey& operator=(PaillierPublicKey&&) noexcept;

    void reset();

    // N from a BIGNUM or from canonical bytes.
    bool set_modulus(const BIGNUM* N);
    bool deserialize_modulus(const std::vector<uint8_t>& in);

    // N in exactly PAILLIER_MODULUS_BYTES big-endian bytes.
    bool serialize_modulus(std::vector<uint8_t>& out) const;

    // Encrypt m in [0, N) with fresh r in Z_N*.
    // Rejects m >= N, gcd(r, N) != 1, r == 0.
    bool encrypt(const BIGNUM* m,
                 const BIGNUM* r,
                 std::vector<uint8_t>& ct_out) const;

    // Multiplicative aggregation mod N^2.
    bool add(const std::vector<uint8_t>& c1,
             const std::vector<uint8_t>& c2,
             std::vector<uint8_t>& out) const;

    // Multiplicative inverse mod N^2. Ciphertext rollback uses this.
    bool inverse(const std::vector<uint8_t>& c,
                 std::vector<uint8_t>& out) const;

    // Multiplicative scalar: c^k mod N^2.
    bool scalar_mul(const std::vector<uint8_t>& c,
                    const BIGNUM* k,
                    std::vector<uint8_t>& out) const;

    // c < N^2 and gcd(c, N) == 1.
    bool is_valid_ciphertext(const std::vector<uint8_t>& c) const;

    const BIGNUM* N()  const { return N_; }
    const BIGNUM* N2() const { return N2_; }
    bool valid() const { return N_ != nullptr; }

private:
    BIGNUM* N_  = nullptr;
    BIGNUM* N2_ = nullptr;

    bool ensure_N2();
};

// Private key (N, lambda, mu). Unit tests and threshold share
// combination use this class. Production key material comes from DKG.
class PaillierPrivateKey
{
public:
    PaillierPrivateKey() = default;
    ~PaillierPrivateKey();

    PaillierPrivateKey(const PaillierPrivateKey&) = delete;
    PaillierPrivateKey& operator=(const PaillierPrivateKey&) = delete;
    PaillierPrivateKey(PaillierPrivateKey&&) noexcept;
    PaillierPrivateKey& operator=(PaillierPrivateKey&&) noexcept;

    void reset();

    // TESTING ONLY. Real key material is created by DKG.
    // Generates an RSA modulus and the (lambda, mu) pair.
    bool generate_for_testing(unsigned int bits = PAILLIER_MODULUS_BITS);

    // m = L(c^lambda mod N^2) * mu mod N, L(x) = (x-1)/N.
    // Uses constant-time modular exponentiation for lambda.
    bool decrypt(const std::vector<uint8_t>& ct,
                 BIGNUM* m_out) const;

    PaillierPublicKey public_key() const;

    const BIGNUM* N()      const { return N_; }
    const BIGNUM* lambda() const { return lambda_; }
    const BIGNUM* mu()     const { return mu_; }

private:
    BIGNUM* N_      = nullptr;
    BIGNUM* N2_     = nullptr;
    BIGNUM* lambda_ = nullptr;
    BIGNUM* mu_     = nullptr;
    // Kept only for tests.
    BIGNUM* p_      = nullptr;
    BIGNUM* q_      = nullptr;
};

// --- canonical serialization ---

// Serialize/deserialize a scalar in exactly `bytes` big-endian bytes.
// Rejects values that do not fit.

// --- signed plaintext encoding (spec §9) ---

// W >= 0 encodes directly. Rejects W > W_MAX and W >= N.
bool encode_unsigned_weight(const governance_weight_t& w,
                            const BIGNUM* N,
                            BIGNUM* m_out);

// Encode signed S per spec §9:
//   S >= 0 -> m = S mod N
//   S <  0 -> m = (N - |S|) mod N
bool encode_signed_value(const boost::multiprecision::int128_t& s,
                         const BIGNUM* N,
                         BIGNUM* m_out);

// Decode m in Z_N back to signed int128 per spec §9:
//   m <= N/2 -> S = m
//   m >  N/2 -> S = m - N
bool decode_signed_value(const BIGNUM* m,
                         const BIGNUM* N,
                         boost::multiprecision::int128_t& out);

// Convert an int128 to / from a BIGNUM.
bool int128_to_bn(const boost::multiprecision::int128_t& v, BIGNUM* out);
bool bn_to_int128(const BIGNUM* v, boost::multiprecision::int128_t& out);

// Convert a governance_weight_t (128-bit unsigned) to a BIGNUM.
bool governance_weight_to_bn(const governance_weight_t& w, BIGNUM* out);

} // namespace dao
} // namespace cryptonote