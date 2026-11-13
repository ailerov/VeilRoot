// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>

namespace cryptonote {
namespace dao {

// Backend-neutral interface for the DAO vote-tally homomorphic
// encryption scheme. One implementation per scheme:
//   - PaillierEncryptionBackend (dao_crypto_backend.cpp)
//   - CLEncryptionBackend      (dao_crypto_backend_cl.cpp)
//
// The public surface covers what the current Paillier callers in
// dao_wallet_v2.cpp, dao_tally.cpp, dao_tally_share.cpp,
// dao_threshold.cpp, dao_consistency.cpp, vote_proof_verifier.cpp,
// dao_dkg.cpp currently touch.
//
// Contract:
//   - encrypt(m, r, ct):       m in the backend's plaintext space,
//                              r sampled via sample_r() (or equivalent
//                              per the backend's own sampler),
//                              ct is the wire-encoded ciphertext
//   - add(c1, c2):             homomorphic addition
//   - inverse(c):              homomorphic negation
//   - scalar_mul(c, k):        homomorphic scalar multiplication
//   - is_valid_ciphertext(c):  structural validity (length, range)
//   - sample_r(r_out):         backend-specific randomness sampler
//                              for the encryption exponent
//   - serialize_modulus / deserialize_modulus:
//                              round-trip the public parameters
//   - ciphertext_size_hint():  advisory upper bound for buffer
//                              pre-sizing; 0 means variable (CL)
class DaoEncryptionBackend
{
public:
    virtual ~DaoEncryptionBackend() = default;

    virtual std::string name() const = 0;

    virtual bool serialize_modulus(std::vector<uint8_t>& out) const = 0;
    virtual bool deserialize_modulus(const std::vector<uint8_t>& in) = 0;

    virtual bool encrypt(const BIGNUM* m,
                         const BIGNUM* r,
                         std::vector<uint8_t>& ct_out) const = 0;

    virtual bool add(const std::vector<uint8_t>& c1,
                     const std::vector<uint8_t>& c2,
                     std::vector<uint8_t>& out) const = 0;

    virtual bool inverse(const std::vector<uint8_t>& c,
                         std::vector<uint8_t>& out) const = 0;

    virtual bool scalar_mul(const std::vector<uint8_t>& c,
                            const BIGNUM* k,
                            std::vector<uint8_t>& out) const = 0;

    virtual bool is_valid_ciphertext(const std::vector<uint8_t>& c) const = 0;

    virtual bool sample_r(BIGNUM* r_out) const = 0;

    virtual size_t ciphertext_size_hint() const = 0;

#ifdef VEILROOT_ENABLE_CL
    // TEST-ONLY: decrypt a ciphertext for round-trip verification in
    // unit tests. Backends without a decryption path return false.
    // Not called from production code paths.
    virtual bool decrypt_for_testing(const std::vector<uint8_t>& /*ct*/,
                                     BIGNUM* /*m_out*/) const { return false; }
#endif
};

// Factory: uninitialised Paillier backend. Caller loads the modulus via
// deserialize_modulus() before any encrypt / add / etc.
std::unique_ptr<DaoEncryptionBackend> make_paillier_backend();

// Factory: Paillier backend with modulus pre-loaded. Returns nullptr if
// the modulus does not deserialize (wrong length or structurally
// invalid).
std::unique_ptr<DaoEncryptionBackend>
    make_paillier_backend(const std::vector<uint8_t>& modulus);

// Canonical CL key context. Carries every immutable public parameter
// of a proposal's CL encryption key, including the key-lifetime
// interpolation scale D. Bound into the on-chain key_id via the
// record's existing SHA256 rule.
//
// Wire format (version 1):
//   domain "VeilRoot-DAO-CL-KeyCtx-V1\0"
//   u8      version = 1
//   u32     len_q
//   bytes   q (BE, no leading zero)
//   u32     k
//   SCALAR  p
//   QFI     pk_qfi (canonical a,b,c)
//   SCALAR  D
struct cl_key_context
{
    std::vector<uint8_t> q;
    uint32_t             k = 0;
    std::vector<uint8_t> p;       // sign_byte || magnitude BE
    std::vector<uint8_t> pk_qfi;  // full QFI wire
    std::vector<uint8_t> D;       // sign_byte(0) || magnitude BE
};

bool dao_cl_key_context_serialize(const cl_key_context& ctx,
                                  std::vector<uint8_t>& out);
bool dao_cl_key_context_parse(const std::vector<uint8_t>& in,
                              cl_key_context& out);

// Structural check used by the activation validator.
bool dao_cl_modulus_wire_valid(const std::vector<uint8_t>& in);

// Factory: CL-over-class-groups backend (research crypto only).
// Returns nullptr when VEILROOT_ENABLE_CL is not defined at build
// time. seclevel_bits defaults to 128; test code may pass 64 for
// speed. Do NOT use in shipped binaries: BICYCL is not constant-time.
std::unique_ptr<DaoEncryptionBackend>
    make_cl_backend(size_t seclevel_bits = 128);

// Weighted-tally maximum and plaintext-field injectivity.
// DAO_WEIGHTED_MAX matches dao_tally.cpp's runtime W_MAX and
// voting_weight.cpp's governance_weight_t maximum. Signed tally
// values live in [-W_MAX, +W_MAX], 2*W_MAX + 1 distinct values.
// For that range to be injectively encodable in Z_q, we require
// 2*W_MAX + 1 <= q.
//
// Compile-time: 2*W_MAX + 1 < 2^69. The CL backend constructor
// enforces q >= 2^200 at runtime. Chain q > 2^200 >> 2^69 >
// 2*W_MAX + 1 establishes injectivity across the signed range.
#if defined(__SIZEOF_INT128__)
constexpr unsigned __int128 DAO_WEIGHTED_MAX =
    (unsigned __int128)240000000ULL * (unsigned __int128)1000000000000ULL;
constexpr unsigned __int128 DAO_SIGNED_RANGE_SIZE =
    2 * DAO_WEIGHTED_MAX + 1;
static_assert(
    DAO_SIGNED_RANGE_SIZE < (((unsigned __int128)1) << 69),
    "signed tally range must fit in 69 bits");
#endif

} // namespace dao
} // namespace cryptonote
