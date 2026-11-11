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
//   - CLEncryptionBackend      (Phase 4.2)
//
// The public surface is everything the current Paillier callers in
// dao_wallet_v2.cpp, dao_tally.cpp, dao_tally_share.cpp,
// dao_threshold.cpp, dao_consistency.cpp, vote_proof_verifier.cpp,
// dao_dkg.cpp currently touch. Callers are migrated to this interface
// incrementally (Phase 4.3+). No caller change happens in 4.1.
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
};

// Factory: uninitialised Paillier backend. Caller loads the modulus via
// deserialize_modulus() before any encrypt / add / etc.
std::unique_ptr<DaoEncryptionBackend> make_paillier_backend();

// Factory: Paillier backend with modulus pre-loaded. Returns nullptr if
// the modulus does not deserialize (wrong length or structurally
// invalid).
std::unique_ptr<DaoEncryptionBackend>
    make_paillier_backend(const std::vector<uint8_t>& modulus);

} // namespace dao
} // namespace cryptonote
