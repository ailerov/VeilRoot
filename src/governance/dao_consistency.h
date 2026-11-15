// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Gap 2 — Paillier/Pedersen equality proof.
//
// Proves that a Paillier ciphertext E and a Pedersen commitment C
// encode the same integer m:
//
//   E = (1+N)^m * r^N   mod N^2      r in Z*_N
//   C = m*H + rho*G     on curve
//
// without revealing m, r, or rho.
//
// Construction: generalized Schnorr with one challenge, two
// verification equations. Response z_r is multiplicative on the
// Paillier side (a_r * r^e mod N) and additive on the curve side
// (a_m + e*m mod curve_order).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "serialization/serialization.h"
#include "serialization/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"

#include "governance/dao_consistency_context.h"

namespace cryptonote {
namespace dao {

struct dao_consistency_proof
{
    rct::key             A_C;   // curve side randomization
    std::vector<uint8_t> A_P;   // Paillier side randomization (512 bytes)
    std::vector<uint8_t> e;     // Fiat-Shamir challenge
    std::vector<uint8_t> z_m;   // integer response
    std::vector<uint8_t> z_r;   // Paillier randomization response
    std::vector<uint8_t> z_rho; // curve blinding response

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);

    BEGIN_SERIALIZE_OBJECT()
        FIELD(A_C)
        FIELD(A_P)
        FIELD(e)
        FIELD(z_m)
        FIELD(z_r)
        FIELD(z_rho)
    END_SERIALIZE()
};

// Prove that E = (1+N)^m * r^N mod N^2 and C = m*H + rho*G commit to
// the same m. `E` is the canonical 512-byte Paillier ciphertext.
bool dao_consistency_prove(const dao_consistency_context& ctx,
                           const BIGNUM* N,
                           const std::vector<uint8_t>& E,
                           const rct::key& C,
                           const BIGNUM* m,
                           const BIGNUM* r,
                           const rct::key& rho,
                           dao_consistency_proof& proof_out);

bool dao_consistency_verify(const dao_consistency_context& ctx,
                            const BIGNUM* N,
                            const std::vector<uint8_t>& E,
                            const rct::key& C,
                            const dao_consistency_proof& proof);

// extra_binding for the OR proof. Includes the two ciphertexts and
// their consistency proofs so that substituting either invalidates
// the OR proof challenge.
std::vector<uint8_t> dao_extra_binding(
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const dao_consistency_proof& proof_W,
    const dao_consistency_proof& proof_S);

} // namespace dao
} // namespace cryptonote