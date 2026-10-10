// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Common-exponent proof of knowledge in the hidden-order group
// Z*_{N^2}, per the expert ruling for DAO V2 resharing.
//
// The proof establishes that a single integer s_i satisfies both
// public relations, without revealing s_i:
//
//     VK_i = V^(Delta * s_i) mod N^2
//     C_i0 = V^(mu_i  * s_i) mod N^2
//
// This is a binary-challenge proof (128 repetitions), not a
// Schnorr proof with a multi-bit challenge: in a hidden-order group
// a multi-bit challenge is not generally sound. Fiat-Shamir is over
// SHAKE256 with domain "VeilRoot-DAO-RESHARE-LINK-V1".

#ifndef VEILROOT_DAO_RESHARE_PROOF_H
#define VEILROOT_DAO_RESHARE_PROOF_H

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

struct dao_reshare_link_proof
{
    static constexpr size_t REPS         = 128;
    static constexpr size_t SCALAR_BYTES = 512;

    // Each A_l and B_l is a PAILLIER_CT_BYTES group element.
    std::vector<std::vector<uint8_t>> A;   // A_l = V^(Delta * r_l)
    std::vector<std::vector<uint8_t>> B;   // B_l = V^(mu_i  * r_l)
    // Each Z_l is: 1 sign byte (0 = nonneg, 1 = negative) then
    // SCALAR_BYTES big-endian magnitude.
    std::vector<std::vector<uint8_t>> Z;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

// Everything the Fiat-Shamir transcript commits to. Deterministic and
// canonical; every field is length-prefixed or fixed-width.
struct dao_reshare_link_context
{
    crypto::hash          genesis_block_hash{};
    std::vector<uint8_t>  stable_key_record_hash;   // 32 bytes
    uint64_t              share_set_id = 0;
    std::vector<uint8_t>  contributor_pubkey;       // 32 bytes
    uint32_t              original_index = 0;
    std::vector<uint32_t> contributor_subset;

    std::vector<uint8_t>  N;      // PAILLIER_MODULUS_BYTES
    std::vector<uint8_t>  V;      // PAILLIER_CT_BYTES
    std::vector<uint8_t>  VK_i;   // PAILLIER_CT_BYTES
    std::vector<uint8_t>  C_i0;   // PAILLIER_CT_BYTES
    std::vector<uint8_t>  Delta;  // canonical big-endian
    std::vector<uint8_t>  mu_i;   // canonical big-endian
};

bool dao_reshare_link_prove(
    const dao_reshare_link_context& ctx,
    const BIGNUM* s_i,
    dao_reshare_link_proof& proof_out);

bool dao_reshare_link_verify(
    const dao_reshare_link_context& ctx,
    const dao_reshare_link_proof& proof);

} // namespace dao
} // namespace cryptonote

#endif
