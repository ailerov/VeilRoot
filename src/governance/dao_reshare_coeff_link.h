// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cross-group coefficient link proof for DAO V2 resharing.
//
// Ties a signed coefficient b (committed in the Paillier group as
// C_ik = V^(Delta * 2^S * b) mod N^2) to the same integer x = b + 2^64
// committed in the FFDHE VSS group as D_x = g^x h^rho mod P.
//
// Fiat-Shamir over SHAKE256 with domain
// "VeilRoot-DAO-RESHARE-COEFF-LINK-V1". Binary challenges, 128
// repetitions, no multi-bit Schnorr in a hidden-order group.

#ifndef VEILROOT_DAO_RESHARE_COEFF_LINK_H
#define VEILROOT_DAO_RESHARE_COEFF_LINK_H

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

struct dao_reshare_coeff_link_proof
{
    static constexpr size_t REPS     = 128;
    // z_x = a + e*x, a in [0, 2^193), x in [0, 2^65), so z_x < 2^194.
    static constexpr size_t ZX_BYTES = 32;

    std::vector<std::vector<uint8_t>> A_paillier;  // PAILLIER_CT_BYTES
    std::vector<std::vector<uint8_t>> A_vss;       // vss_element_bytes
    std::vector<std::vector<uint8_t>> Z_x;         // ZX_BYTES
    std::vector<std::vector<uint8_t>> Z_rho;       // vss_element_bytes

    bool serialize(std::vector<uint8_t>& out,
                   size_t vss_element_bytes) const;
    bool deserialize(const std::vector<uint8_t>& in,
                     size_t vss_element_bytes);
};

struct dao_reshare_coeff_link_context
{
    crypto::hash          genesis_block_hash{};
    std::vector<uint8_t>  stable_key_record_hash;   // 32 bytes
    uint64_t              share_set_id = 0;
    std::vector<uint8_t>  contributor_pubkey;       // 32 bytes
    uint32_t              contributor_index = 0;    // original DKG index
    uint32_t              coefficient_index = 0;    // 1-based

    std::vector<uint8_t>  G;      // PAILLIER_CT_BYTES
    std::vector<uint8_t>  C_ik;   // PAILLIER_CT_BYTES
    std::vector<uint8_t>  Y;      // PAILLIER_CT_BYTES
    std::vector<uint8_t>  D_x;    // vss_element_bytes
    std::vector<uint8_t>  range_proof_hash;  // 32 bytes
};

bool dao_reshare_coeff_link_prove(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const dao_reshare_coeff_link_context& ctx,
    const BIGNUM* x,
    const BIGNUM* rho,
    dao_reshare_coeff_link_proof& proof_out);

bool dao_reshare_coeff_link_verify(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const dao_reshare_coeff_link_context& ctx,
    const dao_reshare_coeff_link_proof& proof);

} // namespace dao
} // namespace cryptonote

#endif
