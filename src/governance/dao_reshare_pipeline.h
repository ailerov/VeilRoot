// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// In-process orchestrator for committee-to-committee resharing.
// Callers supply the contribution set; the pipeline verifies each
// contribution, sums the per-recipient shares, computes VK'_j, and
// produces the new dao_share_set_record. P2P is a transport around
// this same shape.

#ifndef VEILROOT_DAO_RESHARE_PIPELINE_H
#define VEILROOT_DAO_RESHARE_PIPELINE_H

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_reshare_proof.h"
#include "governance/dao_reshare_vss.h"

namespace cryptonote {
namespace dao {

// One contributor's public output plus its targeted share for each new
// member. The share vector is indexed parallel to the new_indices the
// contributor was given.
struct dao_reshare_contribution
{
    uint32_t contributor_index = 0;       // original DKG shareholder index
    std::vector<uint8_t> contributor_pubkey;  // 32 bytes

    dao_reshare_link_context link_ctx;
    dao_reshare_link_proof link_proof;
    dao_reshare_vss_commitments commits;
    dao_reshare_vss_coeff_proofs coeff_proofs;
    std::vector<dao_reshare_vss_share> shares;
};

// A new-member's locally assembled share after combining all verified
// contributions.
struct dao_reshare_new_share
{
    uint32_t j = 0;
    std::vector<uint8_t> share_signed;   // signed serialization of s'_j
    std::vector<uint8_t> VK_j;           // PAILLIER_CT_BYTES
};

// One contributor produces its contribution for the given new member
// set. Returns the public commitments + proofs and the targeted shares.
bool dao_reshare_make_contribution(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const std::vector<uint8_t>& V_bytes,
    const BIGNUM* s_i,
    const BIGNUM* mu_i,
    const BIGNUM* delta,
    uint32_t t_new,
    const std::vector<uint32_t>& new_indices,
    dao_reshare_link_context link_ctx,
    dao_reshare_contribution& out);

// Combine a set of contributions into a per-new-member share.
// Verifies every contribution (link proof, coeff range proof,
// coeff link proof, evaluation consistency) before summing.
// Requires at least `threshold` contributions. Fills one entry per
// new_indices entry in order.
bool dao_reshare_combine(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const std::vector<uint8_t>& V_bytes,
    const std::vector<dao_reshare_contribution>& contributions,
    const std::vector<uint32_t>& new_indices,
    uint32_t threshold,
    const BIGNUM* delta,
    std::vector<dao_reshare_new_share>& new_shares_out);

// Build the final share-set record from the verified contributions and
// the new-member shares. The VK_i vector is taken from each new member's
// computed VK_j. threshold must be <= new_indices.size().
bool dao_reshare_build_share_set(
    uint64_t share_set_id,
    uint64_t height,
    const std::vector<uint8_t>& key_id,
    const std::vector<crypto::public_key>& new_members,
    const std::vector<dao_reshare_new_share>& new_shares,
    uint32_t threshold,
    dao_share_set_record& record_out);

} // namespace dao
} // namespace cryptonote

#endif
