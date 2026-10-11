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


// ====================================================================
// P2P resharing messages.
//
// Deal: one contributor's public commitment package plus per-recipient
// encrypted shares. Complete: a candidate share-set record broadcast by
// a recipient that has verified at least `threshold` deals.
// ====================================================================

struct dao_reshare_msg
{
    uint32_t version          = 1;
    uint64_t old_share_set_id = 0;
    uint64_t new_share_set_id = 0;
    uint32_t sender_index     = 0;
    uint8_t  type             = 0;   // 0 = deal, 1 = complete

    std::vector<uint8_t>              public_blob;
    std::vector<uint32_t>             recipient_indices;
    std::vector<std::vector<uint8_t>> recipient_payloads;
    std::vector<uint8_t>              record_blob;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

bool dao_reshare_serialize_public(
    const dao_reshare_contribution& c, std::vector<uint8_t>& out);
bool dao_reshare_deserialize_public(
    const std::vector<uint8_t>& in, dao_reshare_contribution& c_out);

bool dao_reshare_serialize_share(
    const dao_reshare_vss_share& sh, std::vector<uint8_t>& out);
bool dao_reshare_deserialize_share(
    const std::vector<uint8_t>& in, dao_reshare_vss_share& sh_out);

struct dao_reshare_share_bundle
{
    uint64_t             old_share_set_id = 0;
    uint32_t             sender_index     = 0;
    std::vector<uint8_t> share_bytes;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};


struct dao_reshare_p2p_callbacks
{
    std::function<bool(const crypto::public_key&, const std::string&)> send_to;
    std::function<void(const std::string&)> broadcast;
};

class dao_reshare_runner
{
public:
    struct config
    {
        PaillierPublicKey                 pk;
        const dao_vss_group*              grp = nullptr;
        std::vector<uint8_t>              V_bytes;
        const BIGNUM*                     delta = nullptr;
        uint32_t                          t_new = 0;
        std::vector<uint32_t>             new_indices;
        std::vector<crypto::public_key>   new_members;
        std::vector<uint32_t>             contributor_indices;
        std::vector<crypto::public_key>   contributor_members;
        uint64_t                          old_share_set_id = 0;
        uint64_t                          new_share_set_id = 0;
        uint64_t                          height = 0;
        uint32_t                          threshold = 0;
        std::vector<uint8_t>              key_id;

        // 0 means this node is a new member only, not an old contributor.
        uint32_t                          local_party_index = 0;
        const BIGNUM*                     local_s_i = nullptr;
        const BIGNUM*                     local_mu_i = nullptr;
        crypto::public_key                local_pub{};
        crypto::secret_key                local_priv{};
        dao_reshare_link_context          link_ctx_base;
    };

    dao_reshare_runner(const config& cfg,
                       const dao_reshare_p2p_callbacks& cb);
    ~dao_reshare_runner();
    dao_reshare_runner(const dao_reshare_runner&) = delete;
    dao_reshare_runner& operator=(const dao_reshare_runner&) = delete;

    bool start();
    void stop();
    void on_message(const crypto::public_key& from,
                    const dao_reshare_msg& m);
    bool wait(dao_share_set_record& out, uint32_t timeout_s = 0);
    bool finished() const;

private:
    struct impl;
    std::unique_ptr<impl> p_;
};

} // namespace dao
} // namespace cryptonote

#endif
