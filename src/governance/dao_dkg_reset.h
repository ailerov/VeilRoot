// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Dynamic tally-share transition (Reset).
//
// Integer-scaled Reset. Every old shareholder i commits to a Delta-scaled
// polynomial H_i whose free coefficient is mu_i * SK_i, mu_i = Delta * lambda_i.
// Evaluation at each new shareholder's point is divided by Delta exactly.
// Result: new integer shares with the same secret SK(0), no reconstruction,
// no change to N, no re-encryption.
//
// The free-coefficient commitment C_i,0 = g^(mu*SK) * h^(Delta*b0) is bound
// by a Schnorr proof to the shareholder's existing V_K_i = V_K^(Delta*SK_i).
// No new bootstrap secret commitment.

#pragma once

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_tally_key.h"
#include "governance/dao_threshold.h"

namespace cryptonote {
namespace dao {

struct dao_dkg_reset_config
{
    uint32_t old_epoch = 0;
    uint32_t new_epoch = 0;
    uint32_t old_threshold = 0;
    uint32_t new_threshold = 0;
    std::vector<crypto::public_key> old_members;
    std::vector<crypto::public_key> new_members;
    crypto::hash key_id{};
    crypto::hash old_committee_id{};
    crypto::hash new_committee_id{};
};

struct dao_dkg_reset_result
{
    bool ok = false;
    uint32_t new_epoch     = 0;
    uint32_t new_threshold = 0;
    crypto::hash transcript_hash{};
    crypto::hash new_committee_id{};
    std::vector<uint8_t> local_share;

    // 1-based index of this node in the new committee. 0 if this node
    // is not a member.
    uint32_t local_member_index = 0;

    // V_K'_j = V_K^(Delta * SK'_j). The verification key for this
    // node's temporary tally share. 512 bytes (mod N^2). Empty when
    // this node is not a member of the new committee.
    std::vector<uint8_t> local_vki;

    std::vector<std::vector<uint8_t>> new_verification_keys;
};

// Schnorr proof linking C_i,0 to V_K_i over the shared witness SK_i.
struct dao_reset_share_link_proof
{
    std::vector<uint8_t> T_vss;       // g^(mu*ds) * h^(Delta*db) mod P
    std::vector<uint8_t> T_paillier;  // V_K^(Delta*ds) mod N^2
    std::vector<uint8_t> z_share;     // ds + e*SK_i  mod P'
    std::vector<uint8_t> z_blinding;  // db + e*b0    mod P'

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

struct dao_reset_public_contribution
{
    uint32_t                          old_member_id = 0;
    std::vector<std::vector<uint8_t>> coefficient_commitments;
    dao_reset_share_link_proof        share_link_proof;
};

struct dao_reset_private_subshare
{
    uint32_t             from_old_member_id = 0;
    uint32_t             to_new_member_id   = 0;
    std::vector<uint8_t> subshare;   // H_i(x'_j), signed big-endian, mult of Delta
    std::vector<uint8_t> blinding;   // R_i(x'_j), signed big-endian, mult of Delta
};

// Delta-scaled integer Lagrange coefficient at zero for `member_id` within
// `old_ids`. Returns false if `member_id` not in `old_ids`.
bool dao_dkg_reset_compute_lambda(
    const std::vector<uint32_t>& old_ids,
    uint32_t member_id,
    const BIGNUM* field_modulus,
    BIGNUM* lambda_out);

// Horner evaluation sum_k coeffs[k]*x^k over the integers (field_modulus
// ignored when null; reduced mod field_modulus otherwise).
bool dao_dkg_reset_evaluate(
    const std::vector<BIGNUM*>& coeffs,
    uint32_t x,
    const BIGNUM* field_modulus,
    BIGNUM* out,
    BN_CTX* ctx);

bool dao_dkg_reset_generate_contribution(
    const dao_dkg_reset_config& cfg,
    uint32_t old_member_id,
    const std::vector<uint8_t>& local_old_share,     // signed big-endian SK_i
    const dao_vss_group& vss,
    const BIGNUM* N2,
    const BIGNUM* V_K,
    const std::vector<uint8_t>& V_K_i_bytes,
    dao_reset_public_contribution& public_out,
    std::vector<dao_reset_private_subshare>& private_out);

// Verifier for the Schnorr proof binding C0 to V_K_i over the shared
// witness SK_i. Exposed for testing; production code goes through
// dao_dkg_reset_accept.
bool dao_dkg_reset_share_link_verify(
    const dao_vss_group& vss,
    const BIGNUM* N2,
    const BIGNUM* V_K,
    const std::vector<uint8_t>& V_K_i_bytes,
    const BIGNUM* mu,
    const BIGNUM* C0,
    const std::vector<uint8_t>& transcript_context,
    const dao_reset_share_link_proof& proof);

bool dao_dkg_reset_verify_subshare(
    const dao_vss_group& vss,
    uint32_t recipient_new_id,
    const std::vector<uint8_t>& subshare,
    const std::vector<uint8_t>& blinding,
    const std::vector<std::vector<uint8_t>>& coefficient_commitments);

bool dao_dkg_reset_accept(
    const dao_dkg_reset_config& cfg,
    uint32_t self_new_id,
    const std::vector<dao_reset_public_contribution>& publics,
    const std::vector<dao_reset_private_subshare>& my_subshares,
    const dao_vss_group& vss,
    const BIGNUM* N2,
    const BIGNUM* V_K,
    const std::vector<std::vector<uint8_t>>& old_vk_i_list,
    std::vector<uint8_t>& new_share_out);

// Single-process integer-ceremony test entry point (no Pedersen, no proof).
bool dao_dkg_reset_full_ceremony(
    const dao_dkg_reset_config& cfg,
    const std::vector<std::vector<uint8_t>>& all_old_shares,
    const std::vector<uint8_t>& field_modulus_bytes,
    std::vector<std::vector<uint8_t>>& new_shares_out);

bool dao_dkg_reset(
    const dao_dkg_reset_config& cfg,
    const std::vector<uint8_t>& local_old_share,
    const dao_tally_public_key_record& public_key,
    dao_dkg_reset_result& result);

// ====================================================================
// P2P Reset ceremony
// ====================================================================
//
// One round. Every old shareholder broadcasts its coefficient
// commitments and link proof (reshare_commit), then sends the private
// (subshare, blinding) pair targeted at each new shareholder
// (reshare_share). Every new shareholder collects all commits and its
// private subshares, verifies them, and produces its new share.
//
// A node can be in the old committee, the new committee, both, or
// neither.
//
// Messages reuse dkg_msg (bytes_a, bytes_b, bytes_c, vec_a) and the
// dkg_p2p transport. Private subshares are wrapped with
// encrypt_dkg_private_payload.

struct dkg_p2p_reshare_callbacks
{
    std::function<bool(const crypto::public_key&, const std::string&)> send_to;
    std::function<void(const std::string&)>                            broadcast;
};

class dkg_p2p_reshare_runner
{
public:
    dkg_p2p_reshare_runner(const dao_dkg_reset_config& cfg,
                           const dao_tally_public_key_record& public_key,
                           const dao_vss_group& vss,
                           const BIGNUM* N2,
                           const crypto::public_key& self_pk,
                           const crypto::secret_key& self_sk,
                           const std::vector<uint8_t>& local_old_share,
                           const std::vector<std::vector<uint8_t>>& old_vk_i_list,
                           const dkg_p2p_reshare_callbacks& cb);
    ~dkg_p2p_reshare_runner();

    dkg_p2p_reshare_runner(const dkg_p2p_reshare_runner&) = delete;
    dkg_p2p_reshare_runner& operator=(const dkg_p2p_reshare_runner&) = delete;

    bool start();
    void stop();
    void on_message(const dkg_msg& m);
    bool wait(dao_dkg_reset_result& out, uint32_t timeout_s = 0);

    bool running()  const;
    bool finished() const;

private:
    struct impl;
    std::unique_ptr<impl> p_;
};

} // namespace dao

} // namespace cryptonote
