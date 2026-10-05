// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Dynamic tally-share transition (Reset).
//
// Reference: Klinger, Wüller, Traverso, Meyer (2021), Protocol 3.4 Reset,
// based on the Traverso, Demirel, Buchmann (eprint 2017/724) dynamic
// Birkhoff-interpolation secret sharing. VeilRoot uses ordinary point
// shares, so the Birkhoff machinery reduces to Lagrange interpolation at 0.
//
// Arithmetic is over the integers, not a finite field:
//
//   old shares              sigma_l   (integer, l in 1..n_old)
//   mu_l                    Delta * lambda_l  (integer; lambda_l rational Lagrange)
//   h_l(0)                  mu_l * sigma_l
//   h_l(k) for k>=1         Delta * a_l,k,  a_l,k random
//   f'(x)                   sum_l h_l(x)
//   f'(0)                   sum_l mu_l * sigma_l = Delta * f(0)
//   new share               sigma'_j = f'(j) / Delta    (exact integer division)
//
// Pedersen commitments to (h_l coefficients, r_l coefficients) let each new
// shareholder verify the private subshares it receives.

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
    std::vector<std::vector<uint8_t>> new_verification_keys;
};

// Delta-scaled integer Lagrange coefficient at zero for `member_id` within
// `old_ids`. field_modulus is unused (kept for API stability).
bool dao_dkg_reset_compute_lambda(
    const std::vector<uint32_t>& old_ids,
    uint32_t member_id,
    const BIGNUM* field_modulus,
    BIGNUM* lambda_out);

// Horner evaluation sum_k coeffs[k]*x^k. field_modulus ignored when null.
bool dao_dkg_reset_evaluate(
    const std::vector<BIGNUM*>& coeffs,
    uint32_t x,
    const BIGNUM* field_modulus,
    BIGNUM* out,
    BN_CTX* ctx);

// Single-process test entry point for the integer core (no Pedersen).
bool dao_dkg_reset_full_ceremony(
    const dao_dkg_reset_config& cfg,
    const std::vector<std::vector<uint8_t>>& all_old_shares,
    const std::vector<uint8_t>& field_modulus_bytes,
    std::vector<std::vector<uint8_t>>& new_shares_out);

// Distributed entry point (not yet implemented).
bool dao_dkg_reset(
    const dao_dkg_reset_config& cfg,
    const std::vector<uint8_t>& local_old_share,
    const dao_tally_public_key_record& public_key,
    dao_dkg_reset_result& result);

// --------------------------------------------------------------------
// Pedersen-verified Reset (real ceremony path)
// --------------------------------------------------------------------

struct dao_reset_public_contribution
{
    uint32_t                          old_member_id = 0;
    std::vector<std::vector<uint8_t>> coefficient_commitments;
};

struct dao_reset_private_subshare
{
    uint32_t             from_old_member_id = 0;
    uint32_t             to_new_member_id   = 0;
    std::vector<uint8_t> subshare;   // h_l(x'_j), signed big-endian
    std::vector<uint8_t> blinding;   // r_l(x'_j), signed big-endian
};

bool dao_dkg_reset_generate_contribution(
    const dao_dkg_reset_config& cfg,
    uint32_t old_member_id,
    const std::vector<uint8_t>& local_old_share,
    const dao_vss_group& vss,
    dao_reset_public_contribution& public_out,
    std::vector<dao_reset_private_subshare>& private_out);

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
    std::vector<uint8_t>& new_share_out);

} // namespace dao
} // namespace cryptonote
