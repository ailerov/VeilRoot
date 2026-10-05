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
//   h_l(k) for k>=1         Delta * b_l,k,  b_l,k random
//   f'(x)                   sum_l h_l(x)
//   f'(0)                   sum_l mu_l * sigma_l = Delta * f(0)
//   new share               sigma'_j = f'(j) / Delta    (exact integer division)
//
// Because h_l(k) is a multiple of Delta, f'(j) is a multiple of Delta.
// The integer new share sigma'_j combines via the existing Delta-scaled
// Lagrange mu'_j to give Delta*f(0), identical to the old committee.
// The Paillier threshold machinery is unchanged.

#pragma once

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "governance/dao_paillier.h"
#include "governance/dao_tally_key.h"

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
// `old_ids`. Returns false if `member_id` not in `old_ids`.
bool dao_dkg_reset_compute_lambda(
    const std::vector<uint32_t>& old_ids,
    uint32_t member_id,
    const BIGNUM* field_modulus,
    BIGNUM* lambda_out);

// Horner evaluation sum_k coeffs[k]*x^k. `field_modulus` is ignored when
// null (integer mode); when non-null, reduces mod field_modulus.
bool dao_dkg_reset_evaluate(
    const std::vector<BIGNUM*>& coeffs,
    uint32_t x,
    const BIGNUM* field_modulus,
    BIGNUM* out,
    BN_CTX* ctx);

// Single-process test entry point. Simulates every old shareholder's h_l
// polynomial, sums evaluations at each new shareholder's point, divides by
// Delta, and returns the resulting integer shares in cfg.new_members order.
// `field_modulus_bytes` is unused in the integer construction; kept in the
// signature for API stability.
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

} // namespace dao
} // namespace cryptonote
