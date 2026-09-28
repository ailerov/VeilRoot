// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

// Frozen committee parameters, per docs/DAO-V2-IMPLEMENTATION-SPEC.md §4
// and docs/DAO-V2-DKG.md §1. These are the Nishide-Sakurai (t+1, n)
// parameters with t = 7, n = 16, threshold = t+1 = 8. The paper requires
// t < n/2; for n = 16 the largest permitted t is 7.
constexpr uint32_t DAO_DKG_COMMITTEE_SIZE = 16;
constexpr uint32_t DAO_DKG_SHARING_DEGREE = 7;
constexpr uint32_t DAO_DKG_THRESHOLD      = 8;

// Delta = 16! = 20922789888000. Clears the denominators of the Lagrange
// basis for any (8..16)-member subset of {1..16}. Caller does NOT own
// the returned BIGNUM; it is a process-lifetime singleton.
const BIGNUM* dao_dkg_delta();

// Integer Lagrange multiplier for member i within subset S:
//
//     mu_i = Delta * prod_{j in S, j != i} (-j) / (i-j)
//
// S is a vector of 1-based member indices (1..16), all distinct, and
// must contain i. The division is exact because Delta = 16!. mu_i is
// a signed integer; callers that use it as a modular exponent must
// handle the sign by inverting the base (see dao_threshold_combine,
// which does this internally).
bool dao_dkg_lagrange_mu(const std::vector<uint32_t>& subset,
                         uint32_t i,
                         BIGNUM* mu_out);

// Partial decryption, Nishide-Sakurai §2.1 / §5:
//
//     c_i = c^(2 * Delta * share) mod N^2
//
// `share` is the member's integer share f(i) and may be negative;
// negative exponents are handled by first inverting c modulo N^2.
// The result is a canonical 512-byte ciphertext.
bool dao_threshold_partial_decrypt(const PaillierPublicKey& pk,
                                   const std::vector<uint8_t>& c_bytes,
                                   const BIGNUM* share,
                                   std::vector<uint8_t>& c_i_out);

// Threshold combination, Nishide-Sakurai §2.1 / §5:
//
//     C = prod_{i in S} c_i^(2 * mu_i) mod N^2
//
// `subset` and `partials` must be in the same order. The subset size
// must be >= DAO_DKG_THRESHOLD. The result is a canonical 512-byte
// ciphertext that, given valid partial decryptions from any T-member
// subset, equals c^(4 * Delta^2 * f(0)) modulo N^2.
bool dao_threshold_combine(const PaillierPublicKey& pk,
                           const std::vector<uint32_t>& subset,
                           const std::vector<std::vector<uint8_t>>& partials,
                           std::vector<uint8_t>& C_out);

// Final normalization, Nishide-Sakurai §5:
//
//     M = L(C) * (-4 * Delta^2 * theta_prime)^(-1) mod N
//
// where L(x) = (x - 1) / N. `theta_prime` is the public normalization
// parameter of the current key epoch. The negative sign and the Delta^2
// factor are part of the dealer-free construction's correctness
// derivation and are not optional. Do NOT substitute the ordinary
// Paillier mu here.
bool dao_threshold_finalize(const PaillierPublicKey& pk,
                            const std::vector<uint8_t>& C_bytes,
                            const BIGNUM* theta_prime,
                            BIGNUM* m_out);

} // namespace dao
} // namespace cryptonote