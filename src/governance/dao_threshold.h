// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

// Committee bounds, per docs/DAO-V2-IMPLEMENTATION-SPEC.md §4 rev2.
// The Nishide-Sakurai (t+1, n) construction requires t < n/2. For a
// committee of size n the maximum t is floor((n-1)/2), so:
//
//     threshold T = t + 1 = ceil(n / 2)
//
// n = 16 yields T = 8, which reproduces the prior fixed parameterisation
// exactly. n = 3 yields T = 2, which is the live three-node case.
constexpr uint32_t DAO_DKG_MIN_COMMITTEE_SIZE = 3;
constexpr uint32_t DAO_DKG_MAX_COMMITTEE_SIZE = 16;

// Default maximum, retained as a convenience. Not a runtime requirement.
constexpr uint32_t DAO_DKG_COMMITTEE_SIZE = DAO_DKG_MAX_COMMITTEE_SIZE;

// Derived from DAO_DKG_COMMITTEE_SIZE for backward compatibility with
// code that still builds a 16-member committee. New code must derive
// the threshold from the actual committee size via
// dao_dkg_expected_threshold().
constexpr uint32_t DAO_DKG_SHARING_DEGREE = 7;
constexpr uint32_t DAO_DKG_THRESHOLD      = 8;

// Threshold for a committee of size n. Returns 0 if n is outside the
// permitted range [DAO_DKG_MIN_COMMITTEE_SIZE, DAO_DKG_MAX_COMMITTEE_SIZE].
constexpr uint32_t dao_dkg_expected_threshold(uint32_t n)
{
    return (n < DAO_DKG_MIN_COMMITTEE_SIZE ||
            n > DAO_DKG_MAX_COMMITTEE_SIZE)
        ? 0
        : (n + 1) / 2;
}

// Delta = 16! = 20922789888000. Clears the denominators of the Lagrange
// basis for any subset of {1..16} of any size, since for member indices
// 1..n the interpolation denominators divide n!, and n! divides 16!.
// Caller does NOT own the returned BIGNUM; it is a process-lifetime
// singleton.
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
// `subset` and `partials` must be in the same order. `threshold` is the
// epoch threshold T, which for a committee of size n is ceil(n / 2)
// (see dao_dkg_expected_threshold). The subset size must be >= T. The
// result is a canonical 512-byte ciphertext that, given valid partial
// decryptions from any T-member subset, equals
// c^(4 * Delta^2 * f(0)) modulo N^2.
bool dao_threshold_combine(const PaillierPublicKey& pk,
                           const std::vector<uint32_t>& subset,
                           const std::vector<std::vector<uint8_t>>& partials,
                           uint32_t threshold,
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