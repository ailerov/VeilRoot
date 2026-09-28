// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <boost/multiprecision/cpp_int.hpp>

namespace cryptonote {

// ---------------------------------------------------------------------------
// DAO V2 — Frozen governance-weight domain.
//
// Protocol weight of an output:
//
//     raw_age_days = (vote_height - output_height) / 720
//     age_days     = min(raw_age_days, 7300)          // 20-year cap
//     age_factor   = floor(log2(age_days + 1))
//     weight       = amount * age_factor              // exact, 128-bit
//
// All arithmetic is exact. No clamping. No truncation. No floating point.
//
// The representation is boost::multiprecision::uint128_t so that an
// individual weight, an aggregate weight, and a homomorphic tally
// accumulator can never overflow a 64-bit type under the protocol's
// frozen age cap.
// ---------------------------------------------------------------------------

using governance_weight_t = boost::multiprecision::uint128_t;

// 120-second target block time -> 720 blocks per day.
constexpr uint64_t DAO_BLOCKS_PER_DAY = 720;

// 20-year age cap. The protocol recognizes at most this many days of
// stake age; older outputs are treated as exactly this old. The cap is
// on recognized age, not on the derived age factor.
constexpr uint64_t DAO_AGE_MAX_DAYS = 7300;

// Maximum possible governance weight under the frozen caps:
//   20,000,000 VNS * 10^12 atomic/VNS * 12 (max age factor)
//   = 240,000,000,000,000,000,000
//
// Provided as a function so no consensus-relevant global initializer
// runs at load time.
governance_weight_t governance_w_max();

// floor(log2(n)); returns 0 for n == 0 and n == 1.
uint64_t floor_log2(uint64_t n);

// Compute the exact governance weight of a single output.
//
// Returns false if:
//   - vote_height < output_height (negative age)
//   - the resulting weight exceeds governance_w_max()
//
// On success, `out` holds the exact 128-bit weight.
bool calculate_voting_weight(uint64_t amount,
                             uint64_t output_height,
                             uint64_t vote_height,
                             governance_weight_t& out);

} // namespace cryptonote