// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>

namespace cryptonote {

// Calculate floor_log2 for integer arithmetic - returns 0 for input 0 or 1
inline uint64_t floor_log2(uint64_t n) {
    if (n == 0)
        return 0;

    uint64_t result = 0;
    while (n > 1) {
        n >>= 1;
        result++;
    }
    return result;
}

// Deterministic voting weight calculation as specified in DAO V2
// Returns false on overflow to enforce validation failure
// age_blocks = vote_height - output_height
// age_days = age_blocks / 720
// age_factor = floor_log2(age_days + 1)
// voting_weight = balance * age_factor
bool calculate_voting_weight(uint64_t amount, uint64_t output_height,
                             uint64_t vote_height, uint64_t& result);

} // namespace cryptonote