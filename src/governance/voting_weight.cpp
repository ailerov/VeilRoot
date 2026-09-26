// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "voting_weight.h"
#include <cstdint>
#include <limits>

namespace cryptonote {

// Returns false on overflow to enforce validation failure
bool calculate_voting_weight(uint64_t amount, uint64_t output_height,
                             uint64_t vote_height, uint64_t& result)
{
    // Calculate age in blocks
    uint64_t age_blocks = (vote_height > output_height) ? (vote_height - output_height) : 0;

    // Convert to days (720 blocks per day)
    uint64_t age_days = age_blocks / 720;

    // Calculate age factor using floor_log2
    uint64_t age_factor = floor_log2(age_days + 1);

    // Check for potential overflow before multiplication - must fail validation, not clamp
    if (amount > 0 && age_factor > std::numeric_limits<uint64_t>::max() / amount) {
        return false;  // Overflow is a validation failure
    }

    result = amount * age_factor;
    return true;
}

} // namespace cryptonote