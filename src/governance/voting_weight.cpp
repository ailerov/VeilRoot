// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "voting_weight.h"

namespace cryptonote {

governance_weight_t governance_w_max()
{
    // 20,000,000 VNS * 10^12 atomic/VNS * 12
    return governance_weight_t("240000000000000000000");
}

uint64_t floor_log2(uint64_t n)
{
    uint64_t r = 0;
    while (n > 1)
    {
        n >>= 1;
        ++r;
    }
    return r;
}

bool calculate_voting_weight(uint64_t amount,
                             uint64_t output_height,
                             uint64_t vote_height,
                             governance_weight_t& out)
{
    // Negative age is not a valid protocol state.
    if (vote_height < output_height)
        return false;

    const uint64_t age_blocks    = vote_height - output_height;
    const uint64_t raw_age_days  = age_blocks / DAO_BLOCKS_PER_DAY;
    const uint64_t age_days      =
        raw_age_days > DAO_AGE_MAX_DAYS ? DAO_AGE_MAX_DAYS : raw_age_days;
    const uint64_t age_factor    = floor_log2(age_days + 1);

    // Exact 128-bit multiplication. No 64-bit intermediate.
    const governance_weight_t w =
        governance_weight_t(amount) * governance_weight_t(age_factor);

    if (w > governance_w_max())
        return false;

    out = w;
    return true;
}

} // namespace cryptonote