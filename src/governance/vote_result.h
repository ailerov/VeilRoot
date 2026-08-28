// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>

namespace cryptonote {

// BEGIN_VNS_VOTE
enum class vote_result : uint8_t {
    success,
    missing_vote_tag,
    invalid_format,
    invalid_proposal_id,
    invalid_direction,
    voting_period_closed,
    already_voted,
    invalid_signature
};
// END_VNS_VOTE

} // namespace cryptonote