// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <string>
#include <vector>
#include "crypto/hash.h"
#include "crypto/crypto.h"

// BEGIN_VNS_GOVERNANCE_PARAMETER_ENUM
enum class governance_parameter : uint8_t {
    proposal_submission_fee = 0,
    voting_quorum_percent = 1,
    treasury_ratio = 2,
    execution_delay = 3,
    voting_period_days = 4,

    // BEGIN_VNS_DOMAIN_TIER_FEE_PARAMS
    domain_tier_fee_0 = 5,
    domain_tier_fee_1 = 6,
    domain_tier_fee_2 = 7,
    domain_tier_fee_3 = 8,
    domain_tier_fee_4 = 9,
    domain_tier_fee_5 = 10
    // END_VNS_DOMAIN_TIER_FEE_PARAMS
};
// END_VNS_GOVERNANCE_PARAMETER_ENUM

namespace cryptonote {

struct governance_params
{
    uint8_t  version;
    uint64_t proposal_submission_fee;
    uint64_t voting_quorum_percent;
    uint8_t  tally_committee_size;
    uint8_t  bridge_committee_size;
    uint8_t  threshold_ratio_numerator;
    uint8_t  threshold_ratio_denominator;
    crypto::public_key threshold_public_key;
    uint64_t tier_fees[6];              // C‑array, manually serialized
    uint8_t treasury_ratio;

    std::vector<std::string> extension_tier_map_keys;
    std::vector<uint8_t>       extension_tier_map_vals;
    std::vector<std::string> premium_labels;
    std::vector<std::string> banned_labels;
    std::vector<std::string> banned_extensions;

    std::string serialize() const;
    static governance_params default_params();
    static bool deserialize(const std::string& blob, governance_params& out);

    // Helpers
    uint8_t get_tier_for_extension(const std::string& ext) const;
    bool has_extension_tier_mapping(const std::string& ext) const;
    bool is_premium_label(const std::string& label) const;
    bool is_label_banned(const std::string& label) const;
    bool is_extension_banned(const std::string& ext) const;
};

} // namespace cryptonote