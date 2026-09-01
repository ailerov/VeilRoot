// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <string>
#include "crypto/hash.h"

namespace cryptonote
{

// BEGIN_VNS_DOMAIN_POLICY_SOURCE
enum class domain_policy_source : uint8_t {
    DEFAULT_TIER = 0,
    EXTENSION_TIER = 1,
    PREMIUM_LABEL = 2,
    EXACT_DOMAIN_OVERRIDE = 3,
    BANNED = 4,
    DAO_TIER_FEE = 5,
    DAO_EXTENSION_TIER = 6,
    PENDING_DOMAIN_POLICY = 7,
    EXACT_DOMAIN_BAN = 8,
    DEFAULT_PREMIUM_TIER = 9
};
// END_VNS_DOMAIN_POLICY_SOURCE

// BEGIN_VNS_DOMAIN_POLICY_RESULT
struct domain_policy_result
{
    bool registration_allowed;
    bool pending;
    bool banned;

    uint8_t tier;

    domain_policy_source source;

    uint64_t fee;
    uint64_t policy_height;
    crypto::hash policy_id;

    // Milestone 4 provenance fields.
    bool premium_policy_from_dao;
    uint64_t premium_policy_height;
    crypto::hash premium_policy_id;

    bool ban_policy_from_dao;
    uint64_t ban_policy_height;
    crypto::hash ban_policy_id;
};
// END_VNS_DOMAIN_POLICY_RESULT

} // namespace cryptonote