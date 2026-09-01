// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <limits>
#include <vector>
#include "crypto/hash.h"
#include "governance_params.h"
#include "serialization/serialization.h"
#include "serialization/crypto.h"
#include "serialization/containers.h"
#include "serialization/string.h"

namespace cryptonote
{

// BEGIN_VNS_DOMAIN_TIER_FEE_BOUNDS
static constexpr uint64_t MIN_DOMAIN_TIER_FEE = 100000000000ULL; // 0.1 VNS
static constexpr uint64_t MAX_DOMAIN_TIER_FEE = std::numeric_limits<uint64_t>::max();
// END_VNS_DOMAIN_TIER_FEE_BOUNDS

// BEGIN_VNS_PARAMETER_UPDATE_ENTRY
struct parameter_update_entry
{
    governance_parameter parameter;
    uint64_t value;

    BEGIN_SERIALIZE()
        VARINT_FIELD(parameter)
        VARINT_FIELD(value)
    END_SERIALIZE()
};
// END_VNS_PARAMETER_UPDATE_ENTRY

// BEGIN_VNS_PARAMETER_UPDATE_PAYLOAD
struct parameter_update_payload
{
    uint8_t version;
    std::vector<parameter_update_entry> entries;

    BEGIN_SERIALIZE()
        VARINT_FIELD(version)
        FIELD(entries)
    END_SERIALIZE()
};
// END_VNS_PARAMETER_UPDATE_PAYLOAD

// BEGIN_VNS_EXTENSION_UPDATE_PAYLOAD
struct extension_update_payload
{
    uint8_t version;
    std::string extension;
    uint8_t tier;

    BEGIN_SERIALIZE()
        VARINT_FIELD(version)
        FIELD(extension)
        VARINT_FIELD(tier)
    END_SERIALIZE()
};
// END_VNS_EXTENSION_UPDATE_PAYLOAD

// BEGIN_VNS_LABEL_POLICY_UPDATE_PAYLOAD
struct label_policy_update_payload
{
    uint8_t version;   // 3 = premium label, 4 = banned label, 5 = banned extension
    std::string term;  // label or extension
    bool enable;       // true = add/ban, false = remove/unban

    BEGIN_SERIALIZE()
        VARINT_FIELD(version)
        FIELD(term)
        FIELD(enable)
    END_SERIALIZE()
};
// END_VNS_LABEL_POLICY_UPDATE_PAYLOAD

// BEGIN_VNS_EXACT_DOMAIN_TIER_UPDATE_PAYLOAD
struct exact_domain_tier_update_payload
{
    uint8_t version;   // 6
    std::string domain;
    bool enable;       // true = set override, false = remove override
    uint8_t tier;      // 0..5

    BEGIN_SERIALIZE()
        VARINT_FIELD(version)
        FIELD(domain)
        FIELD(enable)
        VARINT_FIELD(tier)
    END_SERIALIZE()
};
// END_VNS_EXACT_DOMAIN_TIER_UPDATE_PAYLOAD

// BEGIN_VNS_EXACT_DOMAIN_BAN_UPDATE_PAYLOAD
struct exact_domain_ban_update_payload
{
    uint8_t version;   // 7
    std::string domain;
    bool enable;       // true = ban, false = unban

    BEGIN_SERIALIZE()
        VARINT_FIELD(version)
        FIELD(domain)
        FIELD(enable)
    END_SERIALIZE()
};
// END_VNS_EXACT_DOMAIN_BAN_UPDATE_PAYLOAD

// BEGIN_VNS_PARAMETER_EXECUTION_PAYLOAD
struct parameter_execution_payload
{
    uint8_t version;
    crypto::hash proposal_id;

    BEGIN_SERIALIZE()
        VARINT_FIELD(version)
        FIELD(proposal_id)
    END_SERIALIZE()
};
// END_VNS_PARAMETER_EXECUTION_PAYLOAD

} // namespace cryptonote