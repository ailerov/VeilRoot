// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance_params.h"
#include <cstring>
#include <algorithm>
#include "common/domain_utils.h"

namespace cryptonote {

static void append_string(std::string& blob, const std::string& s)
{
    uint16_t len = static_cast<uint16_t>(s.size());
    blob.append((const char*)&len, sizeof(len));
    blob.append(s.data(), len);
}

static bool read_string(const char*& data, size_t& size, std::string& out)
{
    if (size < 2) return false;
    uint16_t len = *(const uint16_t*)data;
    data += 2; size -= 2;
    if (size < len) return false;
    out.assign(data, len);
    data += len; size -= len;
    return true;
}

std::string governance_params::serialize() const
{
    std::string blob;
    blob.reserve(256);
    blob.push_back(version);
    blob.append((const char*)&proposal_submission_fee, sizeof(proposal_submission_fee));
    blob.append((const char*)&voting_quorum_percent, sizeof(voting_quorum_percent));
    blob.push_back(tally_committee_size);
    blob.push_back(bridge_committee_size);
    blob.push_back(threshold_ratio_numerator);
    blob.push_back(threshold_ratio_denominator);
    blob.append((const char*)tier_fees, sizeof(tier_fees));
    blob.append((const char*)&threshold_public_key, sizeof(threshold_public_key));

    uint16_t count = static_cast<uint16_t>(extension_tier_map_keys.size());
    blob.append((const char*)&count, sizeof(count));
    for (size_t i = 0; i < extension_tier_map_keys.size(); ++i) {
        append_string(blob, extension_tier_map_keys[i]);
        blob.push_back(extension_tier_map_vals[i]);
    }

    count = static_cast<uint16_t>(premium_labels.size());
    blob.append((const char*)&count, sizeof(count));
    for (const auto& s : premium_labels) append_string(blob, s);

    count = static_cast<uint16_t>(banned_labels.size());
    blob.append((const char*)&count, sizeof(count));
    for (const auto& s : banned_labels) append_string(blob, s);

    count = static_cast<uint16_t>(banned_extensions.size());
    blob.append((const char*)&count, sizeof(count));
    for (const auto& s : banned_extensions) append_string(blob, s);

    return blob;
}

bool governance_params::deserialize(const std::string& blob, governance_params& out)
{
    const char* data = blob.data();
    size_t size = blob.size();
    if (size < 1 + 8 + 8 + 1 + 1 + 1 + 1 + 6*8 + sizeof(crypto::public_key)) return false;

    out.version = data[0]; data++; size--;
    if (out.version < 1 || out.version > 3) return false;

    out.proposal_submission_fee = *(const uint64_t*)data; data += 8; size -= 8;
    out.voting_quorum_percent = *(const uint64_t*)data; data += 8; size -= 8;
    out.tally_committee_size = *(const uint8_t*)data; data += 1; size -= 1;
    out.bridge_committee_size = *(const uint8_t*)data; data += 1; size -= 1;
    out.threshold_ratio_numerator = *(const uint8_t*)data; data += 1; size -= 1;
    out.threshold_ratio_denominator = *(const uint8_t*)data; data += 1; size -= 1;
    for (int i = 0; i < 6; ++i) { out.tier_fees[i] = *(const uint64_t*)data; data += 8; size -= 8; }
    out.threshold_public_key = *(const crypto::public_key*)data; data += sizeof(crypto::public_key); size -= sizeof(crypto::public_key);

    if (size < 2) return false;
    uint16_t count = *(const uint16_t*)data; data += 2; size -= 2;
    out.extension_tier_map_keys.clear();
    out.extension_tier_map_vals.clear();
    for (uint16_t i = 0; i < count; ++i) {
        std::string key;
        if (!read_string(data, size, key)) return false;
        if (size < 1) return false;
        uint8_t val = *(const uint8_t*)data; data += 1; size -= 1;
        // Banned extensions are separate policy state. Do not expose them
        // as extension-tier mappings.
        if (val == domain_utils::TIER_BANNED)
            continue;
        out.extension_tier_map_keys.push_back(key);
        out.extension_tier_map_vals.push_back(val);
    }

    if (size < 2) return false;
    count = *(const uint16_t*)data; data += 2; size -= 2;
    out.premium_labels.clear();
    for (uint16_t i = 0; i < count; ++i) {
        std::string s;
        if (!read_string(data, size, s)) return false;
        out.premium_labels.push_back(s);
    }

    if (size < 2) return false;
    count = *(const uint16_t*)data; data += 2; size -= 2;
    out.banned_labels.clear();
    for (uint16_t i = 0; i < count; ++i) {
        std::string s;
        if (!read_string(data, size, s)) return false;
        out.banned_labels.push_back(s);
    }

    if (size < 2) return false;
    count = *(const uint16_t*)data; data += 2; size -= 2;
    out.banned_extensions.clear();
    for (uint16_t i = 0; i < count; ++i) {
        std::string s;
        if (!read_string(data, size, s)) return false;
        out.banned_extensions.push_back(s);
    }

    return size == 0;
}

governance_params governance_params::default_params()
{
    governance_params gp;
    gp.version = 2;
    gp.proposal_submission_fee = 10000000;       // 0.00001 VNS (1 VNS = 1e12 atomic units)
    gp.voting_quorum_percent = 10;
    gp.tally_committee_size = 16;
    gp.bridge_committee_size = 32;
    gp.threshold_ratio_numerator = 2;
    gp.threshold_ratio_denominator = 3;
    memset(&gp.threshold_public_key, 0, sizeof(gp.threshold_public_key));
    gp.tier_fees[0] = 100000000000ULL;           // 0.1 VNS
    gp.tier_fees[1] = 1000000000000ULL;          // 1 VNS
    gp.tier_fees[2] = 10000000000000ULL;         // 10 VNS
    gp.tier_fees[3] = 100000000000000ULL;        // 100 VNS
    gp.tier_fees[4] = 1000000000000000ULL;       // 1000 VNS
    gp.tier_fees[5] = 10000000000000000ULL;      // 10000 VNS

    // Populate extension tier map from existing hardcoded constants
    const auto& tier_map = domain_utils::get_extension_tier_map();
    for (const auto& [ext, tier] : tier_map)
    {
        // Banned extensions are policy state, not a registration tier.
        if (tier == domain_utils::TIER_BANNED)
            continue;
        gp.extension_tier_map_keys.push_back(ext);
        gp.extension_tier_map_vals.push_back(tier);
    }

    // Populate premium labels from existing sets
    const auto& premium_labels = domain_utils::get_premium_labels();
    gp.premium_labels.assign(premium_labels.begin(), premium_labels.end());

    // Populate banned labels
    const auto& banned_labels = domain_utils::get_banned_labels();
    gp.banned_labels.assign(banned_labels.begin(), banned_labels.end());

    // Populate banned extensions (directly from the vector constant)
    gp.banned_extensions = domain_utils::BANNED_EXTENSIONS;

    return gp;
}

uint8_t governance_params::get_tier_for_extension(const std::string& ext) const
{
    for (size_t i = 0; i < extension_tier_map_keys.size(); ++i)
        if (extension_tier_map_keys[i] == ext)
            return extension_tier_map_vals[i];
    return 5;
}

bool governance_params::has_extension_tier_mapping(const std::string& ext) const
{
    return std::find(extension_tier_map_keys.begin(), extension_tier_map_keys.end(), ext) != extension_tier_map_keys.end();
}

bool governance_params::is_premium_label(const std::string& label) const
{
    return std::find(premium_labels.begin(), premium_labels.end(), label) != premium_labels.end();
}

bool governance_params::is_label_banned(const std::string& label) const
{
    return std::find(banned_labels.begin(), banned_labels.end(), label) != banned_labels.end();
}

bool governance_params::is_extension_banned(const std::string& ext) const
{
    return std::find(banned_extensions.begin(), banned_extensions.end(), ext) != banned_extensions.end();
}

} // namespace cryptonote