// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#include "gtest/gtest.h"

#include "common/domain_utils.h"
#include "crypto/crypto.h"
#include "string_tools.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

namespace
{
    // Inline literal re-implementation of the frozen algorithm.
    // If this diverges from domain_utils::compute_vns_registration_fingerprint,
    // the test fails: that is the point.
    crypto::hash inline_fingerprint(
        const std::string& domain,
        const std::array<unsigned char, 33>& key,
        uint8_t tier)
    {
        std::string data;
        data.reserve(domain.size() + key.size() + 1);
        data += domain;
        data.append(reinterpret_cast<const char*>(key.data()), key.size());
        data.push_back(static_cast<char>(tier));
        crypto::hash h;
        crypto::cn_fast_hash(data.data(), data.size(), h);
        return h;
    }

    constexpr const char* FROZEN_DOMAIN = "example..free";
    constexpr uint8_t     FROZEN_TIER   = 1;

    // FROZEN TEST VECTOR — fill in after first run.
    // Do NOT change without a deliberate protocol bump.
    constexpr const char* FROZEN_FP_HEX = "9a2664e8db7c1ded32f07b10a032feeeafc1b51a079ec8cb47869721da325f35";

    std::array<unsigned char, 33> frozen_key()
    {
        std::array<unsigned char, 33> key{};
        key[0] = 0x02;
        for (size_t i = 0; i < 32; ++i)
            key[1 + i] = static_cast<unsigned char>(i + 1);
        return key;
    }
}

TEST(vns_fingerprint, helper_matches_inline_reference)
{
    auto key = frozen_key();
    crypto::hash a = domain_utils::compute_vns_registration_fingerprint(FROZEN_DOMAIN, key, FROZEN_TIER);
    crypto::hash b = inline_fingerprint(FROZEN_DOMAIN, key, FROZEN_TIER);
    EXPECT_EQ(a, b);
}

TEST(vns_fingerprint, frozen_vector)
{
    auto key = frozen_key();
    crypto::hash h = domain_utils::compute_vns_registration_fingerprint(FROZEN_DOMAIN, key, FROZEN_TIER);
    std::string hex = epee::string_tools::pod_to_hex(h);

    if (std::string(FROZEN_FP_HEX) == "PENDING_FILL_FROM_FIRST_RUN")
    {
        std::cout << "\nFROZEN_FP_HEX=" << hex << "\n";
        ADD_FAILURE() << "Frozen vector not yet filled: paste value above into FROZEN_FP_HEX";
        return;
    }

    EXPECT_EQ(hex, std::string(FROZEN_FP_HEX));
}

TEST(vns_fingerprint, raw_key_not_hex_encoded)
{
    // Guard: swapping raw key bytes for their hex encoding must change the fingerprint.
    auto key = frozen_key();
    crypto::hash raw = domain_utils::compute_vns_registration_fingerprint(FROZEN_DOMAIN, key, FROZEN_TIER);

    std::array<unsigned char, 33> hex_encoded{};
    std::string hex = epee::string_tools::buff_to_hex_nodelimer(
        std::string(reinterpret_cast<const char*>(key.data()), key.size()));
    std::memcpy(hex_encoded.data(), hex.data(), 33);

    crypto::hash wrong = domain_utils::compute_vns_registration_fingerprint(FROZEN_DOMAIN, hex_encoded, FROZEN_TIER);
    EXPECT_NE(raw, wrong);
}

TEST(vns_fingerprint, domain_key_and_tier_all_matter)
{
    auto key = frozen_key();

    crypto::hash base = domain_utils::compute_vns_registration_fingerprint(FROZEN_DOMAIN, key, FROZEN_TIER);
    crypto::hash d2   = domain_utils::compute_vns_registration_fingerprint("other..free", key, FROZEN_TIER);
    crypto::hash t2   = domain_utils::compute_vns_registration_fingerprint(FROZEN_DOMAIN, key, 2);

    std::array<unsigned char, 33> key2 = key;
    key2[32] ^= 0x01;
    crypto::hash k2 = domain_utils::compute_vns_registration_fingerprint(FROZEN_DOMAIN, key2, FROZEN_TIER);

    EXPECT_NE(base, d2);
    EXPECT_NE(base, t2);
    EXPECT_NE(base, k2);
}