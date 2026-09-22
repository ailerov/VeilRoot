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
    crypto::hash inline_transfer_hash(
        const std::string& domain,
        const std::array<unsigned char, 32>& xonly)
    {
        std::string data;
        data += domain;
        data.append(reinterpret_cast<const char*>(xonly.data()), xonly.size());
        crypto::hash h;
        crypto::cn_fast_hash(data.data(), data.size(), h);
        return h;
    }

    constexpr const char* FROZEN_DOMAIN = "example..free";
    constexpr const char* FROZEN_TRANSFER_HEX = "09fc086486606457b35d48e8daf03103e2d8dd4c0e02cb6a852999082dbbf7ce";

    std::array<unsigned char, 32> frozen_xonly()
    {
        std::array<unsigned char, 32> k{};
        for (size_t i = 0; i < 32; ++i)
            k[i] = static_cast<unsigned char>(0xA0 + i);
        return k;
    }
}

TEST(vns_transfer, helper_matches_inline_reference)
{
    auto k = frozen_xonly();
    EXPECT_EQ(domain_utils::compute_vns_transfer_message_hash(FROZEN_DOMAIN, k),
              inline_transfer_hash(FROZEN_DOMAIN, k));
}

TEST(vns_transfer, frozen_vector)
{
    auto k = frozen_xonly();
    std::string hex = epee::string_tools::pod_to_hex(
        domain_utils::compute_vns_transfer_message_hash(FROZEN_DOMAIN, k));

    if (std::string(FROZEN_TRANSFER_HEX) == "PENDING_FILL_FROM_FIRST_RUN")
    {
        std::cout << "\nFROZEN_TRANSFER_HEX=" << hex << "\n";
        ADD_FAILURE() << "Frozen vector not yet filled";
        return;
    }
    EXPECT_EQ(hex, std::string(FROZEN_TRANSFER_HEX));
}

TEST(vns_transfer, domain_and_key_both_matter)
{
    auto k = frozen_xonly();
    crypto::hash base = domain_utils::compute_vns_transfer_message_hash(FROZEN_DOMAIN, k);
    crypto::hash d2   = domain_utils::compute_vns_transfer_message_hash("other..free", k);
    auto k2 = k; k2[31] ^= 0x01;
    crypto::hash k3 = domain_utils::compute_vns_transfer_message_hash(FROZEN_DOMAIN, k2);
    EXPECT_NE(base, d2);
    EXPECT_NE(base, k3);
}