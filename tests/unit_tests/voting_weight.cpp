// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <limits>
#include <string>

#include "gtest/gtest.h"
#include "governance/voting_weight.h"

using namespace cryptonote;

namespace {

static std::string to_dec(const governance_weight_t& w) { return w.str(); }

// -------------------- floor_log2 --------------------

TEST(voting_weight_floor_log2, zero_returns_zero)
{
    EXPECT_EQ(0u, floor_log2(0));
}

TEST(voting_weight_floor_log2, one_returns_zero)
{
    EXPECT_EQ(0u, floor_log2(1));
}

TEST(voting_weight_floor_log2, exact_powers_of_two)
{
    EXPECT_EQ(1u,  floor_log2(2));
    EXPECT_EQ(2u,  floor_log2(4));
    EXPECT_EQ(3u,  floor_log2(8));
    EXPECT_EQ(4u,  floor_log2(16));
    EXPECT_EQ(5u,  floor_log2(32));
    EXPECT_EQ(8u,  floor_log2(256));
    EXPECT_EQ(16u, floor_log2(uint64_t(1) << 16));
    EXPECT_EQ(32u, floor_log2(uint64_t(1) << 32));
    EXPECT_EQ(62u, floor_log2(uint64_t(1) << 62));
    EXPECT_EQ(63u, floor_log2(uint64_t(1) << 63));
}

TEST(voting_weight_floor_log2, non_powers_of_two)
{
    EXPECT_EQ(1u, floor_log2(3));
    EXPECT_EQ(2u, floor_log2(5));
    EXPECT_EQ(2u, floor_log2(7));
    EXPECT_EQ(3u, floor_log2(9));
    EXPECT_EQ(3u, floor_log2(15));
    EXPECT_EQ(4u, floor_log2(17));
    EXPECT_EQ(4u, floor_log2(31));
    EXPECT_EQ(5u, floor_log2(33));
}

// -------------------- calculate_voting_weight: basics --------------------

TEST(voting_weight_calculation, zero_amount_is_zero)
{
    governance_weight_t w(999);
    ASSERT_TRUE(calculate_voting_weight(0, 100, 100000, w));
    EXPECT_EQ("0", to_dec(w));
}

TEST(voting_weight_calculation, zero_age_is_zero)
{
    governance_weight_t w(999);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 100, w));
    EXPECT_EQ("0", to_dec(w));
}

TEST(voting_weight_calculation, negative_age_rejected)
{
    governance_weight_t w(999);
    EXPECT_FALSE(calculate_voting_weight(1000, 200, 100, w));
}

// -------------------- Fixed-day expectations --------------------
// 1 day = 720 blocks.

TEST(voting_weight_calculation, one_day_factor_one)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 820, w));
    EXPECT_EQ("1000", to_dec(w));
}

TEST(voting_weight_calculation, two_days_factor_one)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 1540, w));
    EXPECT_EQ("1000", to_dec(w));
}

TEST(voting_weight_calculation, three_days_factor_two)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 2260, w));
    EXPECT_EQ("2000", to_dec(w));
}

TEST(voting_weight_calculation, seven_days_factor_three)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 5140, w));
    EXPECT_EQ("3000", to_dec(w));
}

TEST(voting_weight_calculation, thirty_days_factor_four)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 21700, w));
    EXPECT_EQ("4000", to_dec(w));
}

TEST(voting_weight_calculation, one_year_factor_eight)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 100 + 720 * 365, w));
    EXPECT_EQ("8000", to_dec(w));
}

TEST(voting_weight_calculation, partial_days_round_down)
{
    // 3960 blocks = 5.5 days -> age_days = 5 -> floor_log2(6) = 2
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 4060, w));
    EXPECT_EQ("2000", to_dec(w));
}

// -------------------- 20-year age cap --------------------

TEST(voting_weight_calculation, age_cap_boundary_7299)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 100 + 720 * 7299, w));
    EXPECT_EQ("12000", to_dec(w));
}

TEST(voting_weight_calculation, age_cap_boundary_7300)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 100 + 720 * 7300, w));
    EXPECT_EQ("12000", to_dec(w));
}

TEST(voting_weight_calculation, age_cap_exceeded_7301)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 100 + 720 * 7301, w));
    EXPECT_EQ("12000", to_dec(w));
}

TEST(voting_weight_calculation, age_cap_exceeded_10000)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1000, 100, 100 + 720 * 10000, w));
    EXPECT_EQ("12000", to_dec(w));
}

TEST(voting_weight_calculation, age_cap_saturates_factor_at_12)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1, 0, 720 * 4096, w));
    EXPECT_EQ("12", to_dec(w));
}

// -------------------- Exact 128-bit representation --------------------

TEST(voting_weight_calculation, individual_weight_can_exceed_uint64)
{
    // 2,000,000 VNS = 2e18 atomic, at 20-year cap (factor 12)
    // weight = 2.4e19 > UINT64_MAX
    const uint64_t amount = uint64_t(2000000000000000000ULL);
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(amount, 100, 100 + 720 * 7300, w));

    EXPECT_EQ("24000000000000000000", to_dec(w));
    EXPECT_GT(w, governance_weight_t(std::numeric_limits<uint64_t>::max()));
}

TEST(voting_weight_calculation, uint64_max_amount_at_max_age)
{
    // UINT64_MAX * 12 = 221360928884514619380
    const uint64_t amount = std::numeric_limits<uint64_t>::max();
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(amount, 0, 720 * 7300, w));
    EXPECT_EQ("221360928884514619380", to_dec(w));
}

// -------------------- Linearity / determinism --------------------

TEST(voting_weight_calculation, linear_in_amount)
{
    governance_weight_t w1(0), w2(0);
    ASSERT_TRUE(calculate_voting_weight(12345, 100, 100 + 720 * 365, w1));
    ASSERT_TRUE(calculate_voting_weight(12345 * 2, 100, 100 + 720 * 365, w2));
    EXPECT_EQ(w2, w1 * 2);
}

TEST(voting_weight_calculation, deterministic)
{
    governance_weight_t a(0), b(0);
    ASSERT_TRUE(calculate_voting_weight(1000000, 1000, 100000, a));
    ASSERT_TRUE(calculate_voting_weight(1000000, 1000, 100000, b));
    EXPECT_EQ(a, b);
}

// -------------------- Min nonzero --------------------

TEST(voting_weight_calculation, minimum_nonzero)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1, 100, 820, w));
    EXPECT_EQ("1", to_dec(w));
}

TEST(voting_weight_calculation, minimum_with_zero_age)
{
    governance_weight_t w(0);
    ASSERT_TRUE(calculate_voting_weight(1, 100, 100, w));
    EXPECT_EQ("0", to_dec(w));
}

} // namespace