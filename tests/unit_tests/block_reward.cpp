// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Fixed-subsidy reward tests. VeilRoot mints a fixed 0.65 VNS per block,
// clamped to remaining supply, with no block-weight penalty and no
// dynamic-reward inputs. Transaction fees are burned, not paid to the
// miner or the treasury.

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_basic_impl.h"

using namespace cryptonote;

TEST(vns_block_reward, fixed_subsidy)
{
  uint64_t reward = 0;
  EXPECT_TRUE(get_block_reward(0, 0, 0, reward, 1));
  EXPECT_EQ(VNS_BLOCK_SUBSIDY, reward);

  EXPECT_TRUE(get_block_reward(1, 1000000, 0, reward, 255));
  EXPECT_EQ(VNS_BLOCK_SUBSIDY, reward);
}

TEST(vns_block_reward, remains_fixed_independent_of_weight)
{
  uint64_t reward_a = 0;
  uint64_t reward_b = 0;

  EXPECT_TRUE(get_block_reward(100, 100, 0, reward_a, 1));
  EXPECT_TRUE(get_block_reward(100, 199, 0, reward_b, 1));

  EXPECT_EQ(VNS_BLOCK_SUBSIDY, reward_a);
  EXPECT_EQ(reward_a, reward_b);
}

TEST(vns_block_reward, clamps_to_remaining_supply)
{
  uint64_t reward = 0;

  EXPECT_TRUE(get_block_reward(
      0, 0,
      VNS_MAX_SUPPLY_ATOMIC - static_cast<vns_supply_t>(VNS_BLOCK_SUBSIDY),
      reward, 1));
  EXPECT_EQ(VNS_BLOCK_SUBSIDY, reward);

  EXPECT_TRUE(get_block_reward(
      0, 0, VNS_MAX_SUPPLY_ATOMIC - 123, reward, 1));
  EXPECT_EQ(123, reward);
}

TEST(vns_block_reward, zero_at_cap)
{
  uint64_t reward = 123;

  EXPECT_TRUE(get_block_reward(
      0, 0, VNS_MAX_SUPPLY_ATOMIC, reward, 1));
  EXPECT_EQ(0, reward);
}

TEST(vns_block_reward, rejects_supply_above_cap)
{
  uint64_t reward = 123;

  EXPECT_FALSE(get_block_reward(
      0, 0, VNS_MAX_SUPPLY_ATOMIC + 1, reward, 1));
  EXPECT_EQ(0, reward);
}

TEST(vns_supply_serialization, preserves_full_width)
{
  EXPECT_EQ("0", vns_supply_to_decimal(0));
  EXPECT_EQ(
      "18446744073709551616",
      vns_supply_to_decimal(
          static_cast<vns_supply_t>(UINT64_MAX) + 1));
  EXPECT_EQ(
      "20000000000000000000",
      vns_supply_to_decimal(VNS_MAX_SUPPLY_ATOMIC));
}
