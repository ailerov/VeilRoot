// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <limits>
#include <vector>

#include "gtest/gtest.h"

#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "governance/dao_weight.h"

using namespace cryptonote;
using namespace rct;

namespace {

key mk_scalar(uint8_t seed)
{
    key k;
    std::memset(k.bytes, 0, 32);
    k.bytes[0]  = seed;
    k.bytes[31] = static_cast<uint8_t>(seed ^ 0xA5);
    sc_reduce32(k.bytes);
    return k;
}

// Build C = mask*G + amount*H for a test output.
key make_commitment(const key& mask, uint64_t amount)
{
    key mask_G, amount_H, C;
    scalarmultBase(mask_G, mask);

    key s_amount;
    std::memset(s_amount.bytes, 0, 32);
    for (int i = 0; i < 8; ++i)
        s_amount.bytes[i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xff);
    sc_reduce32(s_amount.bytes);

    scalarmultKey(amount_H, H, s_amount);
    addKeys(C, mask_G, amount_H);
    return C;
}

// Independent expected V from scalars:
//   V = (f * mask + rho) * G + (f * amount) * H
key expected_V(const key& mask, uint64_t amount, uint8_t f, const key& rho)
{
    key s_f;
    std::memset(s_f.bytes, 0, 32);
    s_f.bytes[0] = f;
    sc_reduce32(s_f.bytes);

    key s_amount;
    std::memset(s_amount.bytes, 0, 32);
    for (int i = 0; i < 8; ++i)
        s_amount.bytes[i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xff);
    sc_reduce32(s_amount.bytes);

    key f_mask, f_amount, blind;
    sc_mul(f_mask.bytes,   s_f.bytes, mask.bytes);
    sc_mul(f_amount.bytes, s_f.bytes, s_amount.bytes);
    sc_add(blind.bytes, f_mask.bytes, rho.bytes);

    key blind_G, amount_H;
    scalarmultBase(blind_G, blind);
    scalarmultKey(amount_H, H, f_amount);
    key V;
    addKeys(V, blind_G, amount_H);
    return V;
}

} // namespace

TEST(dao_weight, commitment_matches_pedersen_expansion)
{
    const uint64_t amount = 1000000;
    const uint8_t  f      = 5;

    key mask = mk_scalar(0x11);
    key rho  = mk_scalar(0x77);
    key C    = make_commitment(mask, amount);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, rho, ow));

    key expected = expected_V(mask, amount, f, rho);
    EXPECT_TRUE(ow.commitment == expected);
    EXPECT_TRUE(ow.blinding == rho);
    EXPECT_EQ(ow.weight, governance_weight_t(amount) * governance_weight_t(f));
}

TEST(dao_weight, zero_age_factor_is_identity_plus_blind)
{
    const uint64_t amount = 500000;
    const uint8_t  f      = 0;

    key mask = mk_scalar(0x21);
    key rho  = mk_scalar(0x33);
    key C    = make_commitment(mask, amount);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, rho, ow));

    // V_i should equal rho*G.
    key rho_G;
    scalarmultBase(rho_G, rho);
    EXPECT_TRUE(ow.commitment == rho_G);

    // Weight is zero.
    EXPECT_EQ(ow.weight, governance_weight_t(0));
}

TEST(dao_weight, different_age_factor_gives_different_commitment)
{
    const uint64_t amount = 1000000;
    key mask = mk_scalar(0x31);
    key rho  = mk_scalar(0x41);
    key C    = make_commitment(mask, amount);

    dao_output_weight a, b;
    ASSERT_TRUE(dao_commit_output_weight(amount, 4, C, rho, a));
    ASSERT_TRUE(dao_commit_output_weight(amount, 5, C, rho, b));
    EXPECT_FALSE(a.commitment == b.commitment);
    EXPECT_FALSE(a.weight == b.weight);
}

TEST(dao_weight, different_rho_gives_different_commitment)
{
    const uint64_t amount = 1000000;
    const uint8_t  f      = 5;
    key mask = mk_scalar(0x51);
    key C    = make_commitment(mask, amount);

    key rho_a = mk_scalar(0x61);
    key rho_b = mk_scalar(0x71);

    dao_output_weight a, b;
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, rho_a, a));
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, rho_b, b));
    EXPECT_FALSE(a.commitment == b.commitment);
    EXPECT_TRUE(a.weight == b.weight);   // weight unchanged
}

TEST(dao_weight, different_amount_gives_different_commitment_and_weight)
{
    const uint8_t f = 5;
    key mask = mk_scalar(0x81);
    key rho  = mk_scalar(0x91);

    key C_a = make_commitment(mask, 1000);
    key C_b = make_commitment(mask, 2000);

    dao_output_weight a, b;
    ASSERT_TRUE(dao_commit_output_weight(1000, f, C_a, rho, a));
    ASSERT_TRUE(dao_commit_output_weight(2000, f, C_b, rho, b));
    EXPECT_FALSE(a.commitment == b.commitment);
    EXPECT_LT(a.weight, b.weight);
}

TEST(dao_weight, uint64_max_amount_at_max_age_factor_is_accepted)
{
    // A single RingCT output's amount is a uint64_t, so the per-output
    // ceiling is UINT64_MAX atomic units (~18.45M VNS), not the 20M VNS
    // aggregate supply cap. W_MAX is only reachable in aggregate.
    const uint64_t amount = std::numeric_limits<uint64_t>::max();
    const uint8_t  f      = 12;

    key mask = mk_scalar(0xA1);
    key rho  = mk_scalar(0xB1);
    key C    = make_commitment(mask, amount);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, rho, ow));

    // Exact expected weight: UINT64_MAX * 12.
    const governance_weight_t expected =
        governance_weight_t(std::numeric_limits<uint64_t>::max()) * 12;

    EXPECT_EQ(ow.weight, expected);

    // Sanity: a single output's maximum weight is below W_MAX.
    EXPECT_LT(ow.weight, governance_w_max());
}

TEST(dao_weight, w_max_is_exact_frozen_value)
{
    EXPECT_EQ(governance_w_max(),
              governance_weight_t("240000000000000000000"));
}