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

// Independent expected V:
//   V = (f*mask + rho)*G + (f*amount)*H
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

key expected_total_blinding(const key& mask, uint8_t f, const key& rho)
{
    key s_f;
    std::memset(s_f.bytes, 0, 32);
    s_f.bytes[0] = f;
    sc_reduce32(s_f.bytes);

    key f_mask, out;
    sc_mul(f_mask.bytes, s_f.bytes, mask.bytes);
    sc_add(out.bytes, f_mask.bytes, rho.bytes);
    return out;
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
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, mask, rho, ow));

    key expected = expected_V(mask, amount, f, rho);
    EXPECT_TRUE(ow.commitment == expected);
    EXPECT_TRUE(ow.rho_i == rho);
    EXPECT_TRUE(ow.total_blinding == expected_total_blinding(mask, f, rho));
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
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, mask, rho, ow));

    key rho_G;
    scalarmultBase(rho_G, rho);
    EXPECT_TRUE(ow.commitment == rho_G);
    EXPECT_TRUE(ow.total_blinding == rho);
    EXPECT_EQ(ow.weight, governance_weight_t(0));
}

TEST(dao_weight, different_age_factor_gives_different_commitment)
{
    const uint64_t amount = 1000000;
    key mask = mk_scalar(0x31);
    key rho  = mk_scalar(0x41);
    key C    = make_commitment(mask, amount);

    dao_output_weight a, b;
    ASSERT_TRUE(dao_commit_output_weight(amount, 4, C, mask, rho, a));
    ASSERT_TRUE(dao_commit_output_weight(amount, 5, C, mask, rho, b));
    EXPECT_FALSE(a.commitment == b.commitment);
    EXPECT_FALSE(a.weight == b.weight);
    EXPECT_FALSE(a.total_blinding == b.total_blinding);
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
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, mask, rho_a, a));
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, mask, rho_b, b));
    EXPECT_FALSE(a.commitment == b.commitment);
    EXPECT_FALSE(a.total_blinding == b.total_blinding);
    EXPECT_TRUE(a.weight == b.weight);
}

TEST(dao_weight, different_amount_gives_different_commitment_and_weight)
{
    const uint8_t f = 5;
    key mask = mk_scalar(0x81);
    key rho  = mk_scalar(0x91);

    key C_a = make_commitment(mask, 1000);
    key C_b = make_commitment(mask, 2000);

    dao_output_weight a, b;
    ASSERT_TRUE(dao_commit_output_weight(1000, f, C_a, mask, rho, a));
    ASSERT_TRUE(dao_commit_output_weight(2000, f, C_b, mask, rho, b));
    EXPECT_FALSE(a.commitment == b.commitment);
    EXPECT_LT(a.weight, b.weight);
}

TEST(dao_weight, uint64_max_amount_at_max_age_factor_is_accepted)
{
    const uint64_t amount = std::numeric_limits<uint64_t>::max();
    const uint8_t  f      = 12;

    key mask = mk_scalar(0xA1);
    key rho  = mk_scalar(0xB1);
    key C    = make_commitment(mask, amount);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, mask, rho, ow));

    const governance_weight_t expected =
        governance_weight_t(std::numeric_limits<uint64_t>::max()) * 12;

    EXPECT_EQ(ow.weight, expected);
    EXPECT_LT(ow.weight, governance_w_max());
}

TEST(dao_weight, w_max_is_exact_frozen_value)
{
    EXPECT_EQ(governance_w_max(),
              governance_weight_t("240000000000000000000"));
}

// ---- Aggregate tests (spec §19-§20) ----

TEST(dao_weight, aggregate_of_one_output)
{
    key mask = mk_scalar(0xC1);
    key rho  = mk_scalar(0xD1);
    const uint64_t amount = 1000;
    const uint8_t  f      = 5;
    key C = make_commitment(mask, amount);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(amount, f, C, mask, rho, ow));

    dao_vote_aggregate agg;
    dao_aggregate_init(agg);
    ASSERT_TRUE(dao_accumulate_output(agg, ow));

    EXPECT_TRUE(agg.C_W == ow.commitment);
    EXPECT_TRUE(agg.R_W == ow.total_blinding);
    EXPECT_EQ(agg.W_total, governance_weight_t(amount) * governance_weight_t(f));
    EXPECT_EQ(agg.num_inputs, 1u);
}

TEST(dao_weight, aggregate_of_three_outputs_yes)
{
    const uint64_t amounts[3] = { 1000, 2500, 750 };
    const uint8_t  factors[3] = { 3, 5, 4 };

    dao_vote_aggregate agg;
    dao_aggregate_init(agg);

    key expected_C_W;
    identity(expected_C_W);
    key expected_R_W;
    std::memset(expected_R_W.bytes, 0, 32);
    governance_weight_t expected_W = 0;

    for (int i = 0; i < 3; ++i)
    {
        key mask = mk_scalar(0xE0 + i);
        key rho  = mk_scalar(0xF0 + i);
        key C    = make_commitment(mask, amounts[i]);

        dao_output_weight ow;
        ASSERT_TRUE(dao_commit_output_weight(
            amounts[i], factors[i], C, mask, rho, ow));
        ASSERT_TRUE(dao_accumulate_output(agg, ow));

        addKeys(expected_C_W, expected_C_W, ow.commitment);
        sc_add(expected_R_W.bytes, expected_R_W.bytes, ow.total_blinding.bytes);
        expected_W += ow.weight;
    }

    EXPECT_TRUE(agg.C_W == expected_C_W);
    EXPECT_TRUE(agg.R_W == expected_R_W);
    EXPECT_EQ(agg.W_total, expected_W);

    key R_S = mk_scalar(0x77);
    ASSERT_TRUE(dao_finalize_aggregate(agg, true, R_S));
    EXPECT_TRUE(agg.direction_yes);
    EXPECT_TRUE(agg.R_S == R_S);
    EXPECT_TRUE(dao_verify_aggregate(agg));
}

TEST(dao_weight, aggregate_of_three_outputs_no)
{
    const uint64_t amounts[3] = { 1000, 2500, 750 };
    const uint8_t  factors[3] = { 3, 5, 4 };

    dao_vote_aggregate agg;
    dao_aggregate_init(agg);

    for (int i = 0; i < 3; ++i)
    {
        key mask = mk_scalar(0x21 + i);
        key rho  = mk_scalar(0x31 + i);
        key C    = make_commitment(mask, amounts[i]);

        dao_output_weight ow;
        ASSERT_TRUE(dao_commit_output_weight(
            amounts[i], factors[i], C, mask, rho, ow));
        ASSERT_TRUE(dao_accumulate_output(agg, ow));
    }

    key R_S = mk_scalar(0x42);
    ASSERT_TRUE(dao_finalize_aggregate(agg, false, R_S));
    EXPECT_FALSE(agg.direction_yes);
    EXPECT_TRUE(dao_verify_aggregate(agg));

    dao_vote_aggregate yes_agg = agg;
    ASSERT_TRUE(dao_finalize_aggregate(yes_agg, true, R_S));
    EXPECT_FALSE(yes_agg.C_S == agg.C_S);
}

TEST(dao_weight, tamper_C_W_breaks_verify)
{
    key mask = mk_scalar(0x51);
    key rho  = mk_scalar(0x61);
    key C    = make_commitment(mask, 1000);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(1000, 5, C, mask, rho, ow));

    dao_vote_aggregate agg;
    dao_aggregate_init(agg);
    ASSERT_TRUE(dao_accumulate_output(agg, ow));

    key R_S = mk_scalar(0x71);
    ASSERT_TRUE(dao_finalize_aggregate(agg, true, R_S));
    ASSERT_TRUE(dao_verify_aggregate(agg));

    agg.C_W.bytes[0] ^= 0x01;
    EXPECT_FALSE(dao_verify_aggregate(agg));
}

TEST(dao_weight, tamper_C_S_breaks_verify)
{
    key mask = mk_scalar(0x81);
    key rho  = mk_scalar(0x91);
    key C    = make_commitment(mask, 1000);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(1000, 5, C, mask, rho, ow));

    dao_vote_aggregate agg;
    dao_aggregate_init(agg);
    ASSERT_TRUE(dao_accumulate_output(agg, ow));

    key R_S = mk_scalar(0xA1);
    ASSERT_TRUE(dao_finalize_aggregate(agg, true, R_S));
    ASSERT_TRUE(dao_verify_aggregate(agg));

    agg.C_S.bytes[0] ^= 0x01;
    EXPECT_FALSE(dao_verify_aggregate(agg));
}

TEST(dao_weight, tamper_R_W_breaks_verify)
{
    key mask = mk_scalar(0xB1);
    key rho  = mk_scalar(0xC1);
    key C    = make_commitment(mask, 1000);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(1000, 5, C, mask, rho, ow));

    dao_vote_aggregate agg;
    dao_aggregate_init(agg);
    ASSERT_TRUE(dao_accumulate_output(agg, ow));

    key R_S = mk_scalar(0xD1);
    ASSERT_TRUE(dao_finalize_aggregate(agg, true, R_S));
    ASSERT_TRUE(dao_verify_aggregate(agg));

    agg.R_W.bytes[0] ^= 0x01;
    EXPECT_FALSE(dao_verify_aggregate(agg));
}

TEST(dao_weight, finalize_rejects_zero_inputs)
{
    dao_vote_aggregate agg;
    dao_aggregate_init(agg);
    key R_S = mk_scalar(0xE1);
    EXPECT_FALSE(dao_finalize_aggregate(agg, true, R_S));
}

TEST(dao_weight, finalize_rejects_invalid_R_S)
{
    key mask = mk_scalar(0xF1);
    key rho  = mk_scalar(0x03);
    key C    = make_commitment(mask, 1000);

    dao_output_weight ow;
    ASSERT_TRUE(dao_commit_output_weight(1000, 5, C, mask, rho, ow));

    dao_vote_aggregate agg;
    dao_aggregate_init(agg);
    ASSERT_TRUE(dao_accumulate_output(agg, ow));

    key bad_R_S;
    std::memset(bad_R_S.bytes, 0xff, 32);
    EXPECT_FALSE(dao_finalize_aggregate(agg, true, bad_R_S));
}

TEST(dao_weight, weight_to_scalar_round_trips_small_values)
{
    key s;
    dao_weight_to_scalar(governance_weight_t(0), s);
    for (int i = 0; i < 32; ++i) EXPECT_EQ(s.bytes[i], 0);

    dao_weight_to_scalar(governance_weight_t(1), s);
    EXPECT_EQ(s.bytes[0], 1);
    for (int i = 1; i < 32; ++i) EXPECT_EQ(s.bytes[i], 0);

    governance_weight_t big = (governance_weight_t(1) << 64) + 7;
    dao_weight_to_scalar(big, s);
    EXPECT_EQ(s.bytes[0], 7);
    for (int i = 1; i < 8; ++i) EXPECT_EQ(s.bytes[i], 0);
    EXPECT_EQ(s.bytes[8], 1);
    for (int i = 9; i < 32; ++i) EXPECT_EQ(s.bytes[i], 0);
}