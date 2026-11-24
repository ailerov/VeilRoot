// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// V2 final tally tests. Exercise the certificate build/verify pipeline
// and the pure governance rule evaluator. Also prove the quorum-vs-
// majority independence: large W with small B fails quorum; small W
// with large B fails majority.

#include <cstring>
#include <vector>

#include "gtest/gtest.h"

#include <openssl/bn.h>

#include "governance/dao_tally.h"
#include "governance/dao_supply.h"

using namespace cryptonote;
using namespace cryptonote::dao;

#ifdef VEILROOT_DAO_DKG_TESTING
namespace cryptonote { namespace dao {
bool dao_test_bn_to_u128(const BIGNUM* b, dao_u128& out);
}}
#endif

namespace {

// --- Pure evaluator tests ---

TEST(dao_evaluate_v2_tally, both_pass)
{
    dao_u128 qthr; bool qmet, mmet, passed;
    ASSERT_TRUE(dao_evaluate_v2_tally(
        /*yes*/   dao_u128(6000),
        /*no*/    dao_u128(4000),
        /*B*/     dao_u128(2000),
        /*circ*/  dao_u128(10000),
        /*pct*/   10,
        qthr, qmet, mmet, passed));
    EXPECT_EQ(qthr, dao_u128(1000));
    EXPECT_TRUE(qmet);
    EXPECT_TRUE(mmet);
    EXPECT_TRUE(passed);
}

TEST(dao_evaluate_v2_tally, large_W_small_B_fails_quorum)
{
    dao_u128 qthr; bool qmet, mmet, passed;
    ASSERT_TRUE(dao_evaluate_v2_tally(
        /*yes*/   dao_u128(100000),  // big weight
        /*no*/    dao_u128(50000),
        /*B*/     dao_u128(500),     // small coins
        /*circ*/  dao_u128(10000),
        /*pct*/   10,
        qthr, qmet, mmet, passed));
    EXPECT_EQ(qthr, dao_u128(1000));
    EXPECT_FALSE(qmet);
    EXPECT_TRUE(mmet);
    EXPECT_FALSE(passed);
}

TEST(dao_evaluate_v2_tally, small_W_large_B_fails_majority)
{
    dao_u128 qthr; bool qmet, mmet, passed;
    ASSERT_TRUE(dao_evaluate_v2_tally(
        /*yes*/   dao_u128(100),   // small weight, loses majority
        /*no*/    dao_u128(200),
        /*B*/     dao_u128(5000),  // plenty of coins
        /*circ*/  dao_u128(10000),
        /*pct*/   10,
        qthr, qmet, mmet, passed));
    EXPECT_TRUE(qmet);
    EXPECT_FALSE(mmet);
    EXPECT_FALSE(passed);
}

TEST(dao_evaluate_v2_tally, same_B_different_W_quorum_unchanged)
{
    dao_u128 qthr1, qthr2; bool q1, m1, p1, q2, m2, p2;
    ASSERT_TRUE(dao_evaluate_v2_tally(
        dao_u128(1000), dao_u128(1000), dao_u128(5000),
        dao_u128(10000), 10, qthr1, q1, m1, p1));
    ASSERT_TRUE(dao_evaluate_v2_tally(
        dao_u128(9999), dao_u128(1), dao_u128(5000),
        dao_u128(10000), 10, qthr2, q2, m2, p2));
    EXPECT_EQ(qthr1, qthr2);
    EXPECT_EQ(q1, q2);
    EXPECT_TRUE(q1);
}

TEST(dao_evaluate_v2_tally, threshold_floors)
{
    dao_u128 qthr; bool qmet, mmet, passed;
    // 999 * 10 / 100 = 99 (floor), so B=99 passes, B=98 fails.
    ASSERT_TRUE(dao_evaluate_v2_tally(
        dao_u128(1), dao_u128(0), dao_u128(98),
        dao_u128(999), 10, qthr, qmet, mmet, passed));
    EXPECT_EQ(qthr, dao_u128(99));
    EXPECT_FALSE(qmet);
    ASSERT_TRUE(dao_evaluate_v2_tally(
        dao_u128(1), dao_u128(0), dao_u128(99),
        dao_u128(999), 10, qthr, qmet, mmet, passed));
    EXPECT_TRUE(qmet);
}

TEST(dao_evaluate_v2_tally, percent_out_of_range_rejected)
{
    dao_u128 qthr; bool qmet, mmet, passed;
    EXPECT_FALSE(dao_evaluate_v2_tally(
        dao_u128(0), dao_u128(0), dao_u128(0),
        dao_u128(0), 101, qthr, qmet, mmet, passed));
}


TEST(dao_tally_share_set_id, interprets_hash_bytes_as_unsigned)
{
    std::vector<std::uint8_t> key_id(32, 0);
    crypto::hash digest{};
    bool found_sign_sensitive_digest = false;

    // Find deterministic input whose digest has a high-bit byte among
    // positions 0..2, where signed-char promotion changes the result.
    for (std::uint32_t seed = 0;
         seed < 256 && !found_sign_sensitive_digest; ++seed) {
        for (std::size_t i = 0; i < key_id.size(); ++i) {
            key_id[i] = static_cast<std::uint8_t>(
                (seed + 29u * static_cast<std::uint32_t>(i)) & 0xffu);
        }

        std::vector<std::uint8_t> input(key_id.begin(), key_id.end());
        const char* tag = "share_set_id";
        input.insert(input.end(), tag, tag + 13);
        digest = crypto::cn_fast_hash(input.data(), input.size());

        for (int i = 0; i < 3; ++i) {
            if ((static_cast<std::uint8_t>(digest.data[i]) & 0x80u) != 0) {
                found_sign_sensitive_digest = true;
                break;
            }
        }
    }

    ASSERT_TRUE(found_sign_sensitive_digest);

    std::uint32_t expected = 0;
    for (int i = 0; i < 4; ++i) {
        const auto byte = static_cast<std::uint8_t>(digest.data[i]);
        expected |= static_cast<std::uint32_t>(byte) << (8 * i);
    }

    expected &= 0xFFFFFFFEu;
    if (expected < 2) expected = 2;

    EXPECT_EQ(share_set_id_for_key_id(key_id), expected);
}

#ifdef VEILROOT_DAO_DKG_TESTING
// --- decoder overflow tests ---

TEST(dao_tally_decode, bn_to_u128_accepts_2p128_minus_1)
{
    BIGNUM* b = BN_new();
    BN_one(b); BN_lshift(b, b, 128); BN_sub_word(b, 1);
    dao_u128 out = 0;
    EXPECT_TRUE(dao_test_bn_to_u128(b, out));
    EXPECT_EQ(out, (dao_u128(1) << 128) - 1);
    BN_free(b);
}

TEST(dao_tally_decode, bn_to_u128_rejects_2p128)
{
    BIGNUM* b = BN_new();
    BN_one(b); BN_lshift(b, b, 128);
    dao_u128 out = 0;
    EXPECT_FALSE(dao_test_bn_to_u128(b, out));
    BN_free(b);
}

TEST(dao_tally_decode, bn_to_u128_rejects_negative)
{
    BIGNUM* b = BN_new();
    BN_set_word(b, 5); BN_set_negative(b, 1);
    dao_u128 out = 0;
    EXPECT_FALSE(dao_test_bn_to_u128(b, out));
    BN_free(b);
}
#endif

} // namespace
