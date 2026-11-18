// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Canonicality and length-framing tests for
// dao_aggregate_ciphertext_hash. The pre-4.10 implementation rejected
// any input that was not exactly 512 bytes and returned
// the all-zero sentinel, which silently zeroed the hash for every
// variable-length CL ciphertext wire. These tests lock in the
// scheme-agnostic replacement.

#include "gtest/gtest.h"

#include "governance/dao_tally.h"

#include <cstring>
#include <vector>

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

void expect_nonzero(const crypto::hash& h)
{
    for (int i = 0; i < 32; ++i)
        ASSERT_NE(static_cast<uint8_t>(h.data[i]), 0u) << "byte " << i;
}

} // namespace

TEST(dao_aggregate_ciphertext_hash, nonzero_for_paillier_width_inputs)
{
    // Preserves the old Paillier callers: 512-byte payloads still
    // produce a valid hash (length-framed, not fixed-size gated).
    std::vector<uint8_t> W(512, 0xA1);
    std::vector<uint8_t> S(512, 0xB2);
    std::vector<uint8_t> B(512, 0xC3);
    expect_nonzero(dao_aggregate_ciphertext_hash(W, S, B));
}

TEST(dao_aggregate_ciphertext_hash, nonzero_for_cl_style_variable_length)
{
    // QFI pair wire (2 x QFI = 97 bytes for 128-bit security) is a
    // plausible CL ciphertext width. Old implementation returned the
    // all-zero sentinel here; CL tally shares and certificates were
    // therefore not binding to the aggregate ciphertexts.
    std::vector<uint8_t> W(97, 0x11);
    std::vector<uint8_t> S(97, 0x22);
    std::vector<uint8_t> B(97, 0x33);
    expect_nonzero(dao_aggregate_ciphertext_hash(W, S, B));
}

TEST(dao_aggregate_ciphertext_hash, empty_returns_zero_sentinel)
{
    crypto::hash h = dao_aggregate_ciphertext_hash({}, {}, {});
    for (int i = 0; i < 32; ++i)
        ASSERT_EQ(static_cast<uint8_t>(h.data[i]), 0u) << "byte " << i;
}

TEST(dao_aggregate_ciphertext_hash, byte_change_in_W_changes_hash)
{
    std::vector<uint8_t> W(97, 0x11); std::vector<uint8_t> W2 = W; W2[0] ^= 1;
    std::vector<uint8_t> S(97, 0x22), B(97, 0x33);
    crypto::hash h1 = dao_aggregate_ciphertext_hash(W,  S, B);
    crypto::hash h2 = dao_aggregate_ciphertext_hash(W2, S, B);
    ASSERT_NE(std::memcmp(h1.data, h2.data, 32), 0);
}

TEST(dao_aggregate_ciphertext_hash, byte_change_in_S_changes_hash)
{
    std::vector<uint8_t> S(97, 0x22); std::vector<uint8_t> S2 = S; S2[0] ^= 1;
    std::vector<uint8_t> W(97, 0x11), B(97, 0x33);
    crypto::hash h1 = dao_aggregate_ciphertext_hash(W, S,  B);
    crypto::hash h2 = dao_aggregate_ciphertext_hash(W, S2, B);
    ASSERT_NE(std::memcmp(h1.data, h2.data, 32), 0);
}

TEST(dao_aggregate_ciphertext_hash, byte_change_in_B_changes_hash)
{
    std::vector<uint8_t> B(97, 0x33); std::vector<uint8_t> B2 = B; B2[0] ^= 1;
    std::vector<uint8_t> W(97, 0x11), S(97, 0x22);
    crypto::hash h1 = dao_aggregate_ciphertext_hash(W, S, B);
    crypto::hash h2 = dao_aggregate_ciphertext_hash(W, S, B2);
    ASSERT_NE(std::memcmp(h1.data, h2.data, 32), 0);
}

TEST(dao_aggregate_ciphertext_hash, no_length_boundary_ambiguity_concat)
{
    // Naive concatenation ("AA"+"BBBB"+"CC" vs "AABB"+"BB"+"CC")
    // would collide without length framing.
    std::vector<uint8_t> W1 = {0xAA};
    std::vector<uint8_t> S1 = {0xBB, 0xBB, 0xBB};
    std::vector<uint8_t> B  = {0xCC};
    crypto::hash h1 = dao_aggregate_ciphertext_hash(W1, S1, B);

    std::vector<uint8_t> W2 = {0xAA, 0xBB, 0xBB};
    std::vector<uint8_t> S2 = {0xBB};
    crypto::hash h2 = dao_aggregate_ciphertext_hash(W2, S2, B);
    ASSERT_NE(std::memcmp(h1.data, h2.data, 32), 0);
}

TEST(dao_aggregate_ciphertext_hash, same_prefix_different_length_differs)
{
    // W="AA" vs W="AA00": length frame must distinguish.
    std::vector<uint8_t> W1 = {0xAA};
    std::vector<uint8_t> W2 = {0xAA, 0x00};
    std::vector<uint8_t> S  = {0xBB};
    std::vector<uint8_t> B  = {0xCC};
    crypto::hash h1 = dao_aggregate_ciphertext_hash(W1, S, B);
    crypto::hash h2 = dao_aggregate_ciphertext_hash(W2, S, B);
    ASSERT_NE(std::memcmp(h1.data, h2.data, 32), 0);
}
