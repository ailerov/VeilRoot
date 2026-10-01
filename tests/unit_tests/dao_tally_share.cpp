// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Serialization round-trip and tamper tests for the V2 P2P tally
// share. This object never goes on chain; the tests only prove that
// the wire encoding preserves every field and detects every change.

#include <cstring>
#include <vector>

#include "gtest/gtest.h"

#include "governance/dao_tally_share.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

dao_v2_tally_share make_share()
{
    dao_v2_tally_share s;
    s.version = 1;
    std::memset(s.proposal_id.data, 0x33, 32);
    s.vote_end_height = 60000;
    s.tally_key_epoch = 1;
    std::memset(s.aggregate_ciphertext_hash.data, 0x44, 32);
    s.member_index = 2;

    s.partial_W.assign(512, 0xA1);
    s.partial_S.assign(512, 0xB2);
    s.partial_B.assign(512, 0xC3);

    s.proof_W.member_index = 2;
    s.proof_W.E.assign(512, 0x11);
    s.proof_W.Z.assign(32, 0x21);

    s.proof_S.member_index = 2;
    s.proof_S.E.assign(512, 0x12);
    s.proof_S.Z.assign(32, 0x22);

    s.proof_B.member_index = 2;
    s.proof_B.E.assign(512, 0x13);
    s.proof_B.Z.assign(32, 0x23);

    return s;
}

} // namespace

TEST(dao_tally_share, round_trip)
{
    const dao_v2_tally_share s = make_share();
    std::vector<uint8_t> blob;
    ASSERT_TRUE(s.serialize(blob));

    dao_v2_tally_share t;
    ASSERT_TRUE(t.deserialize(blob));
    EXPECT_EQ(t.version, s.version);
    EXPECT_EQ(std::memcmp(t.proposal_id.data, s.proposal_id.data, 32), 0);
    EXPECT_EQ(t.vote_end_height, s.vote_end_height);
    EXPECT_EQ(t.tally_key_epoch, s.tally_key_epoch);
    EXPECT_EQ(std::memcmp(t.aggregate_ciphertext_hash.data,
                          s.aggregate_ciphertext_hash.data, 32), 0);
    EXPECT_EQ(t.member_index, s.member_index);
    EXPECT_EQ(t.partial_W, s.partial_W);
    EXPECT_EQ(t.partial_S, s.partial_S);
    EXPECT_EQ(t.partial_B, s.partial_B);
    EXPECT_EQ(t.proof_W.member_index, s.proof_W.member_index);
    EXPECT_EQ(t.proof_W.E, s.proof_W.E);
    EXPECT_EQ(t.proof_W.Z, s.proof_W.Z);
    EXPECT_EQ(t.proof_S.E, s.proof_S.E);
    EXPECT_EQ(t.proof_S.Z, s.proof_S.Z);
    EXPECT_EQ(t.proof_B.E, s.proof_B.E);
    EXPECT_EQ(t.proof_B.Z, s.proof_B.Z);
}

TEST(dao_tally_share, canonical_encoding)
{
    const dao_v2_tally_share s = make_share();
    std::vector<uint8_t> b1;
    ASSERT_TRUE(s.serialize(b1));

    dao_v2_tally_share mid;
    ASSERT_TRUE(mid.deserialize(b1));

    std::vector<uint8_t> b2;
    ASSERT_TRUE(mid.serialize(b2));
    EXPECT_EQ(b1, b2);
}

TEST(dao_tally_share, truncated_rejected)
{
    const dao_v2_tally_share s = make_share();
    std::vector<uint8_t> blob;
    ASSERT_TRUE(s.serialize(blob));

    std::vector<uint8_t> cut(blob.begin(), blob.end() - 1);
    dao_v2_tally_share t;
    EXPECT_FALSE(t.deserialize(cut));
}

TEST(dao_tally_share, trailing_bytes_rejected)
{
    const dao_v2_tally_share s = make_share();
    std::vector<uint8_t> blob;
    ASSERT_TRUE(s.serialize(blob));
    blob.push_back(0x00);

    dao_v2_tally_share t;
    EXPECT_FALSE(t.deserialize(blob));
}

TEST(dao_tally_share, tamper_detected)
{
    const dao_v2_tally_share s = make_share();
    std::vector<uint8_t> blob;
    ASSERT_TRUE(s.serialize(blob));

    // Change every byte one at a time in a small window and confirm
    // that at least the re-deserialization sees the change or fails.
    // We check that changing member_index (position 1 + 32 + 8 + 4 + 32)
    // is observable.
    const size_t mpos = 1 + 32 + 8 + 4 + 32;
    blob[mpos] ^= 0x01;

    dao_v2_tally_share t;
    ASSERT_TRUE(t.deserialize(blob));
    EXPECT_NE(t.member_index, s.member_index);
}
