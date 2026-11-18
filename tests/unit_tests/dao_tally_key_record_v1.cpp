// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"

#include <cstring>
#include <vector>

namespace cryptonote {
namespace dao {
namespace {

static dao_tally_key_record make_record()
{
    dao_tally_key_record r;
    r.version        = 2;
    r.committee_size = 3;
    r.threshold      = 2;
    r.t              = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.activation_height = 100;
    r.dkg_transcript_hash.assign(32, 0x99);
    r.key_id.assign(32, 0x55);
    r.cl_modulus.assign(48, 0xAA);
    return r;
}



TEST(DaoTallyKeyRecordClModulus, cl_modulus_is_last_field)
{
    // Guard against future reordering: appending any trailing byte
    // after cl_modulus must be rejected.
    auto r = make_record();
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    wire.push_back(0);
    dao_tally_key_record r2;
    EXPECT_FALSE(r2.deserialize(wire));
}

TEST(DaoTallyKeyRecordClModulus, cl_modulus_affects_key_id_digest)
{
    auto r1 = make_record();
    auto r2 = make_record();
    r2.cl_modulus.assign(48, 0xBB);

    auto with_zero_kid = [](dao_tally_key_record r) {
        r.key_id.assign(32, 0);
        std::vector<uint8_t> w;
        (void)r.serialize(w);
        return w;
    };

    auto w1 = with_zero_kid(r1);
    auto w2 = with_zero_kid(r2);
    EXPECT_NE(w1, w2);
}

TEST(DaoTallyKeyRecordClModulus, cl_roundtrip)
{
    dao_tally_key_record r;
    r.committee_size = 3;
    r.threshold      = 2;
    r.t              = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.cl_modulus = std::vector<uint8_t>(48, 0xAA);
    r.activation_height = 100;
    r.dkg_transcript_hash.assign(32, 0x99);
    r.key_id.assign(32, 0x55);

    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    ASSERT_GE(wire.size(), 4u);
    EXPECT_EQ(wire[0], 2u);

    dao_tally_key_record r2;
    ASSERT_TRUE(r2.deserialize(wire));
    EXPECT_EQ(r2.version, 2u);
    EXPECT_EQ(r2.committee_size, 3u);
    EXPECT_EQ(r2.threshold, 2u);
    EXPECT_EQ(r2.cl_modulus, r.cl_modulus);
    EXPECT_EQ(r2.key_id, r.key_id);
    EXPECT_EQ(r2.committee_members, r.committee_members);
}

TEST(DaoTallyKeyRecordClModulus, cl_serialize_rejects_empty_modulus)
{
    dao_tally_key_record r;
    r.committee_size = 3;
    r.threshold      = 2;
    r.t              = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.dkg_transcript_hash.assign(32, 0x99);
    r.key_id.assign(32, 0x55);
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoTallyKeyRecordClModulus, cl_rejects_wrong_wire_version)
{
    dao_tally_key_record r;
    r.committee_size = 3;
    r.threshold      = 2;
    r.t              = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.cl_modulus = std::vector<uint8_t>(48, 0xAA);
    r.dkg_transcript_hash.assign(32, 0x99);
    r.key_id.assign(32, 0x55);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    wire[0] = 1;
    dao_tally_key_record r2;
    EXPECT_FALSE(r2.deserialize(wire));
}

TEST(DaoTallyKeyRecordClModulus, cl_rejects_trailing_bytes)
{
    dao_tally_key_record r;
    r.committee_size = 3;
    r.threshold      = 2;
    r.t              = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.cl_modulus = std::vector<uint8_t>(48, 0xAA);
    r.dkg_transcript_hash.assign(32, 0x99);
    r.key_id.assign(32, 0x55);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    wire.push_back(0);
    dao_tally_key_record r2;
    EXPECT_FALSE(r2.deserialize(wire));
}

TEST(DaoTallyKeyRecordClModulus, dispatches_to_cl_when_modulus_present)
{
    dao_tally_key_record r;
    r.committee_size = 3;
    r.threshold      = 2;
    r.t              = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.cl_modulus = std::vector<uint8_t>(48, 0xAA);
    r.activation_height = 100;
    r.dkg_transcript_hash.assign(32, 0x99);
    r.key_id.assign(32, 0x55);

    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    ASSERT_GE(wire.size(), 4u);
    EXPECT_EQ(wire[0], 2u);   // CL_WIRE_VERSION

    dao_tally_key_record r2;
    ASSERT_TRUE(r2.deserialize(wire));
    EXPECT_EQ(r2.version, 2u);
    EXPECT_EQ(r2.cl_modulus, r.cl_modulus);
}

} // namespace
} // namespace dao
} // namespace cryptonote
