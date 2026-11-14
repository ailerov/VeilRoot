// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"

#include <cstring>
#include <vector>

namespace cryptonote {
namespace dao {
namespace {

static dao_tally_key_record make_record(bool cl_modulus_populated)
{
    dao_tally_key_record r;
    r.version        = 1;
    r.committee_size = 3;
    r.threshold      = 2;
    r.t              = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.delta.assign(32, 0x00);
    r.N.assign(PAILLIER_MODULUS_BYTES, 0x11);
    r.G.assign(PAILLIER_MODULUS_BYTES, 0x12);
    r.theta.assign(PAILLIER_MODULUS_BYTES, 0x13);
    r.V.assign(PAILLIER_CT_BYTES, 0x14);
    r.V_K_i.assign(3, std::vector<uint8_t>(PAILLIER_CT_BYTES, 0x44));
    r.vss_P.assign(8, 0x00);
    r.vss_P_prime.assign(8, 0x00);
    r.vss_g.assign(8, 0x00);
    r.vss_h.assign(8, 0x00);
    r.activation_height = 100;
    r.dkg_transcript_hash.assign(32, 0x99);
    r.key_id.assign(32, 0x55);
    if (cl_modulus_populated)
        r.cl_modulus.assign(48, 0xAA);
    return r;
}

TEST(DaoTallyKeyRecordClModulus, roundtrip_with_cl_modulus)
{
    auto r = make_record(true);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));

    dao_tally_key_record r2;
    ASSERT_TRUE(r2.deserialize(wire));
    EXPECT_EQ(r2.cl_modulus, r.cl_modulus);
    EXPECT_EQ(r2.key_id, r.key_id);
    EXPECT_EQ(r2.committee_members, r.committee_members);
    EXPECT_EQ(r2.N, r.N);
    EXPECT_EQ(r2.V_K_i, r.V_K_i);
    EXPECT_EQ(r2.activation_height, r.activation_height);
}

TEST(DaoTallyKeyRecordClModulus, roundtrip_empty_cl_modulus_legacy)
{
    // Records produced before the CL field existed end the wire at
    // key_id. Readers must accept this.
    auto r = make_record(false);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));

    dao_tally_key_record r2;
    ASSERT_TRUE(r2.deserialize(wire));
    EXPECT_TRUE(r2.cl_modulus.empty());
    EXPECT_EQ(r2.key_id, r.key_id);
}

TEST(DaoTallyKeyRecordClModulus, cl_modulus_is_last_field)
{
    // Guard against future reordering: appending any trailing byte
    // after cl_modulus must be rejected.
    auto r = make_record(true);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    wire.push_back(0);
    dao_tally_key_record r2;
    EXPECT_FALSE(r2.deserialize(wire));
}

TEST(DaoTallyKeyRecordClModulus, cl_modulus_affects_key_id_digest)
{
    auto r1 = make_record(true);
    auto r2 = make_record(true);
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

} // namespace
} // namespace dao
} // namespace cryptonote
