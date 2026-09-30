// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "governance/vote_proof_v2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace cryptonote;

namespace {

static crypto::hash make_hash(uint8_t seed)
{
    crypto::hash h{};
    h.data[0]  = seed;
    h.data[31] = static_cast<uint8_t>(seed ^ 0xA5);
    return h;
}

static rct::key make_key(uint8_t seed)
{
    rct::key k{};
    for (int i = 0; i < 32; ++i)
        k.bytes[i] = static_cast<uint8_t>(seed + i);
    return k;
}

static vote_proof_v2 make_serializable_v2(size_t n_inputs)
{
    vote_proof_v2 vp;
    vp.version         = vote_proof_v2::VERSION;
    vp.proposal_id     = make_hash(0x10);
    vp.vote_height     = 42000;
    vp.tally_key_epoch = 1;

    vp.C_W = make_key(0xAB);
    vp.C_S = make_key(0xCD);

    for (int i = 0; i < 512; ++i) {
        vp.E_W.data[i] = static_cast<uint8_t>(i & 0xff);
        vp.E_S.data[i] = static_cast<uint8_t>((i + 1) & 0xff);
    }

    vp.transcript_hash = make_hash(0x20);

    for (size_t i = 0; i < n_inputs; ++i)
    {
        vote_input_v2 in;
        in.key_offsets = { i, i + 1, i + 2 };
        in.weight_commitment = make_key(static_cast<uint8_t>(0x30 + i));
        vp.inputs.push_back(in);

        crypto::hash n = make_hash(static_cast<uint8_t>(0x40 + i));
        vp.nullifiers.push_back(n);
    }
    return vp;
}

TEST(vote_proof_v2_serialization, version_field_is_two)
{
    vote_proof_v2 vp;
    EXPECT_EQ(static_cast<uint8_t>(2), vp.version);
    EXPECT_EQ(vote_proof_v2::VERSION, vp.version);
}

TEST(vote_proof_v2_serialization, empty_roundtrip)
{
    vote_proof_v2 vp = make_serializable_v2(0);

    blobdata blob;
    ASSERT_TRUE(t_serializable_object_to_blob(vp, blob));
    EXPECT_GT(blob.size(), 0u);

    vote_proof_v2 out;
    ASSERT_TRUE(t_serializable_object_from_blob(out, blob));
    EXPECT_EQ(vp.proposal_id, out.proposal_id);
    EXPECT_EQ(vp.vote_height, out.vote_height);
    EXPECT_EQ(vp.tally_key_epoch, out.tally_key_epoch);
    EXPECT_EQ(0u, out.inputs.size());
    EXPECT_EQ(0u, out.nullifiers.size());

    std::cerr << "[v2-serial] 0 inputs -> " << blob.size() << " bytes\n";
}

TEST(vote_proof_v2_serialization, single_input_roundtrip)
{
    vote_proof_v2 vp = make_serializable_v2(1);

    blobdata blob;
    ASSERT_TRUE(t_serializable_object_to_blob(vp, blob));

    vote_proof_v2 out;
    ASSERT_TRUE(t_serializable_object_from_blob(out, blob));
    ASSERT_EQ(1u, out.inputs.size());
    ASSERT_EQ(1u, out.nullifiers.size());
    EXPECT_EQ(vp.inputs[0].key_offsets, out.inputs[0].key_offsets);
    EXPECT_EQ(std::memcmp(vp.inputs[0].weight_commitment.bytes,
                          out.inputs[0].weight_commitment.bytes, 32), 0);
    EXPECT_EQ(vp.nullifiers[0], out.nullifiers[0]);

    std::cerr << "[v2-serial] 1 input  -> " << blob.size() << " bytes\n";
}

TEST(vote_proof_v2_serialization, eight_inputs_roundtrip)
{
    vote_proof_v2 vp = make_serializable_v2(8);

    blobdata blob;
    ASSERT_TRUE(t_serializable_object_to_blob(vp, blob));

    vote_proof_v2 out;
    ASSERT_TRUE(t_serializable_object_from_blob(out, blob));
    ASSERT_EQ(8u, out.inputs.size());
    ASSERT_EQ(8u, out.nullifiers.size());
    for (size_t i = 0; i < 8; ++i)
    {
        EXPECT_EQ(vp.inputs[i].key_offsets, out.inputs[i].key_offsets);
        EXPECT_EQ(std::memcmp(vp.inputs[i].weight_commitment.bytes,
                              out.inputs[i].weight_commitment.bytes, 32), 0);
        EXPECT_EQ(vp.nullifiers[i], out.nullifiers[i]);
    }

    std::cerr << "[v2-serial] 8 inputs -> " << blob.size() << " bytes\n";
}

TEST(vote_proof_v2_serialization, canonical_encoding)
{
    for (size_t n : { size_t(0), size_t(1), size_t(8) })
    {
        vote_proof_v2 vp = make_serializable_v2(n);

        blobdata b1;
        ASSERT_TRUE(t_serializable_object_to_blob(vp, b1));

        vote_proof_v2 mid;
        ASSERT_TRUE(t_serializable_object_from_blob(mid, b1));

        blobdata b2;
        ASSERT_TRUE(t_serializable_object_to_blob(mid, b2));

        EXPECT_EQ(b1, b2) << "non-canonical encoding for n=" << n;
    }
}

TEST(vote_proof_v2_serialization, aggregate_fields_roundtrip)
{
    vote_proof_v2 vp = make_serializable_v2(2);

    blobdata blob;
    ASSERT_TRUE(t_serializable_object_to_blob(vp, blob));

    vote_proof_v2 out;
    ASSERT_TRUE(t_serializable_object_from_blob(out, blob));

    EXPECT_EQ(std::memcmp(vp.C_W.bytes, out.C_W.bytes, 32), 0);
    EXPECT_EQ(std::memcmp(vp.C_S.bytes, out.C_S.bytes, 32), 0);
    EXPECT_EQ(vp.E_W.data, out.E_W.data);
    EXPECT_EQ(vp.E_S.data, out.E_S.data);
    EXPECT_EQ(vp.transcript_hash, out.transcript_hash);
}

TEST(vote_proof_v2_serialization, fixed_512_is_length_enforced)
{
    vote_proof_v2 vp = make_serializable_v2(1);
    blobdata blob;
    ASSERT_TRUE(t_serializable_object_to_blob(vp, blob));

    // Truncate one byte from a valid serialization and require rejection.
    blobdata bad(blob.begin(), blob.end() - 1);
    vote_proof_v2 out;
    EXPECT_FALSE(t_serializable_object_from_blob(out, bad));
}

} // namespace
