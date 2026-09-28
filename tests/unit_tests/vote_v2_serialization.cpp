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

// Structurally valid but cryptographically meaningless BulletproofPlus.
// The serializer requires L.size() > 0 and L.size() == R.size().
// V is not serialized; the DAO verifier reconstructs it from
// total_weight_commitment per spec §23. This object is for the
// serialization test only and must never be put in a transaction.
static rct::BulletproofPlus make_placeholder_bp()
{
    rct::BulletproofPlus bp;
    rct::key k{};
    bp.A  = k;
    bp.A1 = k;
    bp.B  = k;
    bp.r1 = k;
    bp.s1 = k;
    bp.d1 = k;
    bp.L.push_back(k);
    bp.R.push_back(k);
    return bp;
}

static vote_proof_v2 make_serializable_v2(size_t n_inputs)
{
    vote_proof_v2 vp;
    vp.proposal_id = make_hash(0x10);
    vp.vote_height = 42000;

    vp.weight_range_proof = make_placeholder_bp();

    for (size_t i = 0; i < n_inputs; ++i)
    {
        vote_input_v2 in;
        in.key_offsets = { i, i + 1, i + 2 };
        std::memset(in.dao_nullifier.data,
                    static_cast<uint8_t>(i + 1),
                    sizeof(in.dao_nullifier.data));
        in.signature.payload = { static_cast<uint8_t>(i) };
        vp.inputs.push_back(in);
    }
    return vp;
}

// Regression: documents BulletproofPlus's own contract.
// A default-constructed proof has L empty and its serializer
// deliberately returns false. Do not attempt to weaken that.
TEST(vote_proof_v2_serialization, default_bp_is_not_serializable)
{
    vote_proof_v2 vp;
    vp.proposal_id = make_hash(0x01);

    blobdata blob;
    EXPECT_FALSE(t_serializable_object_to_blob(vp, blob));
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
    EXPECT_EQ(0u, out.inputs.size());

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
    EXPECT_EQ(vp.inputs[0].key_offsets, out.inputs[0].key_offsets);
    EXPECT_EQ(vp.inputs[0].signature.payload,
              out.inputs[0].signature.payload);

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
    for (size_t i = 0; i < 8; ++i)
    {
        EXPECT_EQ(vp.inputs[i].key_offsets, out.inputs[i].key_offsets);
        EXPECT_EQ(vp.inputs[i].signature.payload,
                  out.inputs[i].signature.payload);
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

TEST(vote_proof_v2_serialization, all_payloads_roundtrip)
{
    vote_proof_v2 vp = make_serializable_v2(2);
    vp.encrypted_weight.payload          = { 1, 2, 3 };
    vp.encrypted_signed_weight.payload   = { 4, 5 };
    vp.encrypted_weight_blinding.payload = { 6 };
    vp.encrypted_signed_blinding.payload = { 7, 8, 9 };
    vp.direction_proof.payload           = { 10 };
    vp.consistency_proof.payload         = { 11, 12 };

    blobdata blob;
    ASSERT_TRUE(t_serializable_object_to_blob(vp, blob));

    vote_proof_v2 out;
    ASSERT_TRUE(t_serializable_object_from_blob(out, blob));

    EXPECT_EQ(vp.encrypted_weight.payload, out.encrypted_weight.payload);
    EXPECT_EQ(vp.encrypted_signed_weight.payload,
              out.encrypted_signed_weight.payload);
    EXPECT_EQ(vp.encrypted_weight_blinding.payload,
              out.encrypted_weight_blinding.payload);
    EXPECT_EQ(vp.encrypted_signed_blinding.payload,
              out.encrypted_signed_blinding.payload);
    EXPECT_EQ(vp.direction_proof.payload, out.direction_proof.payload);
    EXPECT_EQ(vp.consistency_proof.payload, out.consistency_proof.payload);
}

} // namespace