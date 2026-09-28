// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <vector>

#include "gtest/gtest.h"

#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "governance/dao_vote_or_proof.h"

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

void le64_to_key(key& out, uint64_t x)
{
    std::memset(out.bytes, 0, 32);
    for (int i = 0; i < 8; ++i)
        out.bytes[i] = static_cast<uint8_t>((x >> (8 * i)) & 0xff);
    sc_reduce32(out.bytes);
}

// Build a synthetic aggregate with a known W and blindings.
// Returns C_W and C_S, plus the underlying scalars for the prover.
struct aggregate_fixture {
    key C_W;
    key C_S;
    key R_W;
    key R_S;
    key W_scalar;
};

aggregate_fixture make_aggregate(uint64_t W, const key& R_W, const key& R_S, bool yes)
{
    aggregate_fixture f;
    f.R_W = R_W;
    f.R_S = R_S;
    le64_to_key(f.W_scalar, W);

    key wH, rWG;
    scalarmultKey(wH, H, f.W_scalar);
    scalarmultBase(rWG, R_W);
    addKeys(f.C_W, wH, rWG);

    key wH_s, rSG;
    if (yes)
        scalarmultKey(wH_s, H, f.W_scalar);
    else
    {
        key negW;
        sc_0(negW.bytes);
        sc_sub(negW.bytes, negW.bytes, f.W_scalar.bytes);
        scalarmultKey(wH_s, H, negW);
    }
    scalarmultBase(rSG, R_S);
    addKeys(f.C_S, wH_s, rSG);

    return f;
}

dao_or_context make_ctx(const key& C_W, const key& C_S)
{
    dao_or_context ctx;
    ctx.version = 2;
    std::memset(ctx.proposal_id.data, 0x33, 32);
    ctx.vote_height = 51000;
    for (int i = 0; i < 3; ++i) {
        key nf = mk_scalar(0x40 + i);
        ctx.nullifiers.push_back(nf);
    }
    ctx.key_offsets = { 1000, 2000, 3000 };
    ctx.C_W = C_W;
    ctx.C_S = C_S;
    return ctx;
}

} // namespace

TEST(dao_or_proof, yes_proof_verifies)
{
    key R_W = mk_scalar(0x11);
    key R_S = mk_scalar(0x22);
    auto f = make_aggregate(1000, R_W, R_S, /*yes=*/true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    EXPECT_TRUE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, no_proof_verifies)
{
    key R_W = mk_scalar(0x33);
    key R_S = mk_scalar(0x44);
    auto f = make_aggregate(2500, R_W, R_S, /*yes=*/false);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, false, f.R_S, f.R_W, proof));
    EXPECT_TRUE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, yes_proof_as_no_context_fails)
{
    key R_W = mk_scalar(0x55);
    key R_S = mk_scalar(0x66);
    auto f_yes = make_aggregate(1000, R_W, R_S, true);
    auto f_no  = make_aggregate(1000, R_W, R_S, false);

    auto ctx_yes = make_ctx(f_yes.C_W, f_yes.C_S);
    auto ctx_no  = make_ctx(f_no.C_W,  f_no.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx_yes, true, f_yes.R_S, f_yes.R_W, proof));

    EXPECT_TRUE(dao_or_verify(ctx_yes, proof));
    EXPECT_FALSE(dao_or_verify(ctx_no, proof));
}

TEST(dao_or_proof, tamper_c_yes_fails)
{
    key R_W = mk_scalar(0x77);
    key R_S = mk_scalar(0x88);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    proof.c_yes.bytes[0] ^= 0x01;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_s_no_fails)
{
    key R_W = mk_scalar(0x99);
    key R_S = mk_scalar(0xAA);
    auto f = make_aggregate(1000, R_W, R_S, false);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, false, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    proof.s_no.bytes[5] ^= 0x01;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_C_W_fails)
{
    key R_W = mk_scalar(0xBB);
    key R_S = mk_scalar(0xCC);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    // Replace C_W with a different valid point, not an off-curve byte flip.
    // A byte flip would throw from ge_frombytes_vartime before reaching the
    // algebraic check; the substitute-point form exercises the intended path.
    key substitute;
    scalarmultBase(substitute, mk_scalar(0x5A));
    ctx.C_W = substitute;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_C_S_fails)
{
    key R_W = mk_scalar(0xDD);
    key R_S = mk_scalar(0xEE);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    // Same rationale as tamper_C_W_fails.
    key substitute;
    scalarmultBase(substitute, mk_scalar(0x6B));
    ctx.C_S = substitute;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_proposal_id_fails)
{
    key R_W = mk_scalar(0x12);
    key R_S = mk_scalar(0x34);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    ctx.proposal_id.data[0] ^= 0x01;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_vote_height_fails)
{
    key R_W = mk_scalar(0x56);
    key R_S = mk_scalar(0x78);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    ctx.vote_height += 1;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_nullifier_fails)
{
    key R_W = mk_scalar(0x9A);
    key R_S = mk_scalar(0xBC);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    ctx.nullifiers[1].bytes[7] ^= 0x01;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_key_offset_fails)
{
    key R_W = mk_scalar(0xDE);
    key R_S = mk_scalar(0xF0);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    ctx.key_offsets[2] += 1;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, tamper_extra_binding_fails)
{
    key R_W = mk_scalar(0x13);
    key R_S = mk_scalar(0x57);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);
    ctx.extra_binding = { 1, 2, 3, 4 };

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    ctx.extra_binding[0] ^= 0x01;
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}

TEST(dao_or_proof, swap_branch_challenges_fails)
{
    key R_W = mk_scalar(0x24);
    key R_S = mk_scalar(0x68);
    auto f = make_aggregate(1000, R_W, R_S, true);
    auto ctx = make_ctx(f.C_W, f.C_S);

    dao_vote_or_proof proof;
    ASSERT_TRUE(dao_or_prove(ctx, true, f.R_S, f.R_W, proof));
    ASSERT_TRUE(dao_or_verify(ctx, proof));

    std::swap(proof.c_yes, proof.c_no);
    EXPECT_FALSE(dao_or_verify(ctx, proof));
}