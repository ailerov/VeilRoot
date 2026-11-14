// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_consistency.h"
#include "governance/dao_cl_dkg_payload.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "ringct/rctOps.h"

#include <array>
#include <memory>

using namespace cryptonote::dao;

namespace {

static std::shared_ptr<BICYCL::CL_HSMqk>
make_cl(BICYCL::RandGen& rng, uint64_t seed)
{
    rng.set_seed(BICYCL::Mpz(static_cast<unsigned long>(seed)));
    std::array<uint8_t, 32> be{};
    const auto L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    BICYCL::Mpz q(std::vector<uint8_t>(be.begin(), be.end()));
    BICYCL::SecLevel sl(128);
    return std::make_shared<BICYCL::CL_HSMqk>(
        q, 1, sl, rng, BICYCL::CL_Params(static_cast<size_t>(128)));
}

static dao_consistency_context make_ctx()
{
    dao_consistency_context c;
    c.domain               = "C_S-Enc(S)";
    c.version              = 4;
    c.proposal_id          = crypto::null_hash;
    c.vote_height          = 12345;
    c.tally_key_id         = crypto::null_hash;
    c.vote_input_transcript.assign(32, 0x77);
    return c;
}

static rct::key to_rct_scalar_signed(const BICYCL::Mpz& m,
                                     const BICYCL::Mpz& q)
{
    // canonical residue in Z_q -> 32-byte LE
    BICYCL::Mpz r = m;
    if (r.sgn() < 0) {
        // r = q - |m|
        BICYCL::Mpz abs_m;
        BICYCL::Mpz::abs(abs_m, m);
        BICYCL::Mpz::sub(r, q, abs_m);
    }
    auto be = static_cast<std::vector<unsigned char>>(r);
    rct::key k = rct::zero();
    for (size_t i = 0; i < be.size() && i < 32; ++i)
        k.bytes[i] = be[be.size() - 1 - i];
    return k;
}

TEST(DaoClConsistencyNoRange, modulus_invariant_holds_for_standard_cl)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 1UL);
    ASSERT_TRUE(cl);
    EXPECT_TRUE(dao_cl_consistency_check_modulus(*cl));
}

TEST(DaoClConsistencyNoRange, prove_verify_positive)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 2UL);
    ASSERT_TRUE(cl);

    BICYCL::CL_HSMqk::SecretKey sk(*cl, rng);
    BICYCL::CL_HSMqk::PublicKey pk(*cl, sk);

    BICYCL::Mpz W(1000UL);
    BICYCL::Mpz r = rng.random_mpz(cl->encrypt_randomness_bound());
    BICYCL::CL_HSMqk::ClearText pt(*cl, W);
    auto ct = cl->encrypt(pk, pt, r);

    rct::key rho = rct::skGen();
    rct::key W_scalar = to_rct_scalar_signed(W, cl->q());
    rct::key WH, rhoG, C;
    WH = rct::scalarmultH(W_scalar);
    rct::scalarmultBase(rhoG, rho);
    rct::addKeys(C, WH, rhoG);

    auto ctx = make_ctx();
    dao_cl_pedersen_proof_no_range proof;
    ASSERT_TRUE(dao_cl_consistency_prove_no_range(
        *cl, pk, ct, W, r, C, rho, ctx, rng, proof));
    ASSERT_TRUE(dao_cl_consistency_verify_no_range(
        *cl, pk, ct, C, ctx, proof));
}

TEST(DaoClConsistencyNoRange, prove_verify_negative_as_canonical_residue)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 3UL);
    ASSERT_TRUE(cl);

    BICYCL::CL_HSMqk::SecretKey sk(*cl, rng);
    BICYCL::CL_HSMqk::PublicKey pk(*cl, sk);

    // S = -W. CL plaintext is q - W.
    BICYCL::Mpz W(1000UL);
    BICYCL::Mpz q_minus_W;
    BICYCL::Mpz::sub(q_minus_W, cl->q(), W);

    BICYCL::Mpz r = rng.random_mpz(cl->encrypt_randomness_bound());
    BICYCL::CL_HSMqk::ClearText pt(*cl, q_minus_W);
    auto ct = cl->encrypt(pk, pt, r);

    // Pedersen commitment uses the mathematically signed value -W,
    // which equals q_minus_W as a scalar.
    rct::key rho = rct::skGen();
    rct::key C;
    {
        rct::key neg_W_scalar = to_rct_scalar_signed(q_minus_W, cl->q());
        rct::key negWH, rhoG;
        negWH = rct::scalarmultH(neg_W_scalar);
        rct::scalarmultBase(rhoG, rho);
        rct::addKeys(C, negWH, rhoG);
    }

    auto ctx = make_ctx();
    dao_cl_pedersen_proof_no_range proof;
    ASSERT_TRUE(dao_cl_consistency_prove_no_range(
        *cl, pk, ct, q_minus_W, r, C, rho, ctx, rng, proof));
    ASSERT_TRUE(dao_cl_consistency_verify_no_range(
        *cl, pk, ct, C, ctx, proof));
}

TEST(DaoClConsistencyNoRange, rejects_modified_ciphertext)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 4UL);
    ASSERT_TRUE(cl);

    BICYCL::CL_HSMqk::SecretKey sk(*cl, rng);
    BICYCL::CL_HSMqk::PublicKey pk(*cl, sk);

    BICYCL::Mpz W(500UL);
    BICYCL::Mpz r = rng.random_mpz(cl->encrypt_randomness_bound());
    BICYCL::CL_HSMqk::ClearText pt(*cl, W);
    auto ct = cl->encrypt(pk, pt, r);

    rct::key rho = rct::skGen();
    rct::key W_scalar = to_rct_scalar_signed(W, cl->q());
    rct::key WH, rhoG, C;
    WH = rct::scalarmultH(W_scalar);
    rct::scalarmultBase(rhoG, rho);
    rct::addKeys(C, WH, rhoG);

    auto ctx = make_ctx();
    dao_cl_pedersen_proof_no_range proof;
    ASSERT_TRUE(dao_cl_consistency_prove_no_range(
        *cl, pk, ct, W, r, C, rho, ctx, rng, proof));

    // Tamper: replace ciphertext with a different one.
    BICYCL::Mpz r2 = rng.random_mpz(cl->encrypt_randomness_bound());
    auto ct2 = cl->encrypt(pk, pt, r2);
    EXPECT_FALSE(dao_cl_consistency_verify_no_range(
        *cl, pk, ct2, C, ctx, proof));
}

TEST(DaoClConsistencyNoRange, rejects_modified_commitment)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 5UL);
    ASSERT_TRUE(cl);

    BICYCL::CL_HSMqk::SecretKey sk(*cl, rng);
    BICYCL::CL_HSMqk::PublicKey pk(*cl, sk);

    BICYCL::Mpz W(500UL);
    BICYCL::Mpz r = rng.random_mpz(cl->encrypt_randomness_bound());
    BICYCL::CL_HSMqk::ClearText pt(*cl, W);
    auto ct = cl->encrypt(pk, pt, r);

    rct::key rho = rct::skGen();
    rct::key W_scalar = to_rct_scalar_signed(W, cl->q());
    rct::key WH, rhoG, C;
    WH = rct::scalarmultH(W_scalar);
    rct::scalarmultBase(rhoG, rho);
    rct::addKeys(C, WH, rhoG);

    auto ctx = make_ctx();
    dao_cl_pedersen_proof_no_range proof;
    ASSERT_TRUE(dao_cl_consistency_prove_no_range(
        *cl, pk, ct, W, r, C, rho, ctx, rng, proof));

    // Tamper: change C.
    rct::key C2 = C;
    C2.bytes[0] ^= 0x01;
    EXPECT_FALSE(dao_cl_consistency_verify_no_range(
        *cl, pk, ct, C2, ctx, proof));
}

TEST(DaoClConsistencyNoRange, rejects_modified_challenge)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 6UL);
    ASSERT_TRUE(cl);

    BICYCL::CL_HSMqk::SecretKey sk(*cl, rng);
    BICYCL::CL_HSMqk::PublicKey pk(*cl, sk);

    BICYCL::Mpz W(500UL);
    BICYCL::Mpz r = rng.random_mpz(cl->encrypt_randomness_bound());
    BICYCL::CL_HSMqk::ClearText pt(*cl, W);
    auto ct = cl->encrypt(pk, pt, r);

    rct::key rho = rct::skGen();
    rct::key W_scalar = to_rct_scalar_signed(W, cl->q());
    rct::key WH, rhoG, C;
    WH = rct::scalarmultH(W_scalar);
    rct::scalarmultBase(rhoG, rho);
    rct::addKeys(C, WH, rhoG);

    auto ctx = make_ctx();
    dao_cl_pedersen_proof_no_range proof;
    ASSERT_TRUE(dao_cl_consistency_prove_no_range(
        *cl, pk, ct, W, r, C, rho, ctx, rng, proof));

    proof.e[0] ^= 0x01;
    EXPECT_FALSE(dao_cl_consistency_verify_no_range(
        *cl, pk, ct, C, ctx, proof));
}

TEST(DaoClConsistencyNoRange, serialize_roundtrip)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 7UL);
    ASSERT_TRUE(cl);

    BICYCL::CL_HSMqk::SecretKey sk(*cl, rng);
    BICYCL::CL_HSMqk::PublicKey pk(*cl, sk);

    BICYCL::Mpz W(999UL);
    BICYCL::Mpz r = rng.random_mpz(cl->encrypt_randomness_bound());
    BICYCL::CL_HSMqk::ClearText pt(*cl, W);
    auto ct = cl->encrypt(pk, pt, r);

    rct::key rho = rct::skGen();
    rct::key W_scalar = to_rct_scalar_signed(W, cl->q());
    rct::key WH, rhoG, C;
    WH = rct::scalarmultH(W_scalar);
    rct::scalarmultBase(rhoG, rho);
    rct::addKeys(C, WH, rhoG);

    auto ctx = make_ctx();
    dao_cl_pedersen_proof_no_range proof;
    ASSERT_TRUE(dao_cl_consistency_prove_no_range(
        *cl, pk, ct, W, r, C, rho, ctx, rng, proof));

    std::vector<uint8_t> wire;
    ASSERT_TRUE(proof.serialize(wire));
    ASSERT_FALSE(wire.empty());

    dao_cl_pedersen_proof_no_range parsed;
    ASSERT_TRUE(parsed.deserialize(wire));
    EXPECT_TRUE(dao_cl_consistency_verify_no_range(
        *cl, pk, ct, C, ctx, parsed));

    // Trailing byte rejected.
    wire.push_back(0);
    dao_cl_pedersen_proof_no_range bad;
    EXPECT_FALSE(bad.deserialize(wire));
}

} // namespace

#endif // VEILROOT_ENABLE_CL
