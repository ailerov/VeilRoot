// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <vector>

#include "gtest/gtest.h"

#include "governance/dao_consistency.h"
#include "governance/dao_paillier.h"
#include "ringct/rctOps.h"

using namespace cryptonote;
using namespace cryptonote::dao;
using namespace rct;

namespace {

dao_consistency_context make_ctx(const char* domain)
{
    dao_consistency_context ctx;
    ctx.domain = domain;
    ctx.version = 2;
    std::memset(ctx.proposal_id.data, 0x33, 32);
    ctx.vote_height = 51000;
    ctx.tally_key_epoch = 1;
    ctx.vote_input_transcript = { 0xAA, 0xBB, 0xCC };
    return ctx;
}

// Mirror of the prover's BE -> LE conversion for small unsigned integers.
key small_int_to_scalar(uint64_t v)
{
    key k{};
    std::memset(k.bytes, 0, 32);
    for (int i = 0; i < 8; ++i) {
        k.bytes[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    }
    return k;
}

key make_pedersen(const BIGNUM* m, const key& rho)
{
    key m_scalar = small_int_to_scalar(BN_get_word(m));
    key mH, rhoG, C;
    scalarmultKey(mH, H, m_scalar);
    scalarmultBase(rhoG, rho);
    addKeys(C, mH, rhoG);
    return C;
}

} // namespace

TEST(dao_consistency, round_trip)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 12345);
    BIGNUM* r = BN_new(); BN_set_word(r, 3);

    std::vector<uint8_t> E;
    ASSERT_TRUE(pk.encrypt(m, r, E));

    key rho = skGen();
    key C = make_pedersen(m, rho);

    auto ctx = make_ctx("test-domain");

    dao_consistency_proof proof;
    ASSERT_TRUE(dao_consistency_prove(ctx, pk.N(), E, C, m, r, rho, proof));
    EXPECT_TRUE(dao_consistency_verify(ctx, pk.N(), E, C, proof));

    BN_free(m); BN_free(r);
}

TEST(dao_consistency, reject_tampered_C)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 999);
    BIGNUM* r = BN_new(); BN_set_word(r, 5);

    std::vector<uint8_t> E;
    ASSERT_TRUE(pk.encrypt(m, r, E));

    key rho = skGen();
    key C = make_pedersen(m, rho);

    auto ctx = make_ctx("test-domain");

    dao_consistency_proof proof;
    ASSERT_TRUE(dao_consistency_prove(ctx, pk.N(), E, C, m, r, rho, proof));
    ASSERT_TRUE(dao_consistency_verify(ctx, pk.N(), E, C, proof));

    key C_bad = C;
    C_bad.bytes[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E, C_bad, proof));

    BN_free(m); BN_free(r);
}

TEST(dao_consistency, reject_tampered_E)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 42);
    BIGNUM* r = BN_new(); BN_set_word(r, 7);

    std::vector<uint8_t> E;
    ASSERT_TRUE(pk.encrypt(m, r, E));

    key rho = skGen();
    key C = make_pedersen(m, rho);

    auto ctx = make_ctx("test-domain");

    dao_consistency_proof proof;
    ASSERT_TRUE(dao_consistency_prove(ctx, pk.N(), E, C, m, r, rho, proof));
    ASSERT_TRUE(dao_consistency_verify(ctx, pk.N(), E, C, proof));

    std::vector<uint8_t> E_bad = E;
    E_bad[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E_bad, C, proof));

    BN_free(m); BN_free(r);
}

TEST(dao_consistency, reject_wrong_domain)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 777);
    BIGNUM* r = BN_new(); BN_set_word(r, 11);

    std::vector<uint8_t> E;
    ASSERT_TRUE(pk.encrypt(m, r, E));

    key rho = skGen();
    key C = make_pedersen(m, rho);

    auto ctx_a = make_ctx("domain-A");
    auto ctx_b = make_ctx("domain-B");

    dao_consistency_proof proof;
    ASSERT_TRUE(dao_consistency_prove(ctx_a, pk.N(), E, C, m, r, rho, proof));
    EXPECT_TRUE (dao_consistency_verify(ctx_a, pk.N(), E, C, proof));
    EXPECT_FALSE(dao_consistency_verify(ctx_b, pk.N(), E, C, proof));

    // Different vote_height also fails.
    auto ctx_c = make_ctx("domain-A");
    ctx_c.vote_height += 1;
    EXPECT_FALSE(dao_consistency_verify(ctx_c, pk.N(), E, C, proof));

    BN_free(m); BN_free(r);
}

TEST(dao_consistency, reject_tampered_proof)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 5555);
    BIGNUM* r = BN_new(); BN_set_word(r, 13);

    std::vector<uint8_t> E;
    ASSERT_TRUE(pk.encrypt(m, r, E));

    key rho = skGen();
    key C = make_pedersen(m, rho);

    auto ctx = make_ctx("test-domain");

    dao_consistency_proof proof;
    ASSERT_TRUE(dao_consistency_prove(ctx, pk.N(), E, C, m, r, rho, proof));
    ASSERT_TRUE(dao_consistency_verify(ctx, pk.N(), E, C, proof));

    // Tamper e.
    dao_consistency_proof p1 = proof;
    p1.e[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E, C, p1));

    // Tamper z_m.
    dao_consistency_proof p2 = proof;
    p2.z_m[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E, C, p2));

    // Tamper z_r.
    dao_consistency_proof p3 = proof;
    p3.z_r[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E, C, p3));

    // Tamper z_rho.
    dao_consistency_proof p4 = proof;
    p4.z_rho[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E, C, p4));

    // Tamper A_C.
    dao_consistency_proof p5 = proof;
    p5.A_C.bytes[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E, C, p5));

    // Tamper A_P.
    dao_consistency_proof p6 = proof;
    p6.A_P[0] ^= 0x01;
    EXPECT_FALSE(dao_consistency_verify(ctx, pk.N(), E, C, p6));

    BN_free(m); BN_free(r);
}

TEST(dao_consistency, serialize_round_trip)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 1010);
    BIGNUM* r = BN_new(); BN_set_word(r, 17);

    std::vector<uint8_t> E;
    ASSERT_TRUE(pk.encrypt(m, r, E));

    key rho = skGen();
    key C = make_pedersen(m, rho);

    auto ctx = make_ctx("test-domain");

    dao_consistency_proof proof;
    ASSERT_TRUE(dao_consistency_prove(ctx, pk.N(), E, C, m, r, rho, proof));

    std::vector<uint8_t> enc;
    ASSERT_TRUE(proof.serialize(enc));

    dao_consistency_proof dec;
    ASSERT_TRUE(dec.deserialize(enc));
    EXPECT_EQ(dec.e, proof.e);
    EXPECT_EQ(dec.z_m, proof.z_m);
    EXPECT_EQ(dec.z_r, proof.z_r);
    EXPECT_EQ(dec.z_rho, proof.z_rho);
    EXPECT_EQ(dec.A_P, proof.A_P);
    EXPECT_TRUE(dec.A_C == proof.A_C);

    EXPECT_TRUE(dao_consistency_verify(ctx, pk.N(), E, C, dec));

    BN_free(m); BN_free(r);
}