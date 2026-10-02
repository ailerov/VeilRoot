// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DKG utility tests: VSS, verification keys, partial-decryption ZKP,
// key-record serialization. The end-to-end 16-party driver test lives
// in dao_dkg_e2e.cpp.

#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include <openssl/bn.h>

#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_threshold.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

void test_nonce(uint32_t seed, BIGNUM* out)
{
    std::vector<uint8_t> buf(32, 0);
    for (int i = 0; i < 4; ++i)
        buf[i] = static_cast<uint8_t>((seed >> (8 * i)) & 0xff);
    buf[31] = 0xA5;
    BN_bin2bn(buf.data(), static_cast<int>(buf.size()), out);
}

} // namespace

// ================= VSS =================

TEST(dao_dkg, vss_group_generation)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 256));
    EXPECT_TRUE(grp.valid());
}

TEST(dao_dkg, vss_deal_and_verify)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 256));

    BIGNUM* secret = BN_new();
    BN_set_word(secret, 1234567);

    dao_vss_commitments commits;
    std::vector<BIGNUM*> shares;
    std::vector<BIGNUM*> blindings;
    ASSERT_TRUE(dao_vss_deal(grp, secret, 4, 1, commits, shares, blindings));
    ASSERT_EQ(shares.size(), 4u);
    ASSERT_EQ(commits.C.size(), 2u);

    for (uint32_t i = 1; i <= 4; ++i) {
        EXPECT_TRUE(dao_vss_verify_share(grp, commits, 4, i,
                                         shares[i - 1], blindings[i - 1]));
    }

    BIGNUM* tampered = BN_dup(shares[1]);
    BN_add_word(tampered, 1);
    EXPECT_FALSE(dao_vss_verify_share(grp, commits, 4, 2, tampered, blindings[1]));
    BN_free(tampered);

    BN_free(secret);
    for (auto* s : shares) BN_free(s);
    for (auto* b : blindings) BN_free(b);
}

// ================= Verification keys =================

TEST(dao_dkg, verification_key_derivation)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    std::vector<uint8_t> V_K;
    ASSERT_TRUE(dao_choose_verification_base(pk, V_K));
    EXPECT_EQ(V_K.size(), PAILLIER_CT_BYTES);

    BIGNUM* share = BN_new();
    BN_set_word(share, 42);

    std::vector<uint8_t> V_K_i;
    ASSERT_TRUE(dao_derive_verification_key(pk, V_K, share, V_K_i));
    EXPECT_EQ(V_K_i.size(), PAILLIER_CT_BYTES);

    BIGNUM* share2 = BN_new();
    BN_set_word(share2, 43);
    std::vector<uint8_t> V_K_i2;
    ASSERT_TRUE(dao_derive_verification_key(pk, V_K, share2, V_K_i2));
    EXPECT_NE(V_K_i, V_K_i2);

    BN_free(share); BN_free(share2);
}

// ================= Partial-decryption ZKP =================

TEST(dao_dkg, partial_decryption_proof_roundtrip)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    std::vector<uint8_t> V_K;
    ASSERT_TRUE(dao_choose_verification_base(pk, V_K));

    BIGNUM* share = BN_new();
    BN_set_word(share, 777);

    std::vector<uint8_t> V_K_i;
    ASSERT_TRUE(dao_derive_verification_key(pk, V_K, share, V_K_i));

    BIGNUM* m = BN_new();
    BN_set_word(m, 4242);
    BIGNUM* r = BN_new();
    BN_set_word(r, 3);

    std::vector<uint8_t> c;
    ASSERT_TRUE(pk.encrypt(m, r, c));

    std::vector<uint8_t> c_i;
    ASSERT_TRUE(dao_threshold_partial_decrypt(pk, c, share, c_i));

    BIGNUM* nonce = BN_new();
    test_nonce(0x12345678, nonce);

    dao_partial_decryption_proof proof;
    ASSERT_TRUE(dao_partial_decryption_prove(pk, V_K, V_K_i, 1, c, c_i,
                                             share, nonce, proof));

    EXPECT_TRUE(dao_partial_decryption_verify(pk, V_K, V_K_i, 1, c, c_i, proof));
    EXPECT_FALSE(dao_partial_decryption_verify(pk, V_K, V_K_i, 2, c, c_i, proof));

    std::vector<uint8_t> c_bad = c;
    c_bad[0] ^= 0x01;
    EXPECT_FALSE(dao_partial_decryption_verify(pk, V_K, V_K_i, 1, c_bad, c_i, proof));

    std::vector<uint8_t> c_i_bad = c_i;
    c_i_bad[0] ^= 0x01;
    EXPECT_FALSE(dao_partial_decryption_verify(pk, V_K, V_K_i, 1, c, c_i_bad, proof));

    BN_free(m); BN_free(r); BN_free(share); BN_free(nonce);
}

TEST(dao_dkg, partial_decryption_proof_alternate_nonce)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(1024));
    PaillierPublicKey pk = sk.public_key();

    std::vector<uint8_t> V_K;
    ASSERT_TRUE(dao_choose_verification_base(pk, V_K));

    BIGNUM* share = BN_new();
    BN_set_word(share, 555);

    std::vector<uint8_t> V_K_i;
    ASSERT_TRUE(dao_derive_verification_key(pk, V_K, share, V_K_i));

    BIGNUM* m = BN_new(); BN_set_word(m, 99);
    BIGNUM* r = BN_new(); BN_set_word(r, 5);
    std::vector<uint8_t> c;
    ASSERT_TRUE(pk.encrypt(m, r, c));

    std::vector<uint8_t> c_i;
    ASSERT_TRUE(dao_threshold_partial_decrypt(pk, c, share, c_i));

    BIGNUM* nonce1 = BN_new(); test_nonce(1, nonce1);
    BIGNUM* nonce2 = BN_new(); test_nonce(2, nonce2);

    dao_partial_decryption_proof p1, p2;
    ASSERT_TRUE(dao_partial_decryption_prove(pk, V_K, V_K_i, 1, c, c_i, share, nonce1, p1));
    ASSERT_TRUE(dao_partial_decryption_prove(pk, V_K, V_K_i, 1, c, c_i, share, nonce2, p2));

    EXPECT_NE(p1.E, p2.E);
    EXPECT_TRUE(dao_partial_decryption_verify(pk, V_K, V_K_i, 1, c, c_i, p1));
    EXPECT_TRUE(dao_partial_decryption_verify(pk, V_K, V_K_i, 1, c, c_i, p2));

    BN_free(m); BN_free(r); BN_free(share);
    BN_free(nonce1); BN_free(nonce2);
}

// ================= Key record serialization =================

namespace {

dao_tally_key_record make_serializable_record()
{
    dao_tally_key_record rec;
    rec.version = 1;
    rec.epoch = 1;
    rec.committee_size = DAO_DKG_COMMITTEE_SIZE;
    rec.threshold = DAO_DKG_THRESHOLD;
    rec.t = DAO_DKG_SHARING_DEGREE;

    rec.committee_id_hash.assign(32, 0x10);
    rec.committee_members.assign(DAO_DKG_COMMITTEE_SIZE,
                                 std::vector<uint8_t>(32, 0x0F));
    rec.delta.assign(32, 0x11);
    rec.N.assign(PAILLIER_MODULUS_BYTES, 0x12);
    rec.G.assign(PAILLIER_MODULUS_BYTES, 0x13);
    rec.theta.assign(PAILLIER_MODULUS_BYTES, 0x14);
    rec.V.assign(PAILLIER_CT_BYTES, 0x15);
    rec.V_K_i.assign(DAO_DKG_COMMITTEE_SIZE,
                     std::vector<uint8_t>(PAILLIER_CT_BYTES, 0x16));

    rec.vss_P.assign(16, 0x17);
    rec.vss_P_prime.assign(16, 0x18);
    rec.vss_g.assign(16, 0x19);
    rec.vss_h.assign(16, 0x1A);

    rec.activation_height = 12345;
    rec.dkg_transcript_hash.assign(32, 0x1B);
    rec.key_id.assign(32, 0x1C);
    return rec;
}

} // namespace

TEST(dao_dkg, key_record_serialize_deserialize)
{
    dao_tally_key_record rec = make_serializable_record();

    std::vector<uint8_t> enc;
    ASSERT_TRUE(rec.serialize(enc));

    dao_tally_key_record out;
    ASSERT_TRUE(out.deserialize(enc));
    EXPECT_EQ(out.version, rec.version);
    EXPECT_EQ(out.epoch, rec.epoch);
    EXPECT_EQ(out.committee_size, rec.committee_size);
    EXPECT_EQ(out.threshold, rec.threshold);
    EXPECT_EQ(out.t, rec.t);
    EXPECT_EQ(out.committee_id_hash, rec.committee_id_hash);
    EXPECT_EQ(out.delta, rec.delta);
    EXPECT_EQ(out.N, rec.N);
    EXPECT_EQ(out.G, rec.G);
    EXPECT_EQ(out.theta, rec.theta);
    EXPECT_EQ(out.V, rec.V);
    EXPECT_EQ(out.V_K_i, rec.V_K_i);
    EXPECT_EQ(out.vss_P, rec.vss_P);
    EXPECT_EQ(out.vss_P_prime, rec.vss_P_prime);
    EXPECT_EQ(out.vss_g, rec.vss_g);
    EXPECT_EQ(out.vss_h, rec.vss_h);
    EXPECT_EQ(out.activation_height, rec.activation_height);
    EXPECT_EQ(out.dkg_transcript_hash, rec.dkg_transcript_hash);
    EXPECT_EQ(out.key_id, rec.key_id);
}

TEST(dao_dkg, key_record_rejects_short_input)
{
    dao_tally_key_record rec = make_serializable_record();

    std::vector<uint8_t> enc;
    ASSERT_TRUE(rec.serialize(enc));

    enc.pop_back();
    dao_tally_key_record out;
    EXPECT_FALSE(out.deserialize(enc));
}

// ================= RFC 7919 FFDHE groups =================

namespace {

void check_group_invariants(const dao_vss_group& grp,
                            int expected_P_bits,
                            int expected_Pp_bits)
{
    ASSERT_NE(grp.P,       nullptr);
    ASSERT_NE(grp.P_prime, nullptr);
    ASSERT_NE(grp.g,       nullptr);
    ASSERT_NE(grp.h,       nullptr);

    EXPECT_EQ(BN_num_bits(grp.P), expected_P_bits);
    EXPECT_EQ(BN_num_bits(grp.P_prime), expected_Pp_bits);
    EXPECT_TRUE(BN_is_word(grp.g, 2));

    // P' = (P-1)/2
    BIGNUM* expected_Pp = BN_new();
    BN_sub(expected_Pp, grp.P, BN_value_one());
    BN_rshift1(expected_Pp, expected_Pp);
    EXPECT_EQ(BN_cmp(expected_Pp, grp.P_prime), 0);

    // g^P' == 1, g != 1
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* check = BN_new();
    ASSERT_TRUE(BN_mod_exp(check, grp.g, grp.P_prime, grp.P, ctx) == 1);
    EXPECT_TRUE(BN_is_one(check));
    EXPECT_FALSE(BN_is_one(grp.g));

    // h^P' == 1, h != 1
    ASSERT_TRUE(BN_mod_exp(check, grp.h, grp.P_prime, grp.P, ctx) == 1);
    EXPECT_TRUE(BN_is_one(check));
    EXPECT_FALSE(BN_is_one(grp.h));
    EXPECT_NE(BN_cmp(grp.h, grp.g), 0);

    BN_free(expected_Pp);
    BN_free(check);
    BN_CTX_free(ctx);
}

} // namespace

TEST(dao_vss, ffdhe2048_parameters)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 2047));
    check_group_invariants(grp, 2048, 2047);
}

TEST(dao_vss, ffdhe6144_parameters)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 6143));
    check_group_invariants(grp, 6144, 6143);
}

// ================= integer VSS bounds =================

TEST(dao_vss, integer_values_do_not_wrap)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    // Representative secrets well below P'.
    const char* secrets[] = {
        "0",
        "1",
        "170141183460469231731687303715884105728",                     // 2^127
        "57896044618658097711785492504343953926634992332820282019728792003956564819968", // 2^255
    };

    for (const char* s : secrets) {
        BIGNUM* secret = nullptr;
        ASSERT_NE(BN_dec2bn(&secret, s), 0);
        ASSERT_LT(BN_cmp(secret, grp.P_prime), 0);

        dao_vss_commitments commits;
        std::vector<BIGNUM*> shares;
        std::vector<BIGNUM*> blindings;
        ASSERT_TRUE(dao_vss_deal(grp, secret, 16, 7, commits, shares, blindings));

        for (size_t i = 0; i < 16; ++i) {
            EXPECT_FALSE(BN_is_negative(shares[i]));
            EXPECT_LT(BN_cmp(shares[i], grp.P_prime), 0);
            EXPECT_FALSE(BN_is_negative(blindings[i]));
            EXPECT_LT(BN_cmp(blindings[i], grp.P_prime), 0);

            EXPECT_TRUE(dao_vss_verify_share(grp, commits, 16,
                                             static_cast<uint32_t>(i + 1),
                                             shares[i], blindings[i]));
        }

        BN_free(secret);
        for (auto* x : shares)    BN_free(x);
        for (auto* x : blindings) BN_free(x);
    }
}

TEST(dao_vss, verify_share_rejects_bad_index)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    BIGNUM* secret = nullptr;
    BN_dec2bn(&secret, "12345");

    dao_vss_commitments commits;
    std::vector<BIGNUM*> shares;
    std::vector<BIGNUM*> blindings;
    ASSERT_TRUE(dao_vss_deal(grp, secret, 16, 7, commits, shares, blindings));

    EXPECT_FALSE(dao_vss_verify_share(grp, commits, 16, 0,
                                      shares[0], blindings[0]));
    EXPECT_FALSE(dao_vss_verify_share(grp, commits, 16, 17,
                                      shares[0], blindings[0]));

    BN_free(secret);
    for (auto* x : shares)    BN_free(x);
    for (auto* x : blindings) BN_free(x);
}

TEST(dao_vss, verify_share_rejects_tampering)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    BIGNUM* secret = nullptr;
    BN_dec2bn(&secret, "987654321");

    dao_vss_commitments commits;
    std::vector<BIGNUM*> shares;
    std::vector<BIGNUM*> blindings;
    ASSERT_TRUE(dao_vss_deal(grp, secret, 16, 7, commits, shares, blindings));

    // Correct case.
    EXPECT_TRUE(dao_vss_verify_share(grp, commits, 16, 3,
                                     shares[2], blindings[2]));

    // share + 1
    {
        BIGNUM* tampered = BN_dup(shares[2]);
        BN_add_word(tampered, 1);
        EXPECT_FALSE(dao_vss_verify_share(grp, commits, 16, 3,
                                          tampered, blindings[2]));
        BN_free(tampered);
    }

    // share - 1
    if (!BN_is_zero(shares[2])) {
        BIGNUM* tampered = BN_dup(shares[2]);
        BN_sub_word(tampered, 1);
        EXPECT_FALSE(dao_vss_verify_share(grp, commits, 16, 3,
                                          tampered, blindings[2]));
        BN_free(tampered);
    }

    // blinding + 1
    {
        BIGNUM* tampered = BN_dup(blindings[2]);
        BN_add_word(tampered, 1);
        EXPECT_FALSE(dao_vss_verify_share(grp, commits, 16, 3,
                                          shares[2], tampered));
        BN_free(tampered);
    }

    // wrong commitment
    {
        dao_vss_commitments bad = commits;
        bad.C[0][0] ^= 0x01;
        EXPECT_FALSE(dao_vss_verify_share(grp, bad, 16, 3,
                                          shares[2], blindings[2]));
    }

    // truncated commitment vector
    {
        dao_vss_commitments bad = commits;
        bad.C.pop_back();
        EXPECT_FALSE(dao_vss_verify_share(grp, bad, 16, 3,
                                          shares[2], blindings[2]));
    }

    // empty commitment vector
    {
        dao_vss_commitments bad;
        EXPECT_FALSE(dao_vss_verify_share(grp, bad, 16, 3,
                                          shares[2], blindings[2]));
    }

    BN_free(secret);
    for (auto* x : shares)    BN_free(x);
    for (auto* x : blindings) BN_free(x);
}

// ================= Gap 1 — range proof =================

namespace {

struct TestCtx
{
    BN_CTX* ctx;
    TestCtx() : ctx(BN_CTX_new()) {}
    ~TestCtx() { if (ctx) BN_CTX_free(ctx); }
    TestCtx(const TestCtx&) = delete;
    TestCtx& operator=(const TestCtx&) = delete;
    bool ok() const { return ctx != nullptr; }
};

BIGNUM* make_commitment(const dao_vss_group& grp, const BIGNUM* x,
                        const BIGNUM* rho, BN_CTX* ctx)
{
    BIGNUM* gx = BN_new();
    BIGNUM* hr = BN_new();
    BIGNUM* C  = BN_new();
    BN_mod_exp(gx, grp.g, x,   grp.P, ctx);
    BN_mod_exp(hr, grp.h, rho, grp.P, ctx);
    BN_mod_mul(C, gx, hr, grp.P, ctx);
    BN_free(gx); BN_free(hr);
    return C;
}

} // namespace

TEST(dao_range, round_trip_small)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x   = BN_new(); BN_set_word(x, 12345);
    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);

    BIGNUM* C = make_commitment(grp, x, rho, ctx.ctx);
    ASSERT_NE(C, nullptr);

    dao_range_proof proof;
    ASSERT_TRUE(dao_range_prove(grp, 1, 7, DAO_RANGE_VALUE_TAG_BETA,
                                x, rho, C, 160, proof));
    EXPECT_TRUE(dao_range_verify(grp, 1, 7, DAO_RANGE_VALUE_TAG_BETA,
                                 C, proof));

    BN_free(x); BN_free(rho); BN_free(C);
}

TEST(dao_range, round_trip_boundary_zero)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x   = BN_new(); BN_zero(x);
    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);

    BIGNUM* C = make_commitment(grp, x, rho, ctx.ctx);

    dao_range_proof proof;
    ASSERT_TRUE(dao_range_prove(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA,
                                x, rho, C, 160, proof));
    EXPECT_TRUE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA,
                                 C, proof));

    BN_free(x); BN_free(rho); BN_free(C);
}

TEST(dao_range, round_trip_boundary_max)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x = BN_new();
    BN_lshift(x, BN_value_one(), 159);
    BN_sub_word(x, 1);

    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);
    BIGNUM* C = make_commitment(grp, x, rho, ctx.ctx);

    dao_range_proof proof;
    ASSERT_TRUE(dao_range_prove(grp, 1, 1, DAO_RANGE_VALUE_TAG_R,
                                x, rho, C, 160, proof));
    EXPECT_TRUE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_R,
                                 C, proof));

    BN_free(x); BN_free(rho); BN_free(C);
}

TEST(dao_range, reject_value_above_bound)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x = BN_new();
    BN_lshift(x, BN_value_one(), 160);

    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);
    BIGNUM* C = make_commitment(grp, x, rho, ctx.ctx);

    dao_range_proof proof;
    EXPECT_FALSE(dao_range_prove(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA,
                                 x, rho, C, 160, proof));

    BN_free(x); BN_free(rho); BN_free(C);
}

TEST(dao_range, reject_wrong_commitment)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x   = BN_new(); BN_set_word(x, 777);
    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);
    BIGNUM* C   = make_commitment(grp, x, rho, ctx.ctx);

    BIGNUM* x2   = BN_new(); BN_set_word(x2, 778);
    BIGNUM* rho2 = BN_new(); BN_rand_range(rho2, grp.P_prime);
    BIGNUM* C2   = make_commitment(grp, x2, rho2, ctx.ctx);

    dao_range_proof proof;
    ASSERT_TRUE(dao_range_prove(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA,
                                x, rho, C, 160, proof));

    EXPECT_TRUE (dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C,  proof));
    EXPECT_FALSE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C2, proof));

    BN_free(x); BN_free(rho); BN_free(C);
    BN_free(x2); BN_free(rho2); BN_free(C2);
}

TEST(dao_range, reject_wrong_domain)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x   = BN_new(); BN_set_word(x, 42);
    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);
    BIGNUM* C   = make_commitment(grp, x, rho, ctx.ctx);

    dao_range_proof proof;
    ASSERT_TRUE(dao_range_prove(grp, 1, 5, DAO_RANGE_VALUE_TAG_BETA,
                                x, rho, C, 160, proof));

    EXPECT_TRUE (dao_range_verify(grp, 1, 5, DAO_RANGE_VALUE_TAG_BETA, C, proof));
    EXPECT_FALSE(dao_range_verify(grp, 2, 5, DAO_RANGE_VALUE_TAG_BETA, C, proof));
    EXPECT_FALSE(dao_range_verify(grp, 1, 6, DAO_RANGE_VALUE_TAG_BETA, C, proof));
    EXPECT_FALSE(dao_range_verify(grp, 1, 5, DAO_RANGE_VALUE_TAG_R,    C, proof));

    BN_free(x); BN_free(rho); BN_free(C);
}

TEST(dao_range, reject_tampered_proof)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x   = BN_new(); BN_set_word(x, 999);
    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);
    BIGNUM* C   = make_commitment(grp, x, rho, ctx.ctx);

    dao_range_proof proof;
    ASSERT_TRUE(dao_range_prove(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA,
                                x, rho, C, 160, proof));
    ASSERT_TRUE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C, proof));

    // Flip a byte in bit commitment 0.
    proof.bit_commitments[0][0] ^= 0x01;
    EXPECT_FALSE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C, proof));
    proof.bit_commitments[0][0] ^= 0x01;

    // Flip a byte in bit proof 3 response z_1.
    proof.bit_proofs[3].z_1[0] ^= 0x01;
    EXPECT_FALSE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C, proof));
    proof.bit_proofs[3].z_1[0] ^= 0x01;

    // Flip a byte in the link proof response.
    proof.link_z[0] ^= 0x01;
    EXPECT_FALSE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C, proof));
    proof.link_z[0] ^= 0x01;

    // Flip a byte in the link A.
    proof.link_a[0] ^= 0x01;
    EXPECT_FALSE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C, proof));
    proof.link_a[0] ^= 0x01;

    // Sanity: unmodified still verifies.
    EXPECT_TRUE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C, proof));

    BN_free(x); BN_free(rho); BN_free(C);
}

TEST(dao_range, serialize_round_trip)
{
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 511));

    TestCtx ctx;
    ASSERT_TRUE(ctx.ok());

    BIGNUM* x   = BN_new(); BN_set_word(x, 424242);
    BIGNUM* rho = BN_new(); BN_rand_range(rho, grp.P_prime);
    BIGNUM* C   = make_commitment(grp, x, rho, ctx.ctx);

    dao_range_proof proof;
    ASSERT_TRUE(dao_range_prove(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA,
                                x, rho, C, 160, proof));

    std::vector<uint8_t> enc;
    ASSERT_TRUE(proof.serialize(enc));

    dao_range_proof dec;
    ASSERT_TRUE(dec.deserialize(enc));
    EXPECT_EQ(dec.bits, proof.bits);
    EXPECT_EQ(dec.bit_commitments.size(), proof.bit_commitments.size());
    EXPECT_EQ(dec.bit_proofs.size(), proof.bit_proofs.size());

    EXPECT_TRUE(dao_range_verify(grp, 1, 1, DAO_RANGE_VALUE_TAG_BETA, C, dec));

    BN_free(x); BN_free(rho); BN_free(C);
}


// ================= Gap 4: canonical transcript hash =================

namespace {

dkg_msg make_test_msg(uint32_t candidate_id, uint32_t phase, uint32_t round,
                      uint32_t sender_id, uint32_t recipient_id,
                      dkg_msg_type type, uint64_t sequence,
                      uint8_t payload_byte)
{
    dkg_msg m;
    m.hdr.version      = 1;
    m.hdr.epoch        = 1;
    m.hdr.candidate_id = candidate_id;
    m.hdr.sender_id    = sender_id;
    m.hdr.recipient_id = recipient_id;
    m.hdr.phase        = phase;
    m.hdr.round        = round;
    m.hdr.sequence     = sequence;
    m.hdr.type         = type;
    m.bytes_a.assign(1, payload_byte);
    return m;
}

} // namespace

TEST(dao_dkg, transcript_hash_reorder_invariant)
{
    std::vector<dkg_msg> msgs;
    for (uint32_t i = 0; i < 10; ++i) {
        msgs.push_back(make_test_msg(1, 1, 0, i + 1, 0,
                                     dkg_msg_type::polynomial_share, i,
                                     static_cast<uint8_t>(0x10 + i)));
    }

    dkg_transcript t_forward;
    for (const auto& m : msgs) t_forward.append(m);

    dkg_transcript t_reverse;
    for (auto it = msgs.rbegin(); it != msgs.rend(); ++it) t_reverse.append(*it);

    std::vector<uint8_t> h_fwd, h_rev;
    t_forward.hash(h_fwd);
    t_reverse.hash(h_rev);

    ASSERT_EQ(h_fwd.size(), 32u);
    ASSERT_EQ(h_rev.size(), 32u);
    EXPECT_EQ(h_fwd, h_rev);
}

TEST(dao_dkg, transcript_hash_tamper_detected)
{
    dkg_msg m = make_test_msg(1, 1, 0, 1, 0,
                              dkg_msg_type::polynomial_share, 0, 0x42);

    dkg_transcript t1;
    t1.append(m);
    std::vector<uint8_t> h1;
    t1.hash(h1);

    dkg_msg m2 = m;
    m2.bytes_a[0] ^= 0x01;
    dkg_transcript t2;
    t2.append(m2);
    std::vector<uint8_t> h2;
    t2.hash(h2);

    EXPECT_NE(h1, h2);
}

TEST(dao_dkg, transcript_hash_duplicates_collapse)
{
    dkg_msg m = make_test_msg(1, 1, 0, 1, 0,
                              dkg_msg_type::polynomial_share, 0, 0x42);

    dkg_transcript t_single;
    t_single.append(m);
    std::vector<uint8_t> h_single;
    t_single.hash(h_single);

    dkg_transcript t_many;
    for (int i = 0; i < 15; ++i) t_many.append(m);
    std::vector<uint8_t> h_many;
    t_many.hash(h_many);

    EXPECT_EQ(h_single, h_many);
}