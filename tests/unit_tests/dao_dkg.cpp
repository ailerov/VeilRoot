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
        EXPECT_TRUE(dao_vss_verify_share(grp, commits, i,
                                         shares[i - 1], blindings[i - 1]));
    }

    BIGNUM* tampered = BN_dup(shares[1]);
    BN_add_word(tampered, 1);
    EXPECT_FALSE(dao_vss_verify_share(grp, commits, 2, tampered, blindings[1]));
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