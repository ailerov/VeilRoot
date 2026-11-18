// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DKG utility tests: VSS, verification keys, partial-decryption ZKP,
// key-record serialization. The end-to-end 16-party driver test lives
// in dao_dkg_e2e.cpp.

#include <cstring>
#include <string>
#include <vector>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>

#include "gtest/gtest.h"

#include <openssl/bn.h>

#include "governance/dao_dkg.h"

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

// ================= Key record serialization =================

namespace {

dao_tally_key_record make_serializable_record()
{
    dao_tally_key_record rec;
    rec.version = 1;
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

// ================= DKG private-payload envelope =================

TEST(DaoDkgPrivateEnvelope, RoundTrip)
{
    crypto::public_key sender_pub;
    crypto::secret_key sender_priv;
    crypto::generate_keys(sender_pub, sender_priv);

    crypto::public_key recipient_pub;
    crypto::secret_key recipient_priv;
    crypto::generate_keys(recipient_pub, recipient_priv);

    const std::string plain = "VeilRoot-DAO-DKG-private-test";

    std::string envelope;
    ASSERT_TRUE(encrypt_dkg_private_payload(plain, sender_pub,
                                            recipient_pub, envelope));
    ASSERT_TRUE(is_dkg_private_payload(envelope));

    std::string recovered;
    ASSERT_TRUE(decrypt_dkg_private_payload(envelope, sender_pub,
                                            recipient_priv, recovered));
    EXPECT_EQ(plain, recovered);
}

TEST(DaoDkgPrivateEnvelope, WrongRecipientCannotDecrypt)
{
    crypto::public_key sender_pub, recipient_pub, wrong_pub;
    crypto::secret_key sender_priv, recipient_priv, wrong_priv;
    crypto::generate_keys(sender_pub, sender_priv);
    crypto::generate_keys(recipient_pub, recipient_priv);
    crypto::generate_keys(wrong_pub, wrong_priv);

    std::string envelope;
    ASSERT_TRUE(encrypt_dkg_private_payload("secret", sender_pub,
                                            recipient_pub, envelope));

    std::string recovered;
    EXPECT_FALSE(decrypt_dkg_private_payload(envelope, sender_pub,
                                             wrong_priv, recovered));
}

TEST(DaoDkgPrivateEnvelope, TamperFailsAuthentication)
{
    crypto::public_key sender_pub, recipient_pub;
    crypto::secret_key sender_priv, recipient_priv;
    crypto::generate_keys(sender_pub, sender_priv);
    crypto::generate_keys(recipient_pub, recipient_priv);

    std::string envelope;
    ASSERT_TRUE(encrypt_dkg_private_payload("secret", sender_pub,
                                            recipient_pub, envelope));
    ASSERT_GT(envelope.size(), 1u);
    envelope.back() ^= 0x01;

    std::string recovered;
    EXPECT_FALSE(decrypt_dkg_private_payload(envelope, sender_pub,
                                             recipient_priv, recovered));
}

TEST(DaoDkgPrivateEnvelope, OuterSenderBindingFails)
{
    crypto::public_key sender_pub, other_sender_pub, recipient_pub;
    crypto::secret_key sender_priv, other_sender_priv, recipient_priv;
    crypto::generate_keys(sender_pub, sender_priv);
    crypto::generate_keys(other_sender_pub, other_sender_priv);
    crypto::generate_keys(recipient_pub, recipient_priv);

    std::string envelope;
    ASSERT_TRUE(encrypt_dkg_private_payload("secret", sender_pub,
                                            recipient_pub, envelope));

    std::string recovered;
    EXPECT_FALSE(decrypt_dkg_private_payload(envelope, other_sender_pub,
                                             recipient_priv, recovered));
}

TEST(DaoDkgPrivateEnvelope, PlainMessageIsNotEnvelope)
{
    const std::string plain = "not-an-envelope";
    EXPECT_FALSE(is_dkg_private_payload(plain));
}
