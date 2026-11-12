// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Interface contract test for DaoEncryptionBackend via the Paillier
// backend. The CL backend is tested through the same interface
// methods in dao_crypto_backend_cl.cpp.

#include <cstring>
#include <vector>

#include "gtest/gtest.h"

#include <openssl/bn.h>

#include "governance/dao_crypto_backend.h"
#include "governance/dao_paillier.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

struct TestFixture {
    PaillierPrivateKey psk;
    std::vector<uint8_t> modulus;
    std::unique_ptr<DaoEncryptionBackend> backend;

    bool init()
    {
        if (!psk.generate_for_testing(1024)) return false;
        PaillierPublicKey pk = psk.public_key();
        if (!pk.serialize_modulus(modulus)) return false;
        backend = make_paillier_backend(modulus);
        return backend != nullptr;
    }
};

} // namespace

TEST(dao_crypto_backend, name_and_hint)
{
    TestFixture f;
    ASSERT_TRUE(f.init());
    EXPECT_EQ(f.backend->name(), "paillier");
    EXPECT_EQ(f.backend->ciphertext_size_hint(), PAILLIER_CT_BYTES);
}

TEST(dao_crypto_backend, modulus_roundtrip)
{
    TestFixture f;
    ASSERT_TRUE(f.init());

    std::vector<uint8_t> m1;
    ASSERT_TRUE(f.backend->serialize_modulus(m1));
    ASSERT_EQ(m1.size(), PAILLIER_MODULUS_BYTES);

    auto b2 = make_paillier_backend();
    ASSERT_NE(b2, nullptr);
    ASSERT_TRUE(b2->deserialize_modulus(m1));
    std::vector<uint8_t> m2;
    ASSERT_TRUE(b2->serialize_modulus(m2));
    EXPECT_EQ(m1, m2);
}

TEST(dao_crypto_backend, homomorphic_add_matches_plaintext_sum)
{
    TestFixture f;
    ASSERT_TRUE(f.init());

    BIGNUM* m1 = BN_new(); BN_set_word(m1, 1234);
    BIGNUM* m2 = BN_new(); BN_set_word(m2, 5678);
    BIGNUM* r1 = BN_new(); BIGNUM* r2 = BN_new();
    ASSERT_TRUE(f.backend->sample_r(r1));
    ASSERT_TRUE(f.backend->sample_r(r2));

    std::vector<uint8_t> c1, c2, csum;
    ASSERT_TRUE(f.backend->encrypt(m1, r1, c1));
    ASSERT_TRUE(f.backend->encrypt(m2, r2, c2));
    ASSERT_TRUE(f.backend->add(c1, c2, csum));

    BIGNUM* dec = BN_new();
    ASSERT_TRUE(f.psk.decrypt(csum, dec));
    BIGNUM* expect = BN_new(); BN_set_word(expect, 1234 + 5678);
    EXPECT_EQ(BN_cmp(dec, expect), 0);

    BN_free(m1); BN_free(m2); BN_free(r1); BN_free(r2);
    BN_free(dec); BN_free(expect);
}

TEST(dao_crypto_backend, ciphertext_validity)
{
    TestFixture f;
    ASSERT_TRUE(f.init());

    BIGNUM* m = BN_new(); BN_set_word(m, 7);
    BIGNUM* r = BN_new();
    ASSERT_TRUE(f.backend->sample_r(r));
    std::vector<uint8_t> c;
    ASSERT_TRUE(f.backend->encrypt(m, r, c));
    EXPECT_TRUE(f.backend->is_valid_ciphertext(c));

    std::vector<uint8_t> short_c(PAILLIER_CT_BYTES - 1, 0);
    EXPECT_FALSE(f.backend->is_valid_ciphertext(short_c));

    BN_free(m); BN_free(r);
}

TEST(dao_crypto_backend, factory_rejects_bad_modulus)
{
    std::vector<uint8_t> bad(PAILLIER_MODULUS_BYTES - 1, 0xAA);
    auto b = make_paillier_backend(bad);
    EXPECT_EQ(b, nullptr);
}
