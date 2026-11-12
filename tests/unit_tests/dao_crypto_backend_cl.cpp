// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Phase 4.2b round-trip test for the CL-over-class-groups backend.
// Compiled only under VEILROOT_ENABLE_CL. Phase 4.2c+ adds tests for
// homomorphic add, scalar_mul, inverse, and modulus deserialize.

#ifdef VEILROOT_ENABLE_CL

#include <vector>

#include "gtest/gtest.h"

#include <openssl/bn.h>

#include "governance/dao_crypto_backend.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

#define EXPECT_BN_EQ(_a, _b) do { \
    if (BN_cmp((_a), (_b)) != 0) { \
        char* _sa = BN_bn2hex((_a)); \
        char* _sb = BN_bn2hex((_b)); \
        ADD_FAILURE() << "BN mismatch: got " << _sa << " expected " << _sb; \
        OPENSSL_free(_sa); OPENSSL_free(_sb); \
    } \
} while (0)

std::unique_ptr<DaoEncryptionBackend> make_test_backend()
{
    // 128-bit security level matches the reference implementation
    // benchmarks (benchmark_qclpvss.cpp etc.). Test runs are short.
    return make_cl_backend(128);
}

} // namespace

TEST(dao_crypto_backend_cl, encrypt_decrypt_roundtrip_1234)
{
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);
    EXPECT_EQ(backend->name(), "cl_hsmqk");
    EXPECT_EQ(backend->ciphertext_size_hint(), 0u);  // variable-length

    BIGNUM* m = BN_new(); BN_set_word(m, 1234);
    BIGNUM* r = BN_new();
    ASSERT_TRUE(backend->sample_r(r));

    std::vector<uint8_t> ct;
    ASSERT_TRUE(backend->encrypt(m, r, ct));
    EXPECT_GT(ct.size(), 0u);
    EXPECT_TRUE(backend->is_valid_ciphertext(ct));

    BIGNUM* dec = BN_new();
    ASSERT_TRUE(backend->decrypt_for_testing(ct, dec));
    EXPECT_BN_EQ(dec, m);

    BN_free(m); BN_free(r); BN_free(dec);
}

TEST(dao_crypto_backend_cl, encrypt_uses_fresh_randomness)
{
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);

    BIGNUM* m = BN_new(); BN_set_word(m, 0);
    BIGNUM* r1 = BN_new(); BIGNUM* r2 = BN_new();
    ASSERT_TRUE(backend->sample_r(r1));
    ASSERT_TRUE(backend->sample_r(r2));

    std::vector<uint8_t> ct1, ct2;
    ASSERT_TRUE(backend->encrypt(m, r1, ct1));
    ASSERT_TRUE(backend->encrypt(m, r2, ct2));
    // Same plaintext + different randomness => distinct ciphertexts.
    EXPECT_NE(ct1, ct2);

    BN_free(m); BN_free(r1); BN_free(r2);
}


TEST(dao_crypto_backend_cl, homomorphic_add)
{
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);

    BIGNUM* a = BN_new(); BN_set_word(a, 1000);
    BIGNUM* b = BN_new(); BN_set_word(b, 2000);
    BIGNUM* ra = BN_new(); BIGNUM* rb = BN_new();
    ASSERT_TRUE(backend->sample_r(ra));
    ASSERT_TRUE(backend->sample_r(rb));

    std::vector<uint8_t> ca, cb, sum;
    ASSERT_TRUE(backend->encrypt(a, ra, ca));
    ASSERT_TRUE(backend->encrypt(b, rb, cb));
    ASSERT_TRUE(backend->add(ca, cb, sum));
    EXPECT_TRUE(backend->is_valid_ciphertext(sum));

    BIGNUM* dec = BN_new();
    ASSERT_TRUE(backend->decrypt_for_testing(sum, dec));
    BIGNUM* expect = BN_new(); BN_set_word(expect, 3000);
    EXPECT_BN_EQ(dec, expect);

    BN_free(a); BN_free(b); BN_free(ra); BN_free(rb);
    BN_free(dec); BN_free(expect);
}

TEST(dao_crypto_backend_cl, homomorphic_scalar_mul)
{
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);

    BIGNUM* m = BN_new(); BN_set_word(m, 5);
    BIGNUM* k = BN_new(); BN_set_word(k, 10);
    BIGNUM* r = BN_new();
    ASSERT_TRUE(backend->sample_r(r));

    std::vector<uint8_t> ct, scaled;
    ASSERT_TRUE(backend->encrypt(m, r, ct));
    ASSERT_TRUE(backend->scalar_mul(ct, k, scaled));

    BIGNUM* dec = BN_new();
    ASSERT_TRUE(backend->decrypt_for_testing(scaled, dec));
    BIGNUM* expect = BN_new(); BN_set_word(expect, 50);
    EXPECT_BN_EQ(dec, expect);

    BN_free(m); BN_free(k); BN_free(r); BN_free(dec); BN_free(expect);
}

TEST(dao_crypto_backend_cl, homomorphic_add_inverse)
{
    // encrypt(500) + inverse(encrypt(300)) == encrypt(200) mod q
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);

    BIGNUM* a = BN_new(); BN_set_word(a, 500);
    BIGNUM* b = BN_new(); BN_set_word(b, 300);
    BIGNUM* ra = BN_new(); BIGNUM* rb = BN_new();
    ASSERT_TRUE(backend->sample_r(ra));
    ASSERT_TRUE(backend->sample_r(rb));

    std::vector<uint8_t> ca, cb, negb, combined;
    ASSERT_TRUE(backend->encrypt(a, ra, ca));
    ASSERT_TRUE(backend->encrypt(b, rb, cb));
    ASSERT_TRUE(backend->inverse(cb, negb));
    ASSERT_TRUE(backend->add(ca, negb, combined));

    BIGNUM* dec = BN_new();
    ASSERT_TRUE(backend->decrypt_for_testing(combined, dec));
    BIGNUM* expect = BN_new(); BN_set_word(expect, 200);
    EXPECT_BN_EQ(dec, expect);

    BN_free(a); BN_free(b); BN_free(ra); BN_free(rb);
    BN_free(dec); BN_free(expect);
}

#endif // VEILROOT_ENABLE_CL
