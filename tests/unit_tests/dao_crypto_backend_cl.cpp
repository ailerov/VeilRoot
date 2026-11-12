// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Tests for the CL-over-class-groups DaoEncryptionBackend. Compiled
// only under VEILROOT_ENABLE_CL.

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


TEST(dao_crypto_backend_cl, modulus_roundtrip_cross_backend)
{
    // Backend A holds the secret key; backend B is constructed empty
    // and then loaded from A's serialized modulus. B must be able to
    // encrypt under the same public key: A must be able to decrypt
    // B's ciphertexts. Byte-for-byte ciphertext equality is a strong
    // extra invariant given BICYCL's deterministic (m, r, pk) -> ct
    // mapping.
    auto a = make_test_backend();
    ASSERT_NE(a, nullptr);

    std::vector<uint8_t> mod1;
    ASSERT_TRUE(a->serialize_modulus(mod1));
    EXPECT_GT(mod1.size(), 0u);

    auto b = make_test_backend();  // fresh backend, its own key
    ASSERT_NE(b, nullptr);
    ASSERT_TRUE(b->deserialize_modulus(mod1));

    // Roundtrip: B reserializes to identical bytes.
    std::vector<uint8_t> mod2;
    ASSERT_TRUE(b->serialize_modulus(mod2));
    EXPECT_EQ(mod1, mod2);

    // Cross-backend encryption: B encrypts, A decrypts.
    BIGNUM* m = BN_new(); BN_set_word(m, 4242);
    BIGNUM* r = BN_new();
    ASSERT_TRUE(b->sample_r(r));

    std::vector<uint8_t> ct_b;
    ASSERT_TRUE(b->encrypt(m, r, ct_b));

    std::vector<uint8_t> ct_a;
    ASSERT_TRUE(a->encrypt(m, r, ct_a));

    // Same (m, r, pk) -> identical ciphertext bytes.
    EXPECT_EQ(ct_a, ct_b);

    BIGNUM* dec = BN_new();
    ASSERT_TRUE(a->decrypt_for_testing(ct_b, dec));
    EXPECT_BN_EQ(dec, m);

    // B has no secret key after deserialize.
    BIGNUM* dummy = BN_new();
    EXPECT_FALSE(b->decrypt_for_testing(ct_b, dummy));
    BN_free(dummy);

    BN_free(m); BN_free(r); BN_free(dec);
}


TEST(dao_crypto_backend_cl, weighted_max_arithmetic_bounds)
{
    // Signed tally values in [-W_MAX, +W_MAX] must be injectively
    // encodable in Z_q. Compile-time check in dao_crypto_backend.h:
    // 2*W_MAX + 1 < 2^69. Runtime check in CLEncryptionBackend
    // constructor: q >= 2^200. Chain:
    //   q > 2^200 >> 2^69 > 2*W_MAX + 1  =>  injective.
    // This test cross-checks the constants.
#if defined(__SIZEOF_INT128__)
    using u128 = unsigned __int128;

    const u128 w_max = DAO_WEIGHTED_MAX;
    const u128 signed_range = DAO_SIGNED_RANGE_SIZE;

    const u128 expected_w_max =
        (u128)240000000ULL * (u128)1000000000000ULL;
    EXPECT_EQ(w_max, expected_w_max);

    EXPECT_EQ(signed_range, 2 * w_max + 1);

    EXPECT_LT(signed_range, (((u128)1) << 69));

    const u128 four_w_max = 4 * w_max;
    EXPECT_LT(four_w_max, (((u128)1) << 70));
#endif

    auto backend = make_test_backend();
    EXPECT_NE(backend, nullptr);
}


TEST(dao_crypto_backend_cl, wire_rejects_leading_zero_magnitude)
{
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);
    // SCALAR with sign=0, len=2, magnitude=[0x00,0x05] — leading zero.
    std::vector<uint8_t> ct = {0, 0, 0, 0, 2, 0x00, 0x05};
    EXPECT_FALSE(backend->is_valid_ciphertext(ct));
}

TEST(dao_crypto_backend_cl, wire_rejects_negative_a_or_c)
{
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);
    // SCALAR with sign=1 (negative) — 'a' must be positive in reduced form.
    std::vector<uint8_t> ct = {1, 0, 0, 0, 1, 0x05};
    EXPECT_FALSE(backend->is_valid_ciphertext(ct));
}

TEST(dao_crypto_backend_cl, wire_rejects_negative_zero_b)
{
    auto backend = make_test_backend();
    ASSERT_NE(backend, nullptr);
    // SCALAR(a)=1 encoded canonically, then SCALAR(b) with sign=1 len=0 (negative zero).
    std::vector<uint8_t> ct = {0, 0, 0, 0, 1, 0x01,   1, 0, 0, 0, 0};
    EXPECT_FALSE(backend->is_valid_ciphertext(ct));
}

TEST(dao_crypto_backend_cl, wire_rejects_ciphertext_from_other_discriminant)
{
    auto a = make_test_backend();
    auto b = make_test_backend();  // independent p, different discriminant
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);

    BIGNUM* m = BN_new(); BN_set_word(m, 42);
    BIGNUM* r = BN_new();
    ASSERT_TRUE(a->sample_r(r));
    std::vector<uint8_t> ct;
    ASSERT_TRUE(a->encrypt(m, r, ct));

    EXPECT_TRUE(a->is_valid_ciphertext(ct));
    EXPECT_FALSE(b->is_valid_ciphertext(ct));

    BN_free(m); BN_free(r);
}

#endif // VEILROOT_ENABLE_CL
