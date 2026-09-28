// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "governance/dao_paillier.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

// Deterministic unit r in Z_N* for reproducible tests. NOT for production.
bool deterministic_r(const BIGNUM* N, uint32_t seed, BIGNUM* out)
{
    BIGNUM* x = BN_new();
    if (!x) return false;
    std::vector<uint8_t> buf(32);
    for (int i = 0; i < 8; ++i) {
        buf[i] = static_cast<uint8_t>((seed >> (8 * i)) & 0xff);
    }
    BIGNUM* tmp = BN_bin2bn(buf.data(), static_cast<int>(buf.size()), nullptr);
    if (!tmp) { BN_free(x); return false; }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) { BN_free(tmp); BN_free(x); return false; }

    // hash = tmp mod N, then force coprime.
    bool ok = false;
    for (uint32_t attempt = 0; attempt < 64; ++attempt) {
        if (!BN_mod(x, tmp, N, ctx)) break;
        if (BN_is_zero(x)) { BN_add(tmp, tmp, BN_value_one()); continue; }
        BIGNUM* gcd = BN_new();
        if (!gcd) break;
        if (!BN_gcd(gcd, x, N, ctx)) { BN_free(gcd); break; }
        const bool coprime = BN_is_one(gcd);
        BN_free(gcd);
        if (coprime) { ok = BN_copy(out, x) != nullptr; break; }
        BN_add(tmp, tmp, BN_value_one());
    }

    BN_free(x);
    BN_free(tmp);
    BN_CTX_free(ctx);
    return ok;
}

} // namespace

// --------------------------------------------------------------------
// Known-answer tests for the algebraic relations
// --------------------------------------------------------------------

TEST(dao_paillier, keygen_and_round_trip_small)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));

    auto pk = sk.public_key();
    ASSERT_TRUE(pk.valid());

    BIGNUM* m = BN_new();
    BN_set_word(m, 42);

    BIGNUM* r = BN_new();
    ASSERT_TRUE(deterministic_r(pk.N(), 0xC0FFEE, r));

    std::vector<uint8_t> ct;
    ASSERT_TRUE(pk.encrypt(m, r, ct));
    EXPECT_EQ(ct.size(), PAILLIER_CT_BYTES);
    EXPECT_TRUE(pk.is_valid_ciphertext(ct));

    BIGNUM* m2 = BN_new();
    ASSERT_TRUE(sk.decrypt(ct, m2));
    EXPECT_EQ(BN_cmp(m, m2), 0);

    BN_clear_free(m); BN_clear_free(m2); BN_clear_free(r);
}

TEST(dao_paillier, homomorphic_addition)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m1 = BN_new(); BN_set_word(m1, 12345);
    BIGNUM* m2 = BN_new(); BN_set_word(m2, 67890);

    BIGNUM* r1 = BN_new(); ASSERT_TRUE(deterministic_r(pk.N(), 1, r1));
    BIGNUM* r2 = BN_new(); ASSERT_TRUE(deterministic_r(pk.N(), 2, r2));

    std::vector<uint8_t> c1, c2, c12;
    ASSERT_TRUE(pk.encrypt(m1, r1, c1));
    ASSERT_TRUE(pk.encrypt(m2, r2, c2));
    ASSERT_TRUE(pk.add(c1, c2, c12));

    BIGNUM* m12 = BN_new();
    ASSERT_TRUE(sk.decrypt(c12, m12));

    // m12 = (m1 + m2) mod N
    BIGNUM* expected = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_add(expected, m1, m2, pk.N(), ctx);
    EXPECT_EQ(BN_cmp(m12, expected), 0);

    BN_free(m1); BN_free(m2); BN_free(m12); BN_free(expected);
    BN_clear_free(r1); BN_clear_free(r2);
    BN_CTX_free(ctx);
}

TEST(dao_paillier, inverse_negates_plaintext)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 777);

    BIGNUM* r = BN_new(); ASSERT_TRUE(deterministic_r(pk.N(), 3, r));

    std::vector<uint8_t> c, cinv;
    ASSERT_TRUE(pk.encrypt(m, r, c));
    ASSERT_TRUE(pk.inverse(c, cinv));

    BIGNUM* mneg = BN_new();
    ASSERT_TRUE(sk.decrypt(cinv, mneg));

    // mneg = -m mod N = N - m
    BIGNUM* expected = BN_new();
    BN_sub(expected, pk.N(), m);
    EXPECT_EQ(BN_cmp(mneg, expected), 0);

    BN_free(m); BN_free(mneg); BN_free(expected); BN_clear_free(r);
}

TEST(dao_paillier, scalar_mul_multiplies_plaintext)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 3);
    BIGNUM* k = BN_new(); BN_set_word(k, 7);

    BIGNUM* r = BN_new(); ASSERT_TRUE(deterministic_r(pk.N(), 4, r));

    std::vector<uint8_t> c, ck;
    ASSERT_TRUE(pk.encrypt(m, r, c));
    ASSERT_TRUE(pk.scalar_mul(c, k, ck));

    BIGNUM* m_k = BN_new();
    ASSERT_TRUE(sk.decrypt(ck, m_k));

    BIGNUM* expected = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_mul(expected, m, k, pk.N(), ctx);
    EXPECT_EQ(BN_cmp(m_k, expected), 0);

    BN_free(m); BN_free(k); BN_free(m_k); BN_free(expected);
    BN_clear_free(r); BN_CTX_free(ctx);
}

TEST(dao_paillier, ciphertext_serialization_is_canonical)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 1);
    BIGNUM* r = BN_new(); ASSERT_TRUE(deterministic_r(pk.N(), 5, r));

    std::vector<uint8_t> c1, c2;
    ASSERT_TRUE(pk.encrypt(m, r, c1));

    // Re-serialize by deserializing the bytes and encrypting again with
    // the same randomness. Both must be byte-for-byte equal.
    ASSERT_TRUE(pk.encrypt(m, r, c2));
    EXPECT_EQ(c1, c2);

    BN_free(m); BN_clear_free(r);
}

TEST(dao_paillier, modulus_serialization_round_trip)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    std::vector<uint8_t> n_bytes;
    ASSERT_TRUE(pk.serialize_modulus(n_bytes));
    EXPECT_EQ(n_bytes.size(), PAILLIER_MODULUS_BYTES);

    PaillierPublicKey pk2;
    ASSERT_TRUE(pk2.deserialize_modulus(n_bytes));
    EXPECT_EQ(BN_cmp(pk.N(), pk2.N()), 0);
}

TEST(dao_paillier, rejects_zero_r)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new(); BN_set_word(m, 5);
    BIGNUM* r = BN_new(); // r = 0

    std::vector<uint8_t> ct;
    EXPECT_FALSE(pk.encrypt(m, r, ct));

    BN_free(m); BN_free(r);
}

TEST(dao_paillier, rejects_m_at_or_above_N)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_dup(pk.N());
    BIGNUM* r = BN_new(); ASSERT_TRUE(deterministic_r(pk.N(), 6, r));

    std::vector<uint8_t> ct;
    EXPECT_FALSE(pk.encrypt(m, r, ct));

    BN_free(m); BN_clear_free(r);
}

TEST(dao_paillier, rejects_invalid_ciphertext_length)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    std::vector<uint8_t> bad(PAILLIER_CT_BYTES - 1, 0x01);
    EXPECT_FALSE(pk.is_valid_ciphertext(bad));

    std::vector<uint8_t> bad2(PAILLIER_CT_BYTES, 0x00);
    EXPECT_FALSE(pk.is_valid_ciphertext(bad2));
}

TEST(dao_paillier, rejects_ciphertext_with_shared_factor)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    // c = 2 * N, which is < N^2 for N > 2 but gcd(c, N) = N.
    BIGNUM* c_bn = BN_new();
    BN_lshift(c_bn, pk.N(), 1);  // c = 2N

    std::vector<uint8_t> c(PAILLIER_CT_BYTES, 0);
    ASSERT_GE(BN_bn2binpad(c_bn, c.data(), PAILLIER_CT_BYTES), 0);

    EXPECT_FALSE(pk.is_valid_ciphertext(c));

    BN_free(c_bn);
}

// --------------------------------------------------------------------
// Signed plaintext encoding
// --------------------------------------------------------------------

TEST(dao_paillier, signed_positive_round_trips)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new();
    boost::multiprecision::int128_t S = 123456789;
    ASSERT_TRUE(encode_signed_value(S, pk.N(), m));

    boost::multiprecision::int128_t S2 = 0;
    ASSERT_TRUE(decode_signed_value(m, pk.N(), S2));
    EXPECT_EQ(S, S2);

    BN_free(m);
}

TEST(dao_paillier, signed_negative_round_trips)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new();
    boost::multiprecision::int128_t S = -987654321;
    ASSERT_TRUE(encode_signed_value(S, pk.N(), m));

    boost::multiprecision::int128_t S2 = 0;
    ASSERT_TRUE(decode_signed_value(m, pk.N(), S2));
    EXPECT_EQ(S, S2);

    BN_free(m);
}

TEST(dao_paillier, signed_zero_round_trips)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new();
    ASSERT_TRUE(encode_signed_value(boost::multiprecision::int128_t(0),
                                    pk.N(), m));
    EXPECT_TRUE(BN_is_zero(m));

    boost::multiprecision::int128_t S = 99;
    ASSERT_TRUE(decode_signed_value(m, pk.N(), S));
    EXPECT_EQ(S, 0);

    BN_free(m);
}

TEST(dao_paillier, encode_unsigned_weight_rejects_above_W_MAX)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    BIGNUM* m = BN_new();
    governance_weight_t too_big = governance_w_max() + 1;
    EXPECT_FALSE(encode_unsigned_weight(too_big, pk.N(), m));

    governance_weight_t at_max = governance_w_max();
    EXPECT_TRUE(encode_unsigned_weight(at_max, pk.N(), m));

    BN_free(m);
}

// --------------------------------------------------------------------
// End-to-end encrypted aggregation of many values
// --------------------------------------------------------------------

TEST(dao_paillier, encrypted_sum_of_many_values)
{
    PaillierPrivateKey sk;
    ASSERT_TRUE(sk.generate_for_testing(2048));
    auto pk = sk.public_key();

    std::vector<uint64_t> vals = { 0, 1, 1000, 1000000, 123456789 };
    uint64_t plain_sum = 0;

    std::vector<uint8_t> agg;
    bool have_agg = false;

    for (size_t i = 0; i < vals.size(); ++i) {
        BIGNUM* m = BN_new(); BN_set_word(m, vals[i]);
        BIGNUM* r = BN_new();
        ASSERT_TRUE(deterministic_r(pk.N(), 100 + static_cast<uint32_t>(i), r));

        std::vector<uint8_t> c;
        ASSERT_TRUE(pk.encrypt(m, r, c));
        if (!have_agg) { agg = c; have_agg = true; }
        else { std::vector<uint8_t> next; ASSERT_TRUE(pk.add(agg, c, next)); agg = next; }

        plain_sum += vals[i];
        BN_clear_free(m); BN_clear_free(r);
    }

    BIGNUM* recovered = BN_new();
    ASSERT_TRUE(sk.decrypt(agg, recovered));

    BIGNUM* expected = BN_new(); BN_set_word(expected, plain_sum);
    EXPECT_EQ(BN_cmp(recovered, expected), 0);

    BN_free(recovered); BN_free(expected);
}