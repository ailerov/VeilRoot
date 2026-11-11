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
    EXPECT_EQ(BN_cmp(dec, m), 0);

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

#endif // VEILROOT_ENABLE_CL
