// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include <openssl/bn.h>

#include "governance/dao_threshold.h"
#include "governance/dao_paillier.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

// Deterministic 256-bit test coefficient.
BIGNUM* test_coeff(uint32_t seed)
{
    std::vector<uint8_t> buf(32, 0);
    for (int i = 0; i < 8; ++i)
        buf[i] = static_cast<uint8_t>((seed >> (8 * i)) & 0xff);
    // Make it clearly nonzero.
    buf[31] = static_cast<uint8_t>(seed & 0xff) | 0x01;
    return BN_bin2bn(buf.data(), static_cast<int>(buf.size()), nullptr);
}

// Evaluate f(X) = secret + sum_{k=1..t} coeffs[k-1] * X^k at X = x.
BIGNUM* eval_poly(const BIGNUM* secret,
                  const std::vector<BIGNUM*>& coeffs,
                  uint32_t x,
                  BN_CTX* ctx)
{
    BIGNUM* result = BN_dup(secret);
    if (!result) return nullptr;

    BIGNUM* xk = BN_new();
    if (!xk) { BN_free(result); return nullptr; }
    BN_one(xk);

    for (size_t k = 0; k < coeffs.size(); ++k) {
        if (!BN_mul_word(xk, x)) {
            BN_free(result); BN_free(xk); return nullptr;
        }
        BIGNUM* term = BN_new();
        if (!term) { BN_free(result); BN_free(xk); return nullptr; }
        if (!BN_mul(term, coeffs[k], xk, ctx)) {
            BN_free(result); BN_free(xk); BN_free(term); return nullptr;
        }
        BN_add(result, result, term);
        BN_free(term);
    }

    BN_free(xk);
    return result;
}

} // namespace

// ------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------

TEST(dao_threshold, frozen_parameters)
{
    EXPECT_EQ(DAO_DKG_COMMITTEE_SIZE, 16u);
    EXPECT_EQ(DAO_DKG_SHARING_DEGREE, 7u);
    EXPECT_EQ(DAO_DKG_THRESHOLD, 8u);

    const BIGNUM* d = dao_dkg_delta();
    ASSERT_NE(d, nullptr);
    char* s = BN_bn2dec(d);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(std::string(s), "20922789888000");
    OPENSSL_free(s);
}

// ------------------------------------------------------------------
// Lagrange coefficients
// ------------------------------------------------------------------

TEST(dao_threshold, lagrange_coefficients_sum_to_delta)
{
    // sum_i mu_i = Delta because the Lagrange basis sums to 1 at 0.
    const std::vector<uint32_t> S = { 1, 2, 3, 4, 5, 6, 7, 8 };

    BIGNUM* sum = BN_new();
    BN_zero(sum);

    for (uint32_t i : S) {
        BIGNUM* mu = BN_new();
        ASSERT_TRUE(dao_dkg_lagrange_mu(S, i, mu));
        BN_add(sum, sum, mu);
        BN_free(mu);
    }

    EXPECT_EQ(BN_cmp(sum, dao_dkg_delta()), 0);
    BN_free(sum);
}

TEST(dao_threshold, lagrange_reconstructs_simple_polynomial)
{
    // f(X) = 1 + 2X + 3X^2. Any 8-member subset must satisfy
    // sum_i mu_i * f(i) = Delta * f(0) = Delta.
    const std::vector<uint32_t> S = { 2, 4, 6, 8, 10, 12, 14, 16 };

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* sum = BN_new();
    BN_zero(sum);

    for (uint32_t i : S) {
        BIGNUM* mu = BN_new();
        ASSERT_TRUE(dao_dkg_lagrange_mu(S, i, mu));

        const uint64_t fi = 1 + 2ULL * i + 3ULL * i * i;
        BIGNUM* fi_bn = BN_new();
        BN_set_word(fi_bn, fi);

        BIGNUM* term = BN_new();
        BN_mul(term, mu, fi_bn, ctx);
        BN_add(sum, sum, term);

        BN_free(mu); BN_free(fi_bn); BN_free(term);
    }

    EXPECT_EQ(BN_cmp(sum, dao_dkg_delta()), 0);

    BN_free(sum);
    BN_CTX_free(ctx);
}

TEST(dao_threshold, lagrange_rejects_member_not_in_subset)
{
    const std::vector<uint32_t> S = { 1, 2, 3 };
    BIGNUM* mu = BN_new();
    EXPECT_FALSE(dao_dkg_lagrange_mu(S, 4, mu));
    BN_free(mu);
}

// ------------------------------------------------------------------
// Full threshold round-trip with a locally generated Paillier key.
//
// Test-only setup: uses a locally-known lambda. Production key
// material comes from the Nishide-Sakurai DKG (3b); no production
// path calls these helpers.
// ------------------------------------------------------------------

class ThresholdRoundTrip : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sk_ = new PaillierPrivateKey();
        ASSERT_TRUE(sk_->generate_for_testing(1024));
        pk_ = new PaillierPublicKey(sk_->public_key());
        ASSERT_TRUE(pk_->valid());
    }
    static void TearDownTestSuite() {
        delete sk_; sk_ = nullptr;
        delete pk_; pk_ = nullptr;
    }
    static PaillierPrivateKey* sk_;
    static PaillierPublicKey* pk_;
};

PaillierPrivateKey* ThresholdRoundTrip::sk_ = nullptr;
PaillierPublicKey* ThresholdRoundTrip::pk_ = nullptr;

TEST_F(ThresholdRoundTrip, eight_of_sixteen_recovers_plaintext)
{
    // Setup: secret d = -lambda, theta' = lambda.
    // Then C = c^(4 Delta^2 * (-lambda)), L(C) = m * 4 Delta^2 * (-lambda),
    // M = L(C) / (-4 Delta^2 lambda) = m.
    BIGNUM* secret = BN_dup(sk_->lambda());
    ASSERT_NE(secret, nullptr);
    BN_set_negative(secret, 1);

    std::vector<BIGNUM*> coeffs;
    for (uint32_t k = 1; k <= DAO_DKG_SHARING_DEGREE; ++k)
        coeffs.push_back(test_coeff(0xAA00 + k));

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    std::vector<BIGNUM*> shares(DAO_DKG_COMMITTEE_SIZE + 1, nullptr);
    for (uint32_t i = 1; i <= DAO_DKG_COMMITTEE_SIZE; ++i) {
        shares[i] = eval_poly(secret, coeffs, i, ctx);
        ASSERT_NE(shares[i], nullptr);
    }

    // Encrypt a known plaintext.
    BIGNUM* m = BN_new();
    BN_set_word(m, 987654321);
    BIGNUM* r = BN_new();
    BN_set_word(r, 2);   // small coprime r; nonce reuse is fine here

    std::vector<uint8_t> ct;
    ASSERT_TRUE(pk_->encrypt(m, r, ct));

    // Partial decrypt with 8 of 16 shares (subset {1..8}).
    std::vector<uint32_t> subset = { 1, 2, 3, 4, 5, 6, 7, 8 };
    std::vector<std::vector<uint8_t>> partials;
    partials.reserve(subset.size());
    for (uint32_t i : subset) {
        std::vector<uint8_t> p;
        ASSERT_TRUE(dao_threshold_partial_decrypt(*pk_, ct, shares[i], p));
        partials.push_back(std::move(p));
    }

    // Combine.
    std::vector<uint8_t> C;
    ASSERT_TRUE(dao_threshold_combine(*pk_, subset, partials, DAO_DKG_THRESHOLD, C));

    // Finalize with theta' = lambda.
    BIGNUM* m_rec = BN_new();
    ASSERT_TRUE(dao_threshold_finalize(*pk_, C, sk_->lambda(), m_rec));

    EXPECT_EQ(BN_cmp(m, m_rec), 0);

    // Cleanup.
    BN_free(m);
    BN_free(r);
    BN_free(m_rec);
    BN_free(secret);
    for (auto* c : coeffs) BN_free(c);
    for (auto* s : shares) if (s) BN_free(s);
    BN_CTX_free(ctx);
}

TEST_F(ThresholdRoundTrip, alternate_subset_also_recovers)
{
    BIGNUM* secret = BN_dup(sk_->lambda());
    BN_set_negative(secret, 1);

    std::vector<BIGNUM*> coeffs;
    for (uint32_t k = 1; k <= DAO_DKG_SHARING_DEGREE; ++k)
        coeffs.push_back(test_coeff(0xBB00 + k));

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    std::vector<BIGNUM*> shares(DAO_DKG_COMMITTEE_SIZE + 1, nullptr);
    for (uint32_t i = 1; i <= DAO_DKG_COMMITTEE_SIZE; ++i)
        shares[i] = eval_poly(secret, coeffs, i, ctx);

    BIGNUM* m = BN_new();
    BN_set_word(m, 42);
    BIGNUM* r = BN_new();
    BN_set_word(r, 3);

    std::vector<uint8_t> ct;
    ASSERT_TRUE(pk_->encrypt(m, r, ct));

    // A different 8-member subset: {9, 10, 11, 12, 13, 14, 15, 16}.
    std::vector<uint32_t> subset = { 9, 10, 11, 12, 13, 14, 15, 16 };
    std::vector<std::vector<uint8_t>> partials;
    for (uint32_t i : subset) {
        std::vector<uint8_t> p;
        ASSERT_TRUE(dao_threshold_partial_decrypt(*pk_, ct, shares[i], p));
        partials.push_back(std::move(p));
    }

    std::vector<uint8_t> C;
    ASSERT_TRUE(dao_threshold_combine(*pk_, subset, partials, DAO_DKG_THRESHOLD, C));

    BIGNUM* m_rec = BN_new();
    ASSERT_TRUE(dao_threshold_finalize(*pk_, C, sk_->lambda(), m_rec));

    EXPECT_EQ(BN_cmp(m, m_rec), 0);

    BN_free(m); BN_free(r); BN_free(m_rec); BN_free(secret);
    for (auto* c : coeffs) BN_free(c);
    for (auto* s : shares) if (s) BN_free(s);
    BN_CTX_free(ctx);
}

TEST_F(ThresholdRoundTrip, too_few_shares_rejected_by_combine)
{
    std::vector<uint32_t> subset = { 1, 2, 3, 4, 5, 6, 7 };
    std::vector<std::vector<uint8_t>> partials;
    for (size_t i = 0; i < subset.size(); ++i)
        partials.push_back(std::vector<uint8_t>(PAILLIER_CT_BYTES, 0));

    std::vector<uint8_t> C;
    EXPECT_FALSE(dao_threshold_combine(*pk_, subset, partials, DAO_DKG_THRESHOLD, C));
}

TEST_F(ThresholdRoundTrip, size_mismatch_rejected)
{
    std::vector<uint32_t> subset = { 1, 2, 3, 4, 5, 6, 7, 8 };
    std::vector<std::vector<uint8_t>> partials;
    for (size_t i = 0; i < 7; ++i)
        partials.push_back(std::vector<uint8_t>(PAILLIER_CT_BYTES, 0));

    std::vector<uint8_t> C;
    EXPECT_FALSE(dao_threshold_combine(*pk_, subset, partials, DAO_DKG_THRESHOLD, C));
}