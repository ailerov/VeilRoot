// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reset test: integer Shamir, small secret, no DKG.
// Proves sum_l lambda_l sigma_l = f(0) is preserved, and that the
// combined ciphertext from old shares equals the combined ciphertext
// from new shares under the same Paillier N.

#include <cstdint>
#include <cstring>
#include <vector>

#include <openssl/bn.h>

#include "gtest/gtest.h"
#include "governance/dao_dkg_reset.h"
#include "governance/dao_threshold.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

void bn_to_vec(const BIGNUM* x, std::vector<uint8_t>& v)
{
    int nb = BN_num_bytes(x);
    v.assign(nb, 0);
    BN_bn2bin(x, v.data());
}

// Build c = (1+N)^m mod N^2.
std::vector<uint8_t> fake_ciphertext(const BIGNUM* N, uint64_t m, BN_CTX* ctx)
{
    BIGNUM* N2 = BN_new();
    BIGNUM* g  = BN_new();
    BIGNUM* c  = BN_new();
    BIGNUM* me = BN_new();
    BN_sqr(N2, N, ctx);
    BN_add(g, N, BN_value_one());
    BN_set_word(me, m);
    BN_mod_exp(c, g, me, N2, ctx);

    std::vector<uint8_t> out;
    bn_to_vec(c, out);
    BN_free(N2); BN_free(g); BN_free(c); BN_free(me);
    return out;
}

// partial_i = c^(2*Delta*sigma_i) mod N^2
std::vector<uint8_t> partial(const BIGNUM* N, const BIGNUM* sigma,
                             const std::vector<uint8_t>& c_bytes,
                             BN_CTX* ctx)
{
    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, ctx);
    BIGNUM* c = BN_new();
    BN_bin2bn(c_bytes.data(), (int)c_bytes.size(), c);
    BIGNUM* exp = BN_new();
    BN_mul(exp, dao_dkg_delta(), sigma, ctx);
    BN_lshift(exp, exp, 1);   // *2

    BIGNUM* res = BN_new();
    if (BN_is_negative(exp)) {
        BIGNUM* inv = BN_mod_inverse(nullptr, c, N2, ctx);
        BIGNUM* pos = BN_dup(exp);
        BN_set_negative(pos, 0);
        BN_mod_exp(res, inv, pos, N2, ctx);
        BN_free(inv); BN_free(pos);
    } else {
        BN_mod_exp(res, c, exp, N2, ctx);
    }

    std::vector<uint8_t> out;
    bn_to_vec(res, out);
    BN_free(N2); BN_free(c); BN_free(exp); BN_free(res);
    return out;
}

// combine: prod partial_i^(2*mu_i) mod N^2. subset is 1-based ids.
std::vector<uint8_t> combine(const BIGNUM* N,
                             const std::vector<uint32_t>& subset,
                             const std::vector<std::vector<uint8_t>>& partials,
                             BN_CTX* ctx)
{
    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, ctx);
    BIGNUM* C = BN_new();
    BN_one(C);

    for (size_t k = 0; k < subset.size(); ++k) {
        BIGNUM* ci = BN_new();
        BN_bin2bn(partials[k].data(), (int)partials[k].size(), ci);

        BIGNUM* mu = BN_new();
        dao_dkg_lagrange_mu(subset, subset[k], mu);

        BIGNUM* exp = BN_new();
        BN_lshift(exp, mu, 1);   // *2

        BIGNUM* term = BN_new();
        if (BN_is_negative(exp)) {
            BIGNUM* inv = BN_mod_inverse(nullptr, ci, N2, ctx);
            BIGNUM* pos = BN_dup(exp);
            BN_set_negative(pos, 0);
            BN_mod_exp(term, inv, pos, N2, ctx);
            BN_free(inv); BN_free(pos);
        } else {
            BN_mod_exp(term, ci, exp, N2, ctx);
        }

        BN_mod_mul(C, C, term, N2, ctx);

        BN_free(ci); BN_free(mu); BN_free(exp); BN_free(term);
    }

    std::vector<uint8_t> out;
    bn_to_vec(C, out);
    BN_free(N2); BN_free(C);
    return out;
}

} // namespace

// -------------------------------------------------------------------
// Pure Shamir reset arithmetic. Old committee {1,2,3}, T=2, secret 42,
// polynomial f(x) = 42 + 100x. New committee {1..5}, T=3.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, shamir_small_secret_combine_matches)
{
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    // Fake modulus N. 128 bits is enough for the small arithmetic below.
    BIGNUM* N = BN_new();
    BN_set_bit(N, 127);
    BN_set_bit(N, 0);   // make it odd
    BN_set_bit(N, 63);  // some structure

    // Old shares: f(1)=142, f(2)=242, f(3)=342.
    std::vector<std::vector<uint8_t>> old_shares(3);
    {
        BIGNUM* s = BN_new();
        BN_set_word(s, 142); bn_to_vec(s, old_shares[0]);
        BN_set_word(s, 242); bn_to_vec(s, old_shares[1]);
        BN_set_word(s, 342); bn_to_vec(s, old_shares[2]);
        BN_free(s);
    }

    // Field modulus q: a 256-bit prime-ish number, well above any
    // intermediate for this test. Use 2^255 - 19 (Curve25519 prime).
    BIGNUM* q = BN_new();
    BN_set_bit(q, 255);
    BIGNUM* nineteen = BN_new();
    BN_set_word(nineteen, 19);
    BN_sub(q, q, nineteen);

    std::vector<uint8_t> q_bytes;
    bn_to_vec(q, q_bytes);

    // Encrypt m = 42.
    std::vector<uint8_t> c_bytes = fake_ciphertext(N, 42, ctx);

    // Old combine: subset {1, 2}.
    std::vector<std::vector<uint8_t>> old_partials(2);
    for (int i = 0; i < 2; ++i) {
        BIGNUM* sg = BN_new();
        BN_bin2bn(old_shares[i].data(), (int)old_shares[i].size(), sg);
        old_partials[i] = partial(N, sg, c_bytes, ctx);
        BN_free(sg);
    }
    std::vector<uint32_t> old_subset = {1, 2};
    std::vector<uint8_t> C_old = combine(N, old_subset, old_partials, ctx);

    // Reset 3 -> 5, T_new = 3.
    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 2;
    cfg.new_threshold = 3;
    cfg.old_members.resize(3);
    cfg.new_members.resize(5);
    for (size_t i = 0; i < 3; ++i) cfg.old_members[i].data[0] = (uint8_t)(i + 1);
    for (size_t i = 0; i < 5; ++i) cfg.new_members[i].data[0] = (uint8_t)(i + 1);

    std::vector<std::vector<uint8_t>> new_shares;
    ASSERT_TRUE(dao_dkg_reset_full_ceremony(cfg, old_shares, q_bytes, new_shares));
    ASSERT_EQ(new_shares.size(), 5u);

    // New combine: subset {1, 2, 3} of the new committee.
    std::vector<std::vector<uint8_t>> new_partials(3);
    for (int i = 0; i < 3; ++i) {
        BIGNUM* sg = BN_new();
        BN_bin2bn(new_shares[i].data(), (int)new_shares[i].size(), sg);
        new_partials[i] = partial(N, sg, c_bytes, ctx);
        BN_free(sg);
    }
    std::vector<uint32_t> new_subset = {1, 2, 3};
    std::vector<uint8_t> C_new = combine(N, new_subset, new_partials, ctx);

    // Compare C_old == C_new mod N^2.
    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, ctx);
    BIGNUM* co = BN_new(); BN_bin2bn(C_old.data(), (int)C_old.size(), co);
    BIGNUM* cn = BN_new(); BN_bin2bn(C_new.data(), (int)C_new.size(), cn);
    BIGNUM* diff = BN_new();
    BN_mod_sub(diff, co, cn, N2, ctx);
    EXPECT_TRUE(BN_is_zero(diff)) << "combined ciphertexts differ";

    BN_free(diff); BN_free(co); BN_free(cn); BN_free(N2);
    BN_free(q); BN_free(nineteen); BN_free(N);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// Resize coverage: 3->5, 5->3, 3->16, 16->3, 8->16, 16->8.
// Uses a fabricated old share vector. The combine ciphertext must be
// invariant across every reset.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, various_resizes_preserve_secret)
{
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* N = BN_new();
    BN_set_bit(N, 127);
    BN_set_bit(N, 0);
    BN_set_bit(N, 63);

    BIGNUM* q = BN_new();
    BN_set_bit(q, 255);
    BIGNUM* nineteen = BN_new();
    BN_set_word(nineteen, 19);
    BN_sub(q, q, nineteen);
    std::vector<uint8_t> q_bytes;
    bn_to_vec(q, q_bytes);

    std::vector<uint8_t> c_bytes = fake_ciphertext(N, 42, ctx);

    auto run_pair = [&](uint32_t n_old, uint32_t t_old,
                        uint32_t n_new, uint32_t t_new)
    {
        // Old shares: pick any low-degree integer polynomial
        // f(x) = 42 + 7x + 3x^2 + ... up to degree t_old - 1.
        // For coverage we just need old shares that reconstruct 42.
        std::vector<BIGNUM*> coeffs(t_old, nullptr);
        for (uint32_t k = 0; k < t_old; ++k) {
            coeffs[k] = BN_new();
            BN_set_word(coeffs[k], k == 0 ? 42 : (7 * (k + 1)));
        }

        std::vector<std::vector<uint8_t>> old_shares(n_old);
        for (uint32_t i = 0; i < n_old; ++i) {
            BIGNUM* eval = BN_new();
            dao_dkg_reset_evaluate(coeffs, i + 1, q, eval, ctx);
            bn_to_vec(eval, old_shares[i]);
            BN_free(eval);
        }

        // Old combine: take the first t_old shares.
        std::vector<uint32_t> old_subset;
        for (uint32_t i = 0; i < t_old; ++i) old_subset.push_back(i + 1);

        std::vector<std::vector<uint8_t>> old_partials(t_old);
        for (uint32_t i = 0; i < t_old; ++i) {
            BIGNUM* sg = BN_new();
            BN_bin2bn(old_shares[i].data(), (int)old_shares[i].size(), sg);
            old_partials[i] = partial(N, sg, c_bytes, ctx);
            BN_free(sg);
        }
        std::vector<uint8_t> C_old = combine(N, old_subset, old_partials, ctx);

        // Reset.
        dao_dkg_reset_config cfg{};
        cfg.old_threshold = t_old;
        cfg.new_threshold = t_new;
        cfg.old_members.resize(n_old);
        cfg.new_members.resize(n_new);
        for (size_t i = 0; i < n_old; ++i) cfg.old_members[i].data[0] = (uint8_t)i;
        for (size_t i = 0; i < n_new; ++i) cfg.new_members[i].data[0] = (uint8_t)i;

        std::vector<std::vector<uint8_t>> new_shares;
        ASSERT_TRUE(dao_dkg_reset_full_ceremony(cfg, old_shares, q_bytes, new_shares))
            << "reset " << n_old << "->" << n_new << " failed";
        ASSERT_EQ(new_shares.size(), n_new);

        std::vector<uint32_t> new_subset;
        for (uint32_t i = 0; i < t_new; ++i) new_subset.push_back(i + 1);

        std::vector<std::vector<uint8_t>> new_partials(t_new);
        for (uint32_t i = 0; i < t_new; ++i) {
            BIGNUM* sg = BN_new();
            BN_bin2bn(new_shares[i].data(), (int)new_shares[i].size(), sg);
            new_partials[i] = partial(N, sg, c_bytes, ctx);
            BN_free(sg);
        }
        std::vector<uint8_t> C_new = combine(N, new_subset, new_partials, ctx);

        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* co = BN_new(); BN_bin2bn(C_old.data(), (int)C_old.size(), co);
        BIGNUM* cn = BN_new(); BN_bin2bn(C_new.data(), (int)C_new.size(), cn);
        BIGNUM* d  = BN_new();
        BN_mod_sub(d, co, cn, N2, ctx);
        EXPECT_TRUE(BN_is_zero(d)) << "combine mismatch for "
                                   << n_old << "->" << n_new;

        BN_free(d); BN_free(co); BN_free(cn); BN_free(N2);
        for (auto* c : coeffs) BN_free(c);
    };

    run_pair(3, 2, 5, 3);
    run_pair(5, 3, 3, 2);
    run_pair(3, 2, 16, 8);
    run_pair(16, 8, 3, 2);
    run_pair(8, 4, 16, 8);
    run_pair(16, 8, 8, 4);

    BN_free(q); BN_free(nineteen); BN_free(N);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// Pedersen-verified Reset, single-process.
// 3 old shareholders, threshold 2 -> 5 new, threshold 3.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, pedersen_verified_resize)
{
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    // Small VSS group. For test speed: a small prime P = 2*P' + 1 with
    // g=2 and h=3 (h != g, no known log). Both g, h lie in the order-P'
    // subgroup. P' = 11 for illustration is too small for cryptographic
    // use but fine for the equation check.
    dao_vss_group vss;
    vss.P       = BN_new();
    vss.P_prime = BN_new();
    vss.g       = BN_new();
    vss.h       = BN_new();
    BN_set_word(vss.P,       23);   // 2*11 + 1
    BN_set_word(vss.P_prime, 11);
    BN_set_word(vss.g,       2);
    BN_set_word(vss.h,       4);    // 4 = 2^2 in the P' subgroup

    // Old shares: f(1)=142, f(2)=242, f(3)=342. Secret f(0) = 42.
    std::vector<std::vector<uint8_t>> old_shares(3);
    auto set_share = [](std::vector<uint8_t>& v, int64_t x) {
        BIGNUM* b = BN_new();
        BN_set_word(b, static_cast<BN_ULONG>(x));
        const int nb = BN_num_bytes(b);
        v.assign(1 + nb, 0);
        BN_bn2bin(b, v.data() + 1);
        BN_free(b);
    };
    set_share(old_shares[0], 142);
    set_share(old_shares[1], 242);
    set_share(old_shares[2], 342);

    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 2;
    cfg.new_threshold = 3;
    cfg.old_members.resize(3);
    cfg.new_members.resize(5);

    std::vector<dao_reset_public_contribution> publics(3);
    std::vector<std::vector<dao_reset_private_subshare>> private_sets(3);

    for (uint32_t l = 1; l <= 3; ++l) {
        ASSERT_TRUE(dao_dkg_reset_generate_contribution(
            cfg, l, old_shares[l-1], vss, publics[l-1], private_sets[l-1]));
        ASSERT_EQ(publics[l-1].coefficient_commitments.size(), 3u);
        ASSERT_EQ(private_sets[l-1].size(), 5u);
    }

    // Each new shareholder accepts.
    std::vector<std::vector<uint8_t>> new_shares(5);
    for (uint32_t j = 1; j <= 5; ++j) {
        std::vector<dao_reset_private_subshare> my;
        for (uint32_t l = 1; l <= 3; ++l) {
            for (const auto& ss : private_sets[l-1]) {
                if (ss.to_new_member_id == j) my.push_back(ss);
            }
        }
        ASSERT_TRUE(dao_dkg_reset_accept(
            cfg, j, publics, my, vss, new_shares[j-1]));
    }

    // Sanity: reconstruct SK(0) from any 3 new shares at 1..5 via integer
    // Lagrange. Must equal 42.
    BIGNUM* acc = BN_new();
    BN_zero(acc);
    std::vector<uint32_t> subset = {1, 2, 3};
    for (uint32_t i = 1; i <= 3; ++i) {
        BIGNUM* mu = BN_new();
        ASSERT_TRUE(dao_dkg_lagrange_mu(subset, i, mu));

        BIGNUM* si = BN_new();
        BN_bin2bn(new_shares[i-1].data() + 1,
                  static_cast<int>(new_shares[i-1].size() - 1), si);
        if (new_shares[i-1][0]) BN_set_negative(si, 1);

        BIGNUM* term = BN_new();
        BN_mul(term, mu, si, ctx);
        BN_add(acc, acc, term);

        BN_free(term); BN_free(si); BN_free(mu);
    }
    BIGNUM* Delta = BN_dup(dao_dkg_delta());
    BIGNUM* q = BN_new();
    BIGNUM* r = BN_new();
    BN_div(q, r, acc, Delta, ctx);
    ASSERT_TRUE(BN_is_zero(r));
    EXPECT_EQ(BN_get_word(q), 42u);

    BN_free(r); BN_free(q); BN_free(Delta); BN_free(acc);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// A single malicious old shareholder publishing a subshare that does not
// match its coefficient commitments must be rejected.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, tampered_subshare_rejected)
{
    dao_vss_group vss;
    vss.P       = BN_new();
    vss.P_prime = BN_new();
    vss.g       = BN_new();
    vss.h       = BN_new();
    BN_set_word(vss.P,       23);
    BN_set_word(vss.P_prime, 11);
    BN_set_word(vss.g,       2);
    BN_set_word(vss.h,       4);

    std::vector<uint8_t> old_share(2, 0);
    old_share[0] = 0;
    old_share[1] = 0x8e;   // 142

    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 2;
    cfg.new_threshold = 3;
    cfg.old_members.resize(3);
    cfg.new_members.resize(5);

    dao_reset_public_contribution pub;
    std::vector<dao_reset_private_subshare> priv;
    ASSERT_TRUE(dao_dkg_reset_generate_contribution(
        cfg, 1, old_share, vss, pub, priv));
    ASSERT_FALSE(priv.empty());

    // Flip a byte of the subshare for new member 2.
    auto& ss = priv[1];
    ss.subshare.back() ^= 0x01;

    EXPECT_FALSE(dao_dkg_reset_verify_subshare(
        vss, 2, ss.subshare, ss.blinding, pub.coefficient_commitments));

}
