// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

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

void bn_to_pad512(const BIGNUM* x, std::vector<uint8_t>& v)
{
    v.assign(512, 0);
    BN_bn2binpad(x, v.data(), 512);
}

void make_signed_share(int64_t x, std::vector<uint8_t>& v)
{
    BIGNUM* b = BN_new();
    if (x >= 0) {
        BN_set_word(b, (BN_ULONG)x);
        v.assign(1 + BN_num_bytes(b), 0);
        BN_bn2bin(b, v.data() + 1);
    } else {
        BN_set_word(b, (BN_ULONG)(-x));
        v.assign(1 + BN_num_bytes(b), 0);
        v[0] = 1;
        BN_bn2bin(b, v.data() + 1);
    }
    BN_free(b);
}

// Small toy VSS group: P = 2q + 1 with q = 23 -> P = 47.  g = 4, h = 16
// both in the order-q subgroup. Safe for equation checks only.
void tiny_vss(dao_vss_group& vss)
{
    vss.P       = BN_new();
    vss.P_prime = BN_new();
    vss.g       = BN_new();
    vss.h       = BN_new();
    BN_set_word(vss.P,       47);
    BN_set_word(vss.P_prime, 23);
    BN_set_word(vss.g,       4);
    BN_set_word(vss.h,       16);
}

} // namespace

// -------------------------------------------------------------------
// Pure integer reset arithmetic.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, shamir_small_secret_combine_matches)
{
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* N = BN_new();
    BN_set_bit(N, 127); BN_set_bit(N, 0); BN_set_bit(N, 63);

    std::vector<std::vector<uint8_t>> old_shares(3);
    {
        BIGNUM* b = BN_new();
        BN_set_word(b, 142); bn_to_vec(b, old_shares[0]);
        BN_set_word(b, 242); bn_to_vec(b, old_shares[1]);
        BN_set_word(b, 342); bn_to_vec(b, old_shares[2]);
        BN_free(b);
    }

    BIGNUM* q = BN_new();
    BN_set_bit(q, 255);
    BIGNUM* nineteen = BN_new(); BN_set_word(nineteen, 19);
    BN_sub(q, q, nineteen);
    std::vector<uint8_t> q_bytes; bn_to_vec(q, q_bytes);

    auto fake_ct = [&](uint64_t m) {
        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* g  = BN_new(); BN_add(g, N, BN_value_one());
        BIGNUM* me = BN_new(); BN_set_word(me, m);
        BIGNUM* c  = BN_new(); BN_mod_exp(c, g, me, N2, ctx);
        std::vector<uint8_t> out; bn_to_vec(c, out);
        BN_free(N2); BN_free(g); BN_free(me); BN_free(c);
        return out;
    };

    auto partial = [&](const BIGNUM* s, const std::vector<uint8_t>& c_bytes) {
        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* c = BN_new(); BN_bin2bn(c_bytes.data(), (int)c_bytes.size(), c);
        BIGNUM* exp = BN_new();
        BN_mul(exp, dao_dkg_delta(), s, ctx);
        BN_lshift(exp, exp, 1);
        BIGNUM* res = BN_new();
        if (BN_is_negative(exp)) {
            BIGNUM* inv = BN_mod_inverse(nullptr, c, N2, ctx);
            BIGNUM* pos = BN_dup(exp); BN_set_negative(pos, 0);
            BN_mod_exp(res, inv, pos, N2, ctx);
            BN_free(inv); BN_free(pos);
        } else BN_mod_exp(res, c, exp, N2, ctx);
        std::vector<uint8_t> out; bn_to_vec(res, out);
        BN_free(N2); BN_free(c); BN_free(exp); BN_free(res);
        return out;
    };

    auto combine = [&](const std::vector<uint32_t>& subset,
                       const std::vector<std::vector<uint8_t>>& partials) {
        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* C = BN_new(); BN_one(C);
        for (size_t k = 0; k < subset.size(); ++k) {
            BIGNUM* ci = BN_new(); BN_bin2bn(partials[k].data(), (int)partials[k].size(), ci);
            BIGNUM* mu = BN_new(); dao_dkg_lagrange_mu(subset, subset[k], mu);
            BIGNUM* exp = BN_new(); BN_lshift(exp, mu, 1);
            BIGNUM* term = BN_new();
            if (BN_is_negative(exp)) {
                BIGNUM* inv = BN_mod_inverse(nullptr, ci, N2, ctx);
                BIGNUM* pos = BN_dup(exp); BN_set_negative(pos, 0);
                BN_mod_exp(term, inv, pos, N2, ctx);
                BN_free(inv); BN_free(pos);
            } else BN_mod_exp(term, ci, exp, N2, ctx);
            BN_mod_mul(C, C, term, N2, ctx);
            BN_free(ci); BN_free(mu); BN_free(exp); BN_free(term);
        }
        std::vector<uint8_t> out; bn_to_vec(C, out);
        BN_free(N2); BN_free(C);
        return out;
    };

    std::vector<uint8_t> c_bytes = fake_ct(42);

    std::vector<std::vector<uint8_t>> old_partials(2);
    for (int i = 0; i < 2; ++i) {
        BIGNUM* s = BN_new();
        BN_bin2bn(old_shares[i].data(), (int)old_shares[i].size(), s);
        old_partials[i] = partial(s, c_bytes);
        BN_free(s);
    }
    std::vector<uint8_t> C_old = combine({1,2}, old_partials);

    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 2;
    cfg.new_threshold = 3;
    cfg.old_members.resize(3);
    cfg.new_members.resize(5);
    cfg.reset_participant_ids = {1, 2};

    std::vector<std::vector<uint8_t>> participant_shares;
    participant_shares.push_back(old_shares[0]);
    participant_shares.push_back(old_shares[1]);
    std::vector<std::vector<uint8_t>> new_shares;
    ASSERT_TRUE(dao_dkg_reset_full_ceremony(cfg, participant_shares, q_bytes, new_shares));
    ASSERT_EQ(new_shares.size(), 5u);

    std::vector<std::vector<uint8_t>> new_partials(3);
    for (int i = 0; i < 3; ++i) {
        BIGNUM* s = BN_new();
        BN_bin2bn(new_shares[i].data(), (int)new_shares[i].size(), s);
        new_partials[i] = partial(s, c_bytes);
        BN_free(s);
    }
    std::vector<uint8_t> C_new = combine({1,2,3}, new_partials);

    BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
    BIGNUM* co = BN_new(); BN_bin2bn(C_old.data(), (int)C_old.size(), co);
    BIGNUM* cn = BN_new(); BN_bin2bn(C_new.data(), (int)C_new.size(), cn);
    BIGNUM* d  = BN_new(); BN_mod_sub(d, co, cn, N2, ctx);
    EXPECT_TRUE(BN_is_zero(d));

    BN_free(d); BN_free(co); BN_free(cn); BN_free(N2);
    BN_free(q); BN_free(nineteen); BN_free(N);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// Various resizes preserve the secret.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, various_resizes_preserve_secret)
{
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* N = BN_new();
    BN_set_bit(N, 127); BN_set_bit(N, 0); BN_set_bit(N, 63);

    BIGNUM* q = BN_new();
    BN_set_bit(q, 255);
    BIGNUM* nineteen = BN_new(); BN_set_word(nineteen, 19);
    BN_sub(q, q, nineteen);
    std::vector<uint8_t> q_bytes; bn_to_vec(q, q_bytes);

    auto fake_ct = [&](uint64_t m) {
        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* g  = BN_new(); BN_add(g, N, BN_value_one());
        BIGNUM* me = BN_new(); BN_set_word(me, m);
        BIGNUM* c  = BN_new(); BN_mod_exp(c, g, me, N2, ctx);
        std::vector<uint8_t> out; bn_to_vec(c, out);
        BN_free(N2); BN_free(g); BN_free(me); BN_free(c);
        return out;
    };
    auto partial = [&](const BIGNUM* s, const std::vector<uint8_t>& c_bytes) {
        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* c = BN_new(); BN_bin2bn(c_bytes.data(), (int)c_bytes.size(), c);
        BIGNUM* exp = BN_new(); BN_mul(exp, dao_dkg_delta(), s, ctx); BN_lshift(exp, exp, 1);
        BIGNUM* res = BN_new();
        if (BN_is_negative(exp)) {
            BIGNUM* inv = BN_mod_inverse(nullptr, c, N2, ctx);
            BIGNUM* pos = BN_dup(exp); BN_set_negative(pos, 0);
            BN_mod_exp(res, inv, pos, N2, ctx);
            BN_free(inv); BN_free(pos);
        } else BN_mod_exp(res, c, exp, N2, ctx);
        std::vector<uint8_t> out; bn_to_vec(res, out);
        BN_free(N2); BN_free(c); BN_free(exp); BN_free(res);
        return out;
    };
    auto combine = [&](const std::vector<uint32_t>& subset,
                       const std::vector<std::vector<uint8_t>>& partials) {
        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* C = BN_new(); BN_one(C);
        for (size_t k = 0; k < subset.size(); ++k) {
            BIGNUM* ci = BN_new(); BN_bin2bn(partials[k].data(), (int)partials[k].size(), ci);
            BIGNUM* mu = BN_new(); dao_dkg_lagrange_mu(subset, subset[k], mu);
            BIGNUM* exp = BN_new(); BN_lshift(exp, mu, 1);
            BIGNUM* term = BN_new();
            if (BN_is_negative(exp)) {
                BIGNUM* inv = BN_mod_inverse(nullptr, ci, N2, ctx);
                BIGNUM* pos = BN_dup(exp); BN_set_negative(pos, 0);
                BN_mod_exp(term, inv, pos, N2, ctx);
                BN_free(inv); BN_free(pos);
            } else BN_mod_exp(term, ci, exp, N2, ctx);
            BN_mod_mul(C, C, term, N2, ctx);
            BN_free(ci); BN_free(mu); BN_free(exp); BN_free(term);
        }
        std::vector<uint8_t> out; bn_to_vec(C, out);
        BN_free(N2); BN_free(C);
        return out;
    };

    std::vector<uint8_t> c_bytes = fake_ct(42);

    auto run_pair = [&](uint32_t n_old, uint32_t t_old,
                        uint32_t n_new, uint32_t t_new) {
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
        std::vector<uint32_t> old_subset;
        for (uint32_t i = 0; i < t_old; ++i) old_subset.push_back(i + 1);
        std::vector<std::vector<uint8_t>> old_partials(t_old);
        for (uint32_t i = 0; i < t_old; ++i) {
            BIGNUM* s = BN_new();
            BN_bin2bn(old_shares[i].data(), (int)old_shares[i].size(), s);
            old_partials[i] = partial(s, c_bytes);
            BN_free(s);
        }
        std::vector<uint8_t> C_old = combine(old_subset, old_partials);

        dao_dkg_reset_config cfg{};
        cfg.old_threshold = t_old; cfg.new_threshold = t_new;
        cfg.old_members.resize(n_old); cfg.new_members.resize(n_new);
        for (uint32_t _pid = 1; _pid <= t_old; ++_pid)
            cfg.reset_participant_ids.push_back(_pid);

        std::vector<std::vector<uint8_t>> participant_shares(
            old_shares.begin(), old_shares.begin() + t_old);
        std::vector<std::vector<uint8_t>> new_shares;
        ASSERT_TRUE(dao_dkg_reset_full_ceremony(cfg, participant_shares, q_bytes, new_shares));
        ASSERT_EQ(new_shares.size(), n_new);

        std::vector<uint32_t> new_subset;
        for (uint32_t i = 0; i < t_new; ++i) new_subset.push_back(i + 1);
        std::vector<std::vector<uint8_t>> new_partials(t_new);
        for (uint32_t i = 0; i < t_new; ++i) {
            BIGNUM* s = BN_new();
            BN_bin2bn(new_shares[i].data(), (int)new_shares[i].size(), s);
            new_partials[i] = partial(s, c_bytes);
            BN_free(s);
        }
        std::vector<uint8_t> C_new = combine(new_subset, new_partials);

        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        BIGNUM* co = BN_new(); BN_bin2bn(C_old.data(), (int)C_old.size(), co);
        BIGNUM* cn = BN_new(); BN_bin2bn(C_new.data(), (int)C_new.size(), cn);
        BIGNUM* d  = BN_new(); BN_mod_sub(d, co, cn, N2, ctx);
        EXPECT_TRUE(BN_is_zero(d)) << "combine mismatch " << n_old << "->" << n_new;
        BN_free(d); BN_free(co); BN_free(cn); BN_free(N2);
        for (auto* c : coeffs) BN_free(c);
    };

    run_pair(3,2,5,3); run_pair(5,3,3,2);
    run_pair(3,2,16,8); run_pair(16,8,3,2);
    run_pair(8,4,16,8); run_pair(16,8,8,4);

    BN_free(q); BN_free(nineteen); BN_free(N);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// Pedersen ceremony with link proof.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, pedersen_and_link_proof_resize)
{
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* N = BN_new();
    BN_set_bit(N, 127); BN_set_bit(N, 0); BN_set_bit(N, 63);
    BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);

    // V_K — arbitrary element mod N^2.
    BIGNUM* V_K = BN_new(); BN_set_word(V_K, 12345);

    int64_t SK[3] = {142, 242, 342};
    std::vector<std::vector<uint8_t>> old_shares(3);
    std::vector<std::vector<uint8_t>> VKi(3);
    for (int i = 0; i < 3; ++i) {
        make_signed_share(SK[i], old_shares[i]);
        BIGNUM* e = BN_new();
        BN_set_word(e, (BN_ULONG)SK[i]);
        BN_mul(e, e, dao_dkg_delta(), ctx);
        BIGNUM* r = BN_new();
        BN_mod_exp(r, V_K, e, N2, ctx);
        bn_to_pad512(r, VKi[i]);
        BN_free(e); BN_free(r);
    }

    dao_vss_group vss;
    tiny_vss(vss);

    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 2;
    cfg.new_threshold = 3;
    cfg.old_members.resize(3);
    cfg.new_members.resize(5);
    cfg.reset_participant_ids = {1, 2};
    for (size_t i = 0; i < sizeof(cfg.key_id.data); ++i) cfg.key_id.data[i] = (uint8_t)i;

    std::vector<dao_reset_public_contribution> publics(2);
    std::vector<std::vector<dao_reset_private_subshare>> priv_sets(2);
    for (uint32_t l = 1; l <= 2; ++l) {
        ASSERT_TRUE(dao_dkg_reset_generate_contribution(
            cfg, l, old_shares[l-1], vss, N2, V_K, VKi[l-1],
            publics[l-1], priv_sets[l-1]))
            << "generate failed for l=" << l;
    }

    std::vector<std::vector<uint8_t>> new_shares(5);
    for (uint32_t j = 1; j <= 5; ++j) {
        std::vector<dao_reset_private_subshare> mine;
        for (uint32_t l = 1; l <= 2; ++l) {
            for (const auto& ss : priv_sets[l-1]) {
                if (ss.to_new_member_id == j) mine.push_back(ss);
            }
        }
        ASSERT_TRUE(dao_dkg_reset_accept(
            cfg, j, publics, mine, vss, N2, V_K, VKi, new_shares[j-1]))
            << "accept failed for j=" << j;
    }

    // Reconstruct SK(0) from any 3 new shares.
    BIGNUM* acc = BN_new(); BN_zero(acc);
    std::vector<uint32_t> subset = {1,2,3};
    for (uint32_t i = 1; i <= 3; ++i) {
        BIGNUM* mu = BN_new();
        ASSERT_TRUE(dao_dkg_lagrange_mu(subset, i, mu));
        BIGNUM* si = BN_new();
        BN_bin2bn(new_shares[i-1].data() + 1,
                  (int)new_shares[i-1].size() - 1, si);
        if (new_shares[i-1][0]) BN_set_negative(si, 1);
        BIGNUM* t = BN_new();
        BN_mul(t, mu, si, ctx);
        BN_add(acc, acc, t);
        BN_free(t); BN_free(si); BN_free(mu);
    }
    BIGNUM* q = BN_new(); BIGNUM* r = BN_new();
    BN_div(q, r, acc, dao_dkg_delta(), ctx);
    ASSERT_TRUE(BN_is_zero(r));
    EXPECT_EQ(BN_get_word(q), 42u);

    BN_free(r); BN_free(q); BN_free(acc);
    BN_free(V_K); BN_free(N2); BN_free(N);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// Tampered subshare must fail verification.
// -------------------------------------------------------------------
TEST(dao_dkg_reset, tampered_subshare_rejected)
{
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* N = BN_new();
    BN_set_bit(N, 127); BN_set_bit(N, 0); BN_set_bit(N, 63);
    BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
    BIGNUM* V_K = BN_new(); BN_set_word(V_K, 12345);

    std::vector<uint8_t> old_share;
    make_signed_share(142, old_share);
    BIGNUM* e = BN_new(); BN_set_word(e, 142);
    BN_mul(e, e, dao_dkg_delta(), ctx);
    BIGNUM* VKi_bn = BN_new(); BN_mod_exp(VKi_bn, V_K, e, N2, ctx);
    std::vector<uint8_t> VKi; bn_to_pad512(VKi_bn, VKi);

    dao_vss_group vss; tiny_vss(vss);

    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 2; cfg.new_threshold = 3;
    cfg.old_members.resize(3); cfg.new_members.resize(5);
    cfg.reset_participant_ids = {1, 2};

    dao_reset_public_contribution pub;
    std::vector<dao_reset_private_subshare> priv;
    ASSERT_TRUE(dao_dkg_reset_generate_contribution(
        cfg, 1, old_share, vss, N2, V_K, VKi, pub, priv));
    ASSERT_GE(priv.size(), 2u);

    auto& ss = priv[1];
    ss.subshare.back() ^= 0x01;

    EXPECT_FALSE(dao_dkg_reset_verify_subshare(
        vss, 2, ss.subshare, ss.blinding, pub.coefficient_commitments));

    BN_free(VKi_bn); BN_free(e); BN_free(V_K); BN_free(N2); BN_free(N);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// Malicious-input tests for the Reset link proof and subshare layer.
// Each case tampers with one value and asserts rejection.
// -------------------------------------------------------------------
namespace {

struct ResetProofFixture
{
    dao_vss_group vss;
    BIGNUM* N   = nullptr;
    BIGNUM* N2  = nullptr;
    BIGNUM* V_K = nullptr;
    std::vector<uint8_t> old_share;
    std::vector<uint8_t> VKi;
    dao_dkg_reset_config cfg;
    dao_reset_public_contribution pub;
    std::vector<dao_reset_private_subshare> priv;
    BIGNUM* mu   = nullptr;
    std::vector<uint8_t> ctx_bytes;

    ResetProofFixture() {
        BN_CTX* ctx = BN_CTX_new();
        N   = BN_new(); BN_set_bit(N, 127); BN_set_bit(N, 0); BN_set_bit(N, 63);
        N2  = BN_new(); BN_sqr(N2, N, ctx);
        V_K = BN_new(); BN_set_word(V_K, 12345);

        make_signed_share(142, old_share);

        BIGNUM* e = BN_new(); BN_set_word(e, 142);
        BN_mul(e, e, dao_dkg_delta(), ctx);
        BIGNUM* r = BN_new(); BN_mod_exp(r, V_K, e, N2, ctx);
        bn_to_pad512(r, VKi);
        BN_free(e); BN_free(r);

        tiny_vss(vss);

        cfg.old_threshold = 2;
        cfg.new_threshold = 3;
        cfg.old_members.resize(3);
        cfg.new_members.resize(5);
        cfg.reset_participant_ids = {1, 2};
        for (size_t i = 0; i < sizeof(cfg.key_id.data); ++i)
            cfg.key_id.data[i] = (uint8_t)i;

        dao_dkg_reset_generate_contribution(cfg, 1, old_share, vss, N2, V_K,
                                            VKi, pub, priv);

        mu = BN_new();
        // The manifest for this fixture is {1, 2}; interpolation runs
        // over that set, matching the contribution that was generated.
        std::vector<uint32_t> ids = {1, 2};
        dao_dkg_lagrange_mu(ids, 1, mu);

        ctx_bytes.insert(ctx_bytes.end(), cfg.key_id.data, cfg.key_id.data + 32);
        for (int i = 0; i < 8; ++i) ctx_bytes.push_back((cfg.old_epoch >> (8*i)) & 0xff);
        for (int i = 0; i < 8; ++i) ctx_bytes.push_back((cfg.new_epoch >> (8*i)) & 0xff);

        BN_CTX_free(ctx);
    }

    ~ResetProofFixture() {
        BN_free(N); BN_free(N2); BN_free(V_K); BN_free(mu);
    }

    BIGNUM* C0() const {
        return BN_bin2bn(pub.coefficient_commitments[0].data(),
                         (int)pub.coefficient_commitments[0].size(), nullptr);
    }

    bool verify_with(const BIGNUM* mu_arg, const BIGNUM* C0_arg,
                     const std::vector<uint8_t>& vki_arg,
                     const dao_reset_share_link_proof& p) {
        return dao_dkg_reset_share_link_verify(
            vss, N2, V_K, vki_arg, mu_arg, C0_arg, ctx_bytes, p);
    }

    bool verify() { 
        BIGNUM* c = C0();
        bool r = verify_with(mu, c, VKi, pub.share_link_proof);
        BN_free(c);
        return r;
    }
};

} // namespace

TEST(dao_dkg_reset, link_proof_valid_baseline)
{
    ResetProofFixture fx;
    ASSERT_FALSE(fx.priv.empty());
    ASSERT_FALSE(fx.pub.coefficient_commitments.empty());
    EXPECT_TRUE(fx.verify());
}

TEST(dao_dkg_reset, link_proof_rejects_tampered_T_vss)
{
    ResetProofFixture fx;
    dao_reset_share_link_proof p = fx.pub.share_link_proof;
    ASSERT_FALSE(p.T_vss.empty());
    p.T_vss[0] ^= 0x01;
    BIGNUM* c = fx.C0();
    EXPECT_FALSE(fx.verify_with(fx.mu, c, fx.VKi, p));
    BN_free(c);
}

TEST(dao_dkg_reset, link_proof_rejects_tampered_T_paillier)
{
    ResetProofFixture fx;
    dao_reset_share_link_proof p = fx.pub.share_link_proof;
    ASSERT_FALSE(p.T_paillier.empty());
    p.T_paillier[0] ^= 0x01;
    BIGNUM* c = fx.C0();
    EXPECT_FALSE(fx.verify_with(fx.mu, c, fx.VKi, p));
    BN_free(c);
}

TEST(dao_dkg_reset, link_proof_rejects_tampered_z_share)
{
    ResetProofFixture fx;
    dao_reset_share_link_proof p = fx.pub.share_link_proof;
    ASSERT_GE(p.z_share.size(), 2u);
    p.z_share[1] ^= 0x01;
    BIGNUM* c = fx.C0();
    EXPECT_FALSE(fx.verify_with(fx.mu, c, fx.VKi, p));
    BN_free(c);
}

TEST(dao_dkg_reset, link_proof_rejects_tampered_z_blinding)
{
    ResetProofFixture fx;
    dao_reset_share_link_proof p = fx.pub.share_link_proof;
    ASSERT_GE(p.z_blinding.size(), 2u);
    p.z_blinding[1] ^= 0x01;
    BIGNUM* c = fx.C0();
    EXPECT_FALSE(fx.verify_with(fx.mu, c, fx.VKi, p));
    BN_free(c);
}

TEST(dao_dkg_reset, link_proof_rejects_wrong_VKi)
{
    ResetProofFixture fx;
    std::vector<uint8_t> wrong_vki = fx.VKi;
    ASSERT_FALSE(wrong_vki.empty());
    wrong_vki[0] ^= 0x01;
    BIGNUM* c = fx.C0();
    EXPECT_FALSE(fx.verify_with(fx.mu, c, wrong_vki, fx.pub.share_link_proof));
    BN_free(c);
}

TEST(dao_dkg_reset, link_proof_rejects_wrong_mu)
{
    ResetProofFixture fx;
    BIGNUM* wrong_mu = BN_new();
    BN_add(wrong_mu, fx.mu, BN_value_one());
    BIGNUM* c = fx.C0();
    EXPECT_FALSE(fx.verify_with(wrong_mu, c, fx.VKi, fx.pub.share_link_proof));
    BN_free(c); BN_free(wrong_mu);
}

TEST(dao_dkg_reset, link_proof_rejects_tampered_C0)
{
    ResetProofFixture fx;
    BIGNUM* c = fx.C0();
    ASSERT_NE(c, nullptr);
    BIGNUM* wrong_c = BN_new();
    BN_add(wrong_c, c, BN_value_one());
    EXPECT_FALSE(fx.verify_with(fx.mu, wrong_c, fx.VKi, fx.pub.share_link_proof));
    BN_free(c); BN_free(wrong_c);
}

TEST(dao_dkg_reset, subshare_rejects_tampered_blinding)
{
    ResetProofFixture fx;
    ASSERT_GE(fx.priv.size(), 2u);
    auto ss = fx.priv[1];
    ASSERT_FALSE(ss.blinding.empty());
    ss.blinding.back() ^= 0x01;
    EXPECT_FALSE(dao_dkg_reset_verify_subshare(
        fx.vss, 2, ss.subshare, ss.blinding, fx.pub.coefficient_commitments));
}

TEST(dao_dkg_reset, accept_rejects_missing_subshare)
{
    ResetProofFixture fx;
    // Pass no private subshares at all.
    std::vector<dao_reset_private_subshare> none;
    std::vector<uint8_t> new_share;
    EXPECT_FALSE(dao_dkg_reset_accept(
        fx.cfg, 1, {fx.pub}, none, fx.vss, fx.N2, fx.V_K, {fx.VKi},
        new_share));
}

TEST(dao_dkg_reset, accept_rejects_wrong_recipient_id)
{
    ResetProofFixture fx;
    // Subshares exist for recipients 1..5, but we ask as recipient 99.
    std::vector<uint8_t> new_share;
    EXPECT_FALSE(dao_dkg_reset_accept(
        fx.cfg, 99, {fx.pub}, fx.priv, fx.vss, fx.N2, fx.V_K, {fx.VKi},
        new_share));
}
