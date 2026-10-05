// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reset against a real DKG run.
//
//   bootstrap DKG (3 parties)
//       |
//       v
//   per-party SK_i (test accessor)
//       |
//       v
//   Reset 3 -> 5
//       |
//       v
//   new shares
//       |
//       v
//   integer Lagrange reconstruction of SK(0)
//       |
//       v
//   c^(2*Delta*SK) partials + combine on real N^2
//       |
//       v
//   old combine == new combine (mod N^2)

#include <cstdint>
#include <cstring>
#include <vector>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "gtest/gtest.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_reset.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_threshold.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

std::vector<crypto::public_key> test_member_ids(uint32_t n)
{
    std::vector<crypto::public_key> ids;
    ids.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        crypto::public_key pk{};
        for (int k = 0; k < 32; ++k)
            pk.data[k] = static_cast<uint8_t>((i + 1) * 17 + k);
        ids.push_back(pk);
    }
    return ids;
}

void bn_to_vec(const BIGNUM* x, std::vector<uint8_t>& out)
{
    int nb = BN_num_bytes(x);
    out.assign(nb, 0);
    BN_bn2bin(x, out.data());
}

void bn_to_signed_vec(const BIGNUM* x, std::vector<uint8_t>& out)
{
    if (!x) { out.clear(); return; }
    const int nb = BN_num_bytes(x);
    out.assign(1 + static_cast<size_t>(nb), 0);
    out[0] = BN_is_negative(x) ? 1 : 0;
    if (nb > 0) BN_bn2bin(x, out.data() + 1);
}

BIGNUM* signed_vec_to_bn(const std::vector<uint8_t>& v)
{
    if (v.empty()) return nullptr;
    BIGNUM* b = BN_bin2bn(v.data() + 1, (int)(v.size() - 1), nullptr);
    if (!b) return nullptr;
    if (v[0]) BN_set_negative(b, 1);
    return b;
}

bool decode_vss_group(const dao_tally_key_record& rec, dao_vss_group& grp)
{
    grp.P       = BN_bin2bn(rec.vss_P.data(),       (int)rec.vss_P.size(),       nullptr);
    grp.P_prime = BN_bin2bn(rec.vss_P_prime.data(), (int)rec.vss_P_prime.size(), nullptr);
    grp.g       = BN_bin2bn(rec.vss_g.data(),       (int)rec.vss_g.size(),       nullptr);
    grp.h       = BN_bin2bn(rec.vss_h.data(),       (int)rec.vss_h.size(),       nullptr);
    return grp.P && grp.P_prime && grp.g && grp.h;
}

// Integer Lagrange reconstruction: sum lambda_i * s_i where lambda_i is
// the rational Lagrange coefficient at 0, computed over the integers
// via a common denominator. Here we use the mu-scaled form and then
// divide by Delta, which is exact.
bool reconstruct_secret(
    const std::vector<uint32_t>& ids,
    const std::vector<BIGNUM*>& shares,
    BIGNUM* out, BN_CTX* ctx)
{
    BIGNUM* acc = BN_new();
    if (!acc) return false;
    BN_zero(acc);

    for (size_t k = 0; k < ids.size(); ++k) {
        BIGNUM* mu = BN_new();
        if (!mu || !dao_dkg_lagrange_mu(ids, ids[k], mu)) {
            BN_free(mu); BN_free(acc); return false;
        }
        BIGNUM* t = BN_new();
        if (!t || !BN_mul(t, mu, shares[k], ctx) ||
            !BN_add(acc, acc, t)) {
            BN_free(t); BN_free(mu); BN_free(acc); return false;
        }
        BN_free(t); BN_free(mu);
    }

    BIGNUM* rem = BN_new();
    BIGNUM* q = BN_new();
    if (!rem || !q) { BN_free(rem); BN_free(q); BN_free(acc); return false; }
    bool ok = BN_div(q, rem, acc, dao_dkg_delta(), ctx) == 1 &&
              BN_is_zero(rem);
    if (ok) BN_copy(out, q);
    BN_free(rem); BN_free(q); BN_free(acc);
    return ok;
}

} // namespace

TEST(dao_dkg_reset_integration, real_dkg_reset_and_combine)
{
    // ---- 1. Run a real 3-party DKG with 128-bit N (fast) ----
    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);   // 2
    cfg.member_ids     = test_member_ids(3);
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = 32;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;

    auto net = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    pool.reserve(net.endpoints.size());
    for (auto& e : net.endpoints) pool.push_back(std::move(e));

    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    dkg_result out;
    dkg_run_with_transport(cfg, factory, out);
    ASSERT_TRUE(out.candidate_accepted)
        << "DKG candidate not accepted in " << out.candidate_attempts
        << " attempts";
    ASSERT_EQ(out.test_SK.size(), 3u) << "test_SK not populated";

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    // ---- 2. Extract per-party SK_i (decimal strings, signed) ----
    std::vector<std::vector<uint8_t>> old_shares(3);
    for (int i = 0; i < 3; ++i) {
        std::string s(out.test_SK[i].begin(), out.test_SK[i].end());
        BIGNUM* b = nullptr;
        ASSERT_TRUE(BN_dec2bn(&b, s.c_str()) > 0);
        bn_to_signed_vec(b, old_shares[i]);
        BN_free(b);
    }

    // ---- 3. Extract the public material from the DKG record ----
    BIGNUM* N  = BN_bin2bn(out.N.data(), (int)out.N.size(), nullptr);
    ASSERT_NE(N, nullptr);
    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, ctx);
    ASSERT_EQ(BN_num_bits(N), 128);

    BIGNUM* V_K = BN_bin2bn(out.record.V.data(),
                            (int)out.record.V.size(), nullptr);
    ASSERT_NE(V_K, nullptr);

    std::vector<std::vector<uint8_t>> VKi(3);
    for (int i = 0; i < 3; ++i) VKi[i] = out.record.V_K_i[i];

    dao_vss_group vss;
    ASSERT_TRUE(decode_vss_group(out.record, vss));

    // ---- 4. Old secret via integer Lagrange ----
    std::vector<BIGNUM*> old_bns(3);
    for (int i = 0; i < 3; ++i) {
        old_bns[i] = signed_vec_to_bn(old_shares[i]);
        ASSERT_NE(old_bns[i], nullptr);
    }
    BIGNUM* S_old = BN_new();
    std::vector<uint32_t> old_ids = {1, 2, 3};
    ASSERT_TRUE(reconstruct_secret(old_ids, old_bns, S_old, ctx));

    // ---- 5. Reset 3 -> 5, threshold 3 ----
    dao_dkg_reset_config rcfg{};
    rcfg.old_threshold = 2;
    rcfg.new_threshold = 3;
    rcfg.old_members   = test_member_ids(3);
    rcfg.new_members   = test_member_ids(5);
    for (size_t i = 0; i < sizeof(rcfg.key_id.data); ++i)
        rcfg.key_id.data[i] = (uint8_t)i;

    std::vector<dao_reset_public_contribution> publics(3);
    std::vector<std::vector<dao_reset_private_subshare>> priv_sets(3);
    for (uint32_t l = 1; l <= 3; ++l) {
        ASSERT_TRUE(dao_dkg_reset_generate_contribution(
            rcfg, l, old_shares[l-1], vss, N2, V_K, VKi[l-1],
            publics[l-1], priv_sets[l-1]))
            << "generate failed for l=" << l;
    }

    std::vector<std::vector<uint8_t>> new_shares(5);
    for (uint32_t j = 1; j <= 5; ++j) {
        std::vector<dao_reset_private_subshare> mine;
        for (uint32_t l = 1; l <= 3; ++l) {
            for (const auto& ss : priv_sets[l-1]) {
                if (ss.to_new_member_id == j) mine.push_back(ss);
            }
        }
        ASSERT_TRUE(dao_dkg_reset_accept(
            rcfg, j, publics, mine, vss, N2, V_K, VKi, new_shares[j-1]))
            << "accept failed for j=" << j;
    }

    // ---- 6. New secret via integer Lagrange (any 3 of 5) ----
    std::vector<BIGNUM*> new_bns(3);
    for (int i = 0; i < 3; ++i) {
        new_bns[i] = signed_vec_to_bn(new_shares[i]);
        ASSERT_NE(new_bns[i], nullptr);
    }
    BIGNUM* S_new = BN_new();
    std::vector<uint32_t> new_subset = {1, 2, 3};
    ASSERT_TRUE(reconstruct_secret(new_subset, new_bns, S_new, ctx));

    EXPECT_EQ(BN_cmp(S_old, S_new), 0)
        << "Reset did not preserve SK(0)";

    // ---- 7. Ciphertext combine invariance on the real N^2 ----
    // c = (1+N)^m mod N^2 with m = 42.
    BIGNUM* g = BN_new(); BN_add(g, N, BN_value_one());
    BIGNUM* me = BN_new(); BN_set_word(me, 42);
    BIGNUM* c = BN_new(); BN_mod_exp(c, g, me, N2, ctx);
    std::vector<uint8_t> c_bytes; bn_to_vec(c, c_bytes);

    auto partial = [&](const BIGNUM* s) {
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
        std::vector<uint8_t> o; bn_to_vec(res, o);
        BN_free(exp); BN_free(res);
        return o;
    };

    auto combine = [&](const std::vector<uint32_t>& subset,
                       const std::vector<std::vector<uint8_t>>& partials) {
        BIGNUM* C = BN_new(); BN_one(C);
        for (size_t k = 0; k < subset.size(); ++k) {
            BIGNUM* ci = BN_new();
            BN_bin2bn(partials[k].data(), (int)partials[k].size(), ci);
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
        std::vector<uint8_t> o; bn_to_vec(C, o);
        BN_free(C);
        return o;
    };

    std::vector<std::vector<uint8_t>> old_partials(2);
    old_partials[0] = partial(old_bns[0]);
    old_partials[1] = partial(old_bns[1]);
    std::vector<uint8_t> C_old = combine({1, 2}, old_partials);

    std::vector<std::vector<uint8_t>> new_partials(3);
    for (int i = 0; i < 3; ++i) new_partials[i] = partial(new_bns[i]);
    std::vector<uint8_t> C_new = combine({1, 2, 3}, new_partials);

    BIGNUM* co = BN_new(); BN_bin2bn(C_old.data(), (int)C_old.size(), co);
    BIGNUM* cn = BN_new(); BN_bin2bn(C_new.data(), (int)C_new.size(), cn);
    BIGNUM* d  = BN_new(); BN_mod_sub(d, co, cn, N2, ctx);
    EXPECT_TRUE(BN_is_zero(d))
        << "real-DKG combine mismatch after Reset";

    // ---- cleanup ----
    for (auto* b : old_bns) BN_free(b);
    for (auto* b : new_bns) BN_free(b);
    BN_free(d); BN_free(co); BN_free(cn);
    BN_free(c); BN_free(me); BN_free(g);
    BN_free(S_old); BN_free(S_new);
    BN_free(V_K); BN_free(N2); BN_free(N);
    BN_CTX_free(ctx);
}
