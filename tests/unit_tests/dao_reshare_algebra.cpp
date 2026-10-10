// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DAO V2 resharing algebra regression test.
//
// Isolated arithmetic test: does the existing DKG share representation
// support redistribution to a new committee while preserving the
// underlying secret f(0)? This file does NOT implement or exercise
// the resharing P2P protocol or its proofs. It only establishes that
// the algebra works with real shares produced by the existing DKG
// harness.
//
// Identity under test:
//
//   sum_{i in S} mu_i * s_i = Delta * f(0),  mu_i = Delta * lambda_i(0)
//
// where s_i = N * F_1(i) - theta_tilde is the existing share and S is
// any threshold-sized subset of old shareholders.
//
// Resharing via q_i(x) = mu_i * s_i + Delta * r_i(x), r_i(0) = 0:
//
//   s'_j = (sum_i q_i(j)) / Delta = f(0) + sum_i r_i(j)
//
// preserves f(0). Partial decryption with the new shares must recover
// the same plaintext as partial decryption with the old shares.

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_paillier.h"
#include "governance/dao_threshold.h"
#include "crypto/crypto.h"

#include <openssl/bn.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

struct BNFree
{
    void operator()(BIGNUM* p) const { if (p) BN_free(p); }
};
using BN_ptr = std::unique_ptr<BIGNUM, BNFree>;

BN_ptr bn_from_dec(const std::string& s)
{
    BIGNUM* b = nullptr;
    if (BN_dec2bn(&b, s.c_str()) == 0)
    {
        if (b) BN_free(b);
        return BN_ptr();
    }
    return BN_ptr(b);
}

bool run_dkg_3(dkg_result& out)
{
    dao_vss_group vss;
    if (!dao_vss_group_generate(vss,
            dao_dkg_required_vss_bits(60, 128, 32)))
        return false;

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    pool.reserve(inet.endpoints.size());
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));

    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    std::vector<crypto::public_key> pks;
    for (int i = 0; i < 3; ++i)
    {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        pks.push_back(pk);
    }

    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);
    cfg.member_ids     = pks;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;

    return dkg_run_with_transport(cfg, factory, out);
}

} // namespace

TEST(DaoReshareAlgebra, SharesRedistributeWithoutChangingSecret)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);
    ASSERT_EQ(out.test_SK.size(), 3u);

    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    BN_ptr s2 = bn_from_dec(std::string(out.test_SK[1].begin(),
                                         out.test_SK[1].end()));
    BN_ptr s3 = bn_from_dec(std::string(out.test_SK[2].begin(),
                                         out.test_SK[2].end()));
    ASSERT_NE(s1, nullptr);
    ASSERT_NE(s2, nullptr);
    ASSERT_NE(s3, nullptr);

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    // Old threshold subset S = {1, 2}.
    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new());
    BN_ptr mu2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 2, mu2.get()));

    // sum = mu1*s1 + mu2*s2 = Delta * f(0).
    BN_ptr t1(BN_new());
    BN_ptr t2(BN_new());
    BN_ptr sum(BN_new());
    ASSERT_TRUE(BN_mul(t1.get(), mu1.get(), s1.get(), ctx));
    ASSERT_TRUE(BN_mul(t2.get(), mu2.get(), s2.get(), ctx));
    ASSERT_TRUE(BN_add(sum.get(), t1.get(), t2.get()));

    BN_ptr f0(BN_new());
    BN_ptr rem(BN_new());
    ASSERT_TRUE(BN_div(f0.get(), rem.get(), sum.get(),
                       dao_dkg_delta(), ctx));
    ASSERT_TRUE(BN_is_zero(rem.get()))
        << "old-share interpolation not divisible by Delta";

    // Resharing polynomials: r_i(x) = c_i * x, r_i(0) = 0.
    BN_ptr c1(BN_new());
    BN_ptr c2(BN_new());
    BN_set_word(c1.get(), 7);
    BN_set_word(c2.get(), 11);

    auto new_share = [&](uint32_t j) -> BN_ptr
    {
        BN_ptr jj(BN_new());
        BN_set_word(jj.get(), j);

        BN_ptr c1j(BN_new());
        BN_ptr c2j(BN_new());
        BN_mul(c1j.get(), c1.get(), jj.get(), ctx);
        BN_mul(c2j.get(), c2.get(), jj.get(), ctx);

        BN_ptr rj(BN_new());
        BN_add(rj.get(), c1j.get(), c2j.get());

        BN_ptr delta_rj(BN_new());
        BN_mul(delta_rj.get(), dao_dkg_delta(), rj.get(), ctx);

        BN_ptr num(BN_new());
        BN_add(num.get(), sum.get(), delta_rj.get());

        BN_ptr q(BN_new());
        BN_ptr r(BN_new());
        if (!BN_div(q.get(), r.get(), num.get(), dao_dkg_delta(), ctx))
            return BN_ptr();
        if (!BN_is_zero(r.get()))
            return BN_ptr();
        return q;
    };

    BN_ptr sp1 = new_share(1);
    BN_ptr sp2 = new_share(2);
    BN_ptr sp3 = new_share(3);
    ASSERT_NE(sp1, nullptr);
    ASSERT_NE(sp2, nullptr);
    ASSERT_NE(sp3, nullptr);

    // Reconstruct with S' = {1', 2'}.
    const std::vector<uint32_t> Sp = {1, 2};
    BN_ptr mup1(BN_new());
    BN_ptr mup2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(Sp, 1, mup1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(Sp, 2, mup2.get()));

    BN_ptr u1(BN_new());
    BN_ptr u2(BN_new());
    BN_mul(u1.get(), mup1.get(), sp1.get(), ctx);
    BN_mul(u2.get(), mup2.get(), sp2.get(), ctx);
    BN_ptr ssum(BN_new());
    BN_add(ssum.get(), u1.get(), u2.get());

    BN_ptr f0p(BN_new());
    BN_ptr remp(BN_new());
    ASSERT_TRUE(BN_div(f0p.get(), remp.get(), ssum.get(),
                       dao_dkg_delta(), ctx));
    ASSERT_TRUE(BN_is_zero(remp.get()));

    EXPECT_EQ(BN_cmp(f0.get(), f0p.get()), 0)
        << "f(0) not preserved after resharing";

    // Different subset S'' = {2', 3'} must yield the same f(0).
    const std::vector<uint32_t> Spp = {2, 3};
    BN_ptr mupp2(BN_new());
    BN_ptr mupp3(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(Spp, 2, mupp2.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(Spp, 3, mupp3.get()));

    BN_ptr v2(BN_new());
    BN_ptr v3(BN_new());
    BN_mul(v2.get(), mupp2.get(), sp2.get(), ctx);
    BN_mul(v3.get(), mupp3.get(), sp3.get(), ctx);
    BN_ptr vsum(BN_new());
    BN_add(vsum.get(), v2.get(), v3.get());

    BN_ptr f0pp(BN_new());
    BN_ptr rem2(BN_new());
    ASSERT_TRUE(BN_div(f0pp.get(), rem2.get(), vsum.get(),
                       dao_dkg_delta(), ctx));
    ASSERT_TRUE(BN_is_zero(rem2.get()));

    EXPECT_EQ(BN_cmp(f0.get(), f0pp.get()), 0)
        << "different subset yields a different f(0)";

    BN_CTX_free(ctx);
}

// ---------------------------------------------------------------------
// Real resharing uses NEW member indices (all distinct from the old
// committee) and the new share polynomial must have the degree required
// by the new threshold. This test builds new shares at indices 4, 5, 6
// from two old contributors (indices 1, 2) and verifies every 2-of-3
// subset of the new set reconstructs the same f(0).
// ---------------------------------------------------------------------
TEST(DaoReshareAlgebra, NewIndicesPreserveSecret)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    std::vector<BN_ptr> old_shares;
    for (int i = 0; i < 3; ++i) {
        old_shares.push_back(bn_from_dec(
            std::string(out.test_SK[i].begin(), out.test_SK[i].end())));
        ASSERT_NE(old_shares[i], nullptr);
    }

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new()), mu2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 2, mu2.get()));

    BN_ptr t1(BN_new()), t2(BN_new()), base(BN_new());
    BN_mul(t1.get(), mu1.get(), old_shares[0].get(), ctx);
    BN_mul(t2.get(), mu2.get(), old_shares[1].get(), ctx);
    BN_add(base.get(), t1.get(), t2.get());   // = Delta * f(0)

    BN_ptr f0(BN_new()), rem0(BN_new());
    BN_div(f0.get(), rem0.get(), base.get(), dao_dkg_delta(), ctx);
    ASSERT_TRUE(BN_is_zero(rem0.get()));

    BN_ptr c1(BN_new()), c2(BN_new());
    BN_set_word(c1.get(), 13);
    BN_set_word(c2.get(), 29);

    auto new_share = [&](uint32_t j) -> BN_ptr
    {
        BN_ptr jj(BN_new());
        BN_set_word(jj.get(), j);
        BN_ptr s1j(BN_new()), s2j(BN_new());
        BN_mul(s1j.get(), c1.get(), jj.get(), ctx);
        BN_mul(s2j.get(), c2.get(), jj.get(), ctx);
        BN_ptr rj(BN_new());
        BN_add(rj.get(), s1j.get(), s2j.get());
        BN_ptr drj(BN_new());
        BN_mul(drj.get(), dao_dkg_delta(), rj.get(), ctx);
        BN_ptr num(BN_new());
        BN_add(num.get(), base.get(), drj.get());
        BN_ptr q(BN_new()), rr(BN_new());
        if (!BN_div(q.get(), rr.get(), num.get(), dao_dkg_delta(), ctx))
            return BN_ptr();
        if (!BN_is_zero(rr.get()))
            return BN_ptr();
        return q;
    };

    BN_ptr sp4 = new_share(4);
    BN_ptr sp5 = new_share(5);
    BN_ptr sp6 = new_share(6);
    ASSERT_NE(sp4, nullptr);
    ASSERT_NE(sp5, nullptr);
    ASSERT_NE(sp6, nullptr);

    std::map<uint32_t, BIGNUM*> share_map = {
        {4, sp4.get()}, {5, sp5.get()}, {6, sp6.get()}
    };

    for (auto [a, b] : { std::pair<uint32_t,uint32_t>{4,5},
                          std::pair<uint32_t,uint32_t>{4,6},
                          std::pair<uint32_t,uint32_t>{5,6} })
    {
        std::vector<uint32_t> sub = {a, b};
        BN_ptr mua(BN_new()), mub(BN_new());
        ASSERT_TRUE(dao_dkg_lagrange_mu(sub, a, mua.get()));
        ASSERT_TRUE(dao_dkg_lagrange_mu(sub, b, mub.get()));

        BN_ptr ta(BN_new()), tb(BN_new()), ss(BN_new());
        BN_mul(ta.get(), mua.get(), share_map[a], ctx);
        BN_mul(tb.get(), mub.get(), share_map[b], ctx);
        BN_add(ss.get(), ta.get(), tb.get());

        BN_ptr f0p(BN_new()), rr(BN_new());
        BN_div(f0p.get(), rr.get(), ss.get(), dao_dkg_delta(), ctx);
        ASSERT_TRUE(BN_is_zero(rr.get()))
            << "subset {" << a << "," << b << "} not exactly divisible";
        EXPECT_EQ(BN_cmp(f0.get(), f0p.get()), 0)
            << "subset {" << a << "," << b << "} recovered a different f(0)";
    }

    BN_CTX_free(ctx);
}

// ---------------------------------------------------------------------
// Partial decryption round trip. Encrypt a value, produce partial
// decryptions with old shares at old indices, combine; do the same with
// new shares at new indices, combine. The combined ciphertexts must be
// byte-identical because both are c^(4 * Delta^2 * f(0)) for the same
// c and the same f(0).
// ---------------------------------------------------------------------
TEST(DaoReshareAlgebra, PartialDecryptionMatchesBeforeAndAfterReshare)
{
    using namespace cryptonote;

    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    BIGNUM* m = BN_new();
    BIGNUM* r = BN_new();
    ASSERT_NE(m, nullptr);
    ASSERT_NE(r, nullptr);
    BN_set_word(m, 12345);
    BN_set_word(r, 67890);

    std::vector<uint8_t> c;
    ASSERT_TRUE(pk.encrypt(m, r, c));

    std::vector<BN_ptr> old_shares;
    for (int i = 0; i < 3; ++i) {
        old_shares.push_back(bn_from_dec(
            std::string(out.test_SK[i].begin(), out.test_SK[i].end())));
        ASSERT_NE(old_shares[i], nullptr);
    }

    // Old path: partials with shares 1, 2; combine on subset {1, 2}.
    std::vector<std::vector<uint8_t>> old_partials;
    for (uint32_t i : {1u, 2u}) {
        std::vector<uint8_t> pi;
        ASSERT_TRUE(dao_threshold_partial_decrypt(
            pk, c, old_shares[i - 1].get(), pi));
        old_partials.push_back(std::move(pi));
    }
    std::vector<uint8_t> C_old;
    ASSERT_TRUE(dao_threshold_combine(pk, {1u, 2u}, old_partials, 2, C_old));

    // New path: redistribute to indices 4, 5, 6; combine on {4, 5}.
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BN_ptr mu1(BN_new()), mu2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu({1u, 2u}, 1, mu1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu({1u, 2u}, 2, mu2.get()));

    BN_ptr t1(BN_new()), t2(BN_new()), base(BN_new());
    BN_mul(t1.get(), mu1.get(), old_shares[0].get(), ctx);
    BN_mul(t2.get(), mu2.get(), old_shares[1].get(), ctx);
    BN_add(base.get(), t1.get(), t2.get());

    BN_ptr c1(BN_new()), c2(BN_new());
    BN_set_word(c1.get(), 3);
    BN_set_word(c2.get(), 5);

    auto new_share = [&](uint32_t j) -> BN_ptr
    {
        BN_ptr jj(BN_new());
        BN_set_word(jj.get(), j);
        BN_ptr s1j(BN_new()), s2j(BN_new());
        BN_mul(s1j.get(), c1.get(), jj.get(), ctx);
        BN_mul(s2j.get(), c2.get(), jj.get(), ctx);
        BN_ptr rj(BN_new());
        BN_add(rj.get(), s1j.get(), s2j.get());
        BN_ptr drj(BN_new());
        BN_mul(drj.get(), dao_dkg_delta(), rj.get(), ctx);
        BN_ptr num(BN_new());
        BN_add(num.get(), base.get(), drj.get());
        BN_ptr q(BN_new()), rr(BN_new());
        if (!BN_div(q.get(), rr.get(), num.get(), dao_dkg_delta(), ctx))
            return BN_ptr();
        if (!BN_is_zero(rr.get()))
            return BN_ptr();
        return q;
    };

    BN_ptr sp4 = new_share(4);
    BN_ptr sp5 = new_share(5);
    BN_ptr sp6 = new_share(6);
    ASSERT_NE(sp4, nullptr);
    ASSERT_NE(sp5, nullptr);
    ASSERT_NE(sp6, nullptr);

    std::vector<std::vector<uint8_t>> new_partials;
    {
        std::vector<uint8_t> p4, p5;
        ASSERT_TRUE(dao_threshold_partial_decrypt(pk, c, sp4.get(), p4));
        ASSERT_TRUE(dao_threshold_partial_decrypt(pk, c, sp5.get(), p5));
        new_partials.push_back(std::move(p4));
        new_partials.push_back(std::move(p5));
    }
    std::vector<uint8_t> C_new;
    ASSERT_TRUE(dao_threshold_combine(
        pk, {4u, 5u}, new_partials, 2, C_new));

    EXPECT_EQ(C_old, C_new)
        << "combined ciphertexts differ: resharing did not preserve the secret";

    BN_free(m);
    BN_free(r);
    BN_CTX_free(ctx);
}
