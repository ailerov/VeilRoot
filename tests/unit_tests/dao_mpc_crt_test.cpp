#include "gtest/gtest.h"
#include <openssl/bn.h>
#include <cstdlib>
#include "governance/dao_dkg.h"
#include "governance/dao_mpc.h"
#include "governance/dao_mpc_crt.h"

using namespace cryptonote::dao;

TEST(dao_mpc_crt, primes_small) {
    std::vector<uint32_t> p;
    ASSERT_TRUE(dao_mpc_crt::sieved_primes(20, p));
    std::vector<uint32_t> expected = {3, 5, 7, 11, 13, 17, 19};
    EXPECT_EQ(p, expected);

    std::vector<uint32_t> p2;
    ASSERT_TRUE(dao_mpc_crt::sieved_primes(5, p2));
    std::vector<uint32_t> exp2 = {3};
    EXPECT_EQ(p2, exp2);

    std::vector<uint32_t> p3;
    ASSERT_TRUE(dao_mpc_crt::sieved_primes(3, p3));
    EXPECT_TRUE(p3.empty());
}

TEST(dao_mpc_crt, sieve_product_ok) {
    std::vector<uint32_t> primes = {3, 5, 7};
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);
    BIGNUM* Q = BN_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_product(primes, Q, ctx));
    EXPECT_EQ(BN_get_word(Q), 105UL);
    BN_free(Q);
    BN_CTX_free(ctx);
}

TEST(dao_mpc_crt, crt_simple) {
    std::vector<uint32_t> primes = {3, 5, 7};
    std::vector<std::vector<uint32_t>> shares = {{2, 4, 6}};
    std::vector<BIGNUM*> out;
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(dao_mpc_crt::crt_reconstruct(primes, shares, out, ctx));
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(BN_get_word(out[0]), 104UL);
    for (auto* u : out) BN_free(u);
    BN_CTX_free(ctx);
}

TEST(dao_mpc_crt, sample_nonzero) {
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::sieved_primes(20, primes));
    std::vector<std::vector<uint32_t>> r;
    ASSERT_TRUE(dao_mpc_crt::sample_party_residues(primes, 3, r));
    ASSERT_EQ(r.size(), 3u);
    for (const auto& party : r) {
        ASSERT_EQ(party.size(), primes.size());
        for (size_t i = 0; i < primes.size(); ++i) {
            EXPECT_GT(party[i], 0u);
            EXPECT_LT(party[i], primes[i]);
        }
    }
}

TEST(dao_mpc_crt, lift_to_range_mod4_and_bits) {
    // Q = 105, U = 7. Lift to 16 bits with mod-4 residue 3.
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);
    BIGNUM* Q = BN_new(); BN_set_word(Q, 105);
    BIGNUM* U = BN_new(); BN_set_word(U, 7);
    BIGNUM* out = BN_new();
    ASSERT_TRUE(dao_mpc_crt::lift_to_range(U, Q, 16, 3, out, ctx));
    uint64_t v = BN_get_word(out);
    EXPECT_EQ(v % 4, 3UL);
    EXPECT_GE(v, (uint64_t)1 << 15);
    EXPECT_LT(v, (uint64_t)1 << 16);
    EXPECT_EQ(v % 105, 7UL);
    BN_free(Q); BN_free(U); BN_free(out);
    BN_CTX_free(ctx);
}

TEST(dao_mpc_crt, sieve_end_to_end_local) {
    std::vector<uint32_t> primes = {3, 5, 7};
    const uint32_t n = 3, t = 1;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);

    std::vector<std::vector<uint32_t>> us(primes.size(),
        std::vector<uint32_t>(n, 0));
    for (size_t j = 0; j < primes.size(); ++j) {
        BIGNUM* mod = BN_new(); BN_set_word(mod, primes[j]);
        for (uint32_t i = 0; i < n; ++i) {
            BIGNUM* tmp = BN_new();
            uint32_t u = 0;
            for (int tries = 0; tries < 32 && u == 0; ++tries) {
                ASSERT_TRUE(BN_rand_range(tmp, mod));
                u = (uint32_t)BN_get_word(tmp);
            }
            ASSERT_GT(u, 0u);
            us[j][i] = u;
            BN_free(tmp);
        }
        BN_free(mod);
    }

    std::vector<std::vector<uint32_t>> shares_per_party(n,
        std::vector<uint32_t>(primes.size(), 0));

    for (size_t j = 0; j < primes.size(); ++j) {
        uint32_t r = primes[j];
        dao_mpc_field f; f.r = r;

        std::vector<std::vector<BIGNUM*>> shares(n);
        std::vector<std::vector<BIGNUM*>> blinds(n);
        std::vector<dao_vss_commitments> commits(n);
        for (uint32_t i = 0; i < n; ++i) {
            ASSERT_TRUE(dao_mpc_vss::deal(f, grp, us[j][i], n, t,
                                          commits[i], shares[i], blinds[i], ctx));
        }

        std::vector<const BIGNUM*> sa(n), sb(n);
        for (uint32_t i = 0; i < n; ++i) { sa[i] = shares[0][i]; sb[i] = shares[1][i]; }
        std::vector<BIGNUM*> ab;
        ASSERT_TRUE(dao_mpc_mul::multiply(f, grp, n, t, sa, sb, ab, ctx));
        ASSERT_EQ(ab.size(), (size_t)n);

        std::vector<const BIGNUM*> sab(n), sc(n);
        for (uint32_t i = 0; i < n; ++i) { sab[i] = ab[i]; sc[i] = shares[2][i]; }
        std::vector<BIGNUM*> abc;
        ASSERT_TRUE(dao_mpc_mul::multiply(f, grp, n, t, sab, sc, abc, ctx));
        ASSERT_EQ(abc.size(), (size_t)n);

        for (uint32_t i = 0; i < n; ++i)
            shares_per_party[i][j] = (uint32_t)BN_mod_word(abc[i], r);

        for (auto* x : shares[0]) BN_free(x);
        for (auto* x : shares[1]) BN_free(x);
        for (auto* x : shares[2]) BN_free(x);
        for (auto* x : blinds[0]) BN_free(x);
        for (auto* x : blinds[1]) BN_free(x);
        for (auto* x : blinds[2]) BN_free(x);
        for (auto* x : ab) BN_free(x);
        for (auto* x : abc) BN_free(x);
    }

    // For each prime: Lagrange-reconstruct the degree-t sharing of
    // (u_0 * u_1 * u_2) over parties 1..t+1. Verify nonzero and equal
    // to the direct product of the party-secrets. Then CRT-reconstruct
    // the product vector into a single integer V and verify V is
    // coprime to every sieved prime.
    std::vector<uint32_t> prod_res(primes.size(), 0);
    for (size_t j = 0; j < primes.size(); ++j) {
        dao_mpc_field fj; fj.r = primes[j];
        std::vector<BIGNUM*> sbn(t + 1, nullptr);
        std::vector<const BIGNUM*> sv(t + 1, nullptr);
        std::vector<uint32_t> idx(t + 1);
        for (uint32_t i = 0; i <= t; ++i) {
            sbn[i] = BN_new();
            ASSERT_TRUE(sbn[i] != nullptr);
            BN_set_word(sbn[i], shares_per_party[i][j]);
            sv[i] = sbn[i];
            idx[i] = i + 1;
        }
        uint32_t rec = 0;
        ASSERT_TRUE(dao_mpc_vss::reconstruct(fj, sv, idx, t, rec, ctx));
        prod_res[j] = rec;

        uint64_t expected = 1;
        for (uint32_t a = 0; a < n; ++a)
            expected = (expected * us[j][a]) % primes[j];
        EXPECT_NE(prod_res[j], 0u) << "prime " << primes[j];
        EXPECT_EQ(prod_res[j], (uint32_t)expected) << "prime " << primes[j];

        for (auto* b : sbn) BN_free(b);
    }

    std::vector<std::vector<uint32_t>> one_vec = { prod_res };
    std::vector<BIGNUM*> V_bn;
    ASSERT_TRUE(dao_mpc_crt::crt_reconstruct(primes, one_vec, V_bn, ctx));
    ASSERT_EQ(V_bn.size(), 1u);
    for (size_t j = 0; j < primes.size(); ++j) {
        EXPECT_NE(BN_mod_word(V_bn[0], primes[j]), 0UL)
            << "V divisible by " << primes[j];
    }
    for (auto* v : V_bn) BN_free(v);

    BN_CTX_free(ctx);
}
