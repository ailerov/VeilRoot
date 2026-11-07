// Eratosthenes / Chen construction scaffolding tests.
// These verify infrastructure pieces that are NOT yet the full
// production protocol. Passing here is necessary, not sufficient.
// Production gate is one complete candidate through the full path.

#include "gtest/gtest.h"
#include <chrono>
#include <openssl/bn.h>
#include <vector>

#include "governance/dao_dkg.h"
#include "governance/dao_mpc.h"
#include "governance/dao_mpc_crt.h"

using namespace cryptonote::dao;

TEST(dao_mpc_eratosthenes, near_primorial_kappa1024_n3)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 3, primes));
    std::cout << "n=3: |primes|=" << primes.size()
              << " max=" << (primes.empty() ? 0 : primes.back()) << "\n";
    EXPECT_GT(primes.size(), 100u);
    EXPECT_LT(primes.size(), 200u);
    // Published: max prime 739, count ~130. Allow slack for the
    // exact log2(n) floor convention.
    EXPECT_LE(primes.back(), 1000u);
    BIGNUM* Q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_product(primes, Q, ctx));
    std::cout << "n=3: log2(Q)~" << BN_num_bits(Q) << "\n";
    BN_free(Q); BN_CTX_free(ctx);
}

TEST(dao_mpc_eratosthenes, near_primorial_kappa1024_n16)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 16, primes));
    std::cout << "n=16: |primes|=" << primes.size()
              << " min=" << (primes.empty() ? 0 : primes.front())
              << " max=" << (primes.empty() ? 0 : primes.back()) << "\n";
    // n=16, t=7, 2t+1=15. Primes <= 15 (3,5,7,11,13) are excluded
    // for Lagrange reasons; prime set starts at 17. The exact count
    // depends on how many fit under the bit budget. Coprimality to
    // the excluded primes is enforced by the runner-side gcd check,
    // not by the sieve.
    EXPECT_FALSE(primes.empty());
    EXPECT_GE(primes.front(), 17u);
    EXPECT_GT(primes.size(), 100u);
    EXPECT_LE(primes.back(), 1000u);
}

TEST(dao_mpc_eratosthenes, multiply_tree_depth_4_and_correct)
{
    dao_mpc_field f; f.r = 1000003;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);

    const uint32_t n = 4, t = 1;
    const uint32_t secrets[4] = {3, 5, 7, 11};

    std::vector<std::vector<const BIGNUM*>> operands(4);
    std::vector<std::vector<BIGNUM*>> all_sa(4), all_ba(4);
    for (uint32_t k = 0; k < 4; ++k) {
        dao_vss_commitments c;
        std::vector<BIGNUM*> sh, bl;
        ASSERT_TRUE(dao_mpc_vss::deal(f, grp, secrets[k], n, t, c, sh, bl, ctx));
        std::vector<const BIGNUM*> op(sh.begin(), sh.end());
        operands[k] = op;
        all_sa[k] = std::move(sh);
        all_ba[k] = std::move(bl);
    }

    std::vector<BIGNUM*> out;
    ASSERT_TRUE(dao_mpc_mul::multiply_tree(f, grp, n, t, operands, out, ctx));
    ASSERT_EQ(out.size(), (size_t)n);

    std::vector<const BIGNUM*> rec = {out[0], out[1]};
    std::vector<uint32_t> idx = {1, 2};
    uint32_t got = 0;
    ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec, idx, t, got, ctx));
    EXPECT_EQ(got, (3u * 5u * 7u * 11u) % f.r);

    for (auto& v : all_sa) for (auto* x : v) BN_free(x);
    for (auto& v : all_ba) for (auto* x : v) BN_free(x);
    for (auto* x : out) BN_free(x);
    BN_CTX_free(ctx);
}

TEST(dao_mpc_eratosthenes, multiply_tree_matches_sequential_n4)
{
    dao_mpc_field f; f.r = 1000003;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);
    const uint32_t n = 4, t = 1;
    const uint32_t secrets[4] = {3, 5, 7, 11};

    std::vector<std::vector<const BIGNUM*>> operands(4);
    std::vector<std::vector<BIGNUM*>> keep(4);
    for (uint32_t k = 0; k < 4; ++k) {
        dao_vss_commitments c;
        std::vector<BIGNUM*> sh, bl;
        ASSERT_TRUE(dao_mpc_vss::deal(f, grp, secrets[k], n, t, c, sh, bl, ctx));
        std::vector<const BIGNUM*> op(sh.begin(), sh.end());
        operands[k] = op;
        keep[k] = std::move(sh);
        for (auto* x : bl) BN_free(x);
    }

    std::vector<BIGNUM*> tree_out;
    ASSERT_TRUE(dao_mpc_mul::multiply_tree(f, grp, n, t, operands, tree_out, ctx));

    // Sequential comparison: (((s0*s1)*s2)*s3)
    std::vector<BIGNUM*> cur;
    ASSERT_TRUE(dao_mpc_mul::multiply(f, grp, n, t, operands[0], operands[1], cur, ctx));
    for (uint32_t k = 2; k < 4; ++k) {
        std::vector<const BIGNUM*> a(cur.begin(), cur.end());
        std::vector<BIGNUM*> next;
        ASSERT_TRUE(dao_mpc_mul::multiply(f, grp, n, t, a, operands[k], next, ctx));
        for (auto* x : cur) BN_free(x);
        cur = std::move(next);
    }

    std::vector<const BIGNUM*> rt = {tree_out[0], tree_out[1]};
    std::vector<const BIGNUM*> rs = {cur[0], cur[1]};
    std::vector<uint32_t> idx = {1, 2};
    uint32_t vt = 0, vs = 0;
    ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rt, idx, t, vt, ctx));
    ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rs, idx, t, vs, ctx));
    EXPECT_EQ(vt, vs);

    for (auto& v : keep) for (auto* x : v) BN_free(x);
    for (auto* x : tree_out) BN_free(x);
    for (auto* x : cur) BN_free(x);
    BN_CTX_free(ctx);
}

// ================================================================
// Expert-specified tests: uniform lift (Q1) + pairwise masks (Q3).
// ================================================================

namespace {

void print_pq_bounds(const char* tag, uint32_t n,
                     const std::vector<uint32_t>& primes, BN_CTX* ctx)
{
    BIGNUM* M0 = BN_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_modulus_mod4(primes, M0, ctx));
    std::cout << tag << ": n=" << n
              << " |primes|=" << primes.size()
              << " log2(M0)=" << BN_num_bits(M0) << "\n";
    BN_free(M0);
}

} // namespace

TEST(dao_mpc_eratosthenes, lift_bounds_n3)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 3, primes));
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);

    BIGNUM* M0 = BN_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_modulus_mod4(primes, M0, ctx));
    print_pq_bounds("lift_bounds", 3, primes, ctx);

    const uint32_t lambda = 1024, sigma = 80;
    BIGNUM* L = BN_new(); BIGNUM* U = BN_new();
    BN_one(L); BN_lshift(L, L, lambda);
    BIGNUM* n_bn = BN_new(); BN_set_word(n_bn, 3);
    BIGNUM* rem = BN_new();
    BN_div(L, rem, L, n_bn, ctx);
    if (!BN_is_zero(rem)) BN_add_word(L, 1);  // ceil

    BN_one(U); BN_lshift(U, U, lambda + sigma);
    BN_div(U, rem, U, n_bn, ctx);
    if (!BN_is_zero(rem)) BN_add_word(U, 1);

    std::cout << "n=3: log2(L)=" << BN_num_bits(L)
              << " log2(U)=" << BN_num_bits(U) << "\n";
    EXPECT_GT(BN_cmp(U, L), 0);
    EXPECT_GT(BN_cmp(L, M0), 0) << "L must exceed M_0";

    // Run 10 samples of the lift, check range and residue preservation.
    std::vector<std::vector<uint32_t>> shares(3, std::vector<uint32_t>(primes.size()));
    BIGNUM* rmod = BN_new();
    for (size_t j = 0; j < primes.size(); ++j) {
        BN_set_word(rmod, primes[j]);
        for (uint32_t i = 0; i < 3; ++i) {
            BIGNUM* tmp = BN_new();
            BN_rand_range(tmp, rmod);
            shares[i][j] = (uint32_t)BN_get_word(tmp);
            BN_free(tmp);
        }
    }
    BN_free(rmod); BN_free(n_bn); BN_free(rem);

    for (int trial = 0; trial < 10; ++trial) {
        std::vector<BIGNUM*> W;
        ASSERT_TRUE(dao_mpc_crt::crt_reconstruct_with_mod4(primes, shares, W, ctx));
        ASSERT_EQ(W.size(), 3u);
        std::vector<BIGNUM*> P;
        ASSERT_TRUE(dao_mpc_crt::reconstruct_all_to_contributions(
            W, M0, lambda, sigma, P, ctx));
        ASSERT_EQ(P.size(), 3u);

        // Each party's p_i ∈ [L, U).
        for (uint32_t i = 0; i < 3; ++i) {
            EXPECT_GE(BN_cmp(P[i], L), 0);
            EXPECT_LT(BN_cmp(P[i], U), 0);
        }
        // Aggregate P ∈ [2^1024, 2^1104).
        BIGNUM* agg = BN_new();
        BN_zero(agg);
        for (auto* p : P) BN_add(agg, agg, p);
        BIGNUM* lam_lb = BN_new(); BN_one(lam_lb); BN_lshift(lam_lb, lam_lb, 1024);
        BIGNUM* lam_ub = BN_new(); BN_one(lam_ub); BN_lshift(lam_ub, lam_ub, 1104);
        EXPECT_GE(BN_cmp(agg, lam_lb), 0);
        EXPECT_LT(BN_cmp(agg, lam_ub), 0);
        // Aggregate mod r == sum of residue shares mod r.
        for (size_t j = 0; j < primes.size(); ++j) {
            uint64_t expected = 0;
            for (uint32_t i = 0; i < 3; ++i)
                expected = (expected + shares[i][j]) % primes[j];
            uint64_t got = (uint64_t)BN_mod_word(agg, primes[j]);
            EXPECT_EQ(got, expected) << "prime " << primes[j];
        }
        // Aggregate mod 4 == 3 (party 1's 3 + others' 0).
        EXPECT_EQ(BN_mod_word(agg, 4), 3UL);

        BN_free(agg); BN_free(lam_lb); BN_free(lam_ub);
        for (auto* x : W) BN_free(x);
        for (auto* x : P) BN_free(x);
    }

    BN_free(L); BN_free(U); BN_free(M0); BN_CTX_free(ctx);
}

TEST(dao_mpc_eratosthenes, lift_bounds_n16)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 16, primes));
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    BIGNUM* M0 = BN_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_modulus_mod4(primes, M0, ctx));
    print_pq_bounds("lift_bounds", 16, primes, ctx);
    EXPECT_GT(primes.size(), 100u);
    // M0 must be smaller than L = 2^1020 for n=16.
    BIGNUM* L = BN_new(); BN_one(L); BN_lshift(L, L, 1020);
    EXPECT_LT(BN_cmp(M0, L), 0);
    BN_free(L); BN_free(M0); BN_CTX_free(ctx);
}

TEST(dao_mpc_eratosthenes, mask_uniformity_n3)
{
    // Expert test 1: for each corrupt party and each fixed corrupt
    // output, honest outputs are uniform over the fixed-sum line.
    dao_mpc_field f; f.r = 7;
    const uint32_t n = 3;

    // Arbitrary baseline shares summing to x mod 7.
    std::vector<uint32_t> b = {2, 3, 4};  // sum = 9 ≡ 2
    const uint32_t x = f.add(f.add(b[0], b[1]), b[2]);
    EXPECT_EQ(x, 2u);

    // Case: corrupt party 1. Corrupt controls rho_12, rho_13.
    // a_1 = b_1 + rho_12 + rho_13, fixed to v.
    for (uint32_t v = 0; v < f.r; ++v) {
        std::set<std::pair<uint32_t,uint32_t>> seen;
        for (uint32_t rho_23 = 0; rho_23 < f.r; ++rho_23) {
            // Pick rho_12 arbitrary, then rho_13 = v - b_1 - rho_12.
            uint32_t rho_12 = 1;
            uint32_t rho_13 = f.sub(f.sub(v, b[0]), rho_12);

            uint32_t a_1 = f.add(f.add(b[0], rho_12), rho_13);
            uint32_t a_2 = f.add(f.sub(b[1], rho_12), rho_23);
            uint32_t a_3 = f.sub(f.sub(b[2], rho_13), rho_23);

            EXPECT_EQ(a_1, v);
            EXPECT_EQ(f.add(f.add(a_1, a_2), a_3), x);

            auto pr = std::make_pair(a_2, a_3);
            EXPECT_TRUE(seen.insert(pr).second) << "non-uniform at v=" << v;
        }
        EXPECT_EQ(seen.size(), (size_t)f.r);
    }
}

TEST(dao_mpc_eratosthenes, mask_sum_invariant)
{
    dao_mpc_field f; f.r = 1000003;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t n = 4, t = 1;
    const uint32_t secret = 12345;

    dao_vss_commitments c;
    std::vector<BIGNUM*> sh, bl;
    ASSERT_TRUE(dao_mpc_vss::deal(f, grp, secret, n, t, c, sh, bl, ctx));
    std::vector<const BIGNUM*> sh_const(sh.begin(), sh.end());

    std::vector<dao_pair_mask> masks;
    ASSERT_TRUE(dao_mpc_randomize::generate_pair_masks(f, n, masks));
    ASSERT_EQ(masks.size(), n * (n - 1) / 2);

    std::vector<uint32_t> masked;
    ASSERT_TRUE(dao_mpc_additive::to_additive_shares_masked(
        f, n, sh_const, masks, masked));
    ASSERT_EQ(masked.size(), (size_t)n);
    uint64_t sum = 0;
    for (uint32_t v : masked) sum = (sum + v) % f.r;
    EXPECT_EQ(sum, secret % f.r);

    // Baseline sum is also secret (sanity).
    std::vector<uint32_t> base;
    ASSERT_TRUE(dao_mpc_additive::to_additive_shares(f, n, sh_const, base));
    uint64_t bsum = 0;
    for (uint32_t v : base) bsum = (bsum + v) % f.r;
    EXPECT_EQ(bsum, secret % f.r);

    // Masked != baseline (with overwhelming probability for r large).
    EXPECT_NE(masked, base);

    for (auto* x : sh) BN_free(x);
    for (auto* x : bl) BN_free(x);
    BN_CTX_free(ctx);
}

TEST(dao_mpc_eratosthenes, mask_party_local_matches_full)
{
    dao_mpc_field f; f.r = 1000003;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t n = 4, t = 1;
    const uint32_t secret = 999;

    dao_vss_commitments c;
    std::vector<BIGNUM*> sh, bl;
    ASSERT_TRUE(dao_mpc_vss::deal(f, grp, secret, n, t, c, sh, bl, ctx));
    std::vector<const BIGNUM*> sh_const(sh.begin(), sh.end());

    std::vector<dao_pair_mask> masks;
    ASSERT_TRUE(dao_mpc_randomize::generate_pair_masks(f, n, masks));

    std::vector<uint32_t> full;
    ASSERT_TRUE(dao_mpc_additive::to_additive_shares_masked(
        f, n, sh_const, masks, full));

    for (uint32_t me = 1; me <= n; ++me) {
        std::vector<dao_pair_mask> my;
        for (const auto& m : masks)
            if (m.i == me || m.j == me) my.push_back(m);
        uint32_t out = 0;
        ASSERT_TRUE(dao_mpc_additive::to_additive_shares_masked_party(
            f, me, n, sh_const, my, out));
        EXPECT_EQ(out, full[me - 1]);
    }

    for (auto* x : sh) BN_free(x);
    for (auto* x : bl) BN_free(x);
    BN_CTX_free(ctx);
}

TEST(dao_mpc_eratosthenes, mask_fresh_per_call)
{
    // Session-binding invariant in-process: two calls to
    // generate_pair_masks produce distinct rho vectors (with
    // overwhelming probability for a large field). Wire-level
    // enforcement is a separate concern (proposal/candidate/factor
    // binding in the message envelope).
    dao_mpc_field f; f.r = 1000003;
    const uint32_t n = 3;
    std::vector<dao_pair_mask> a, b;
    ASSERT_TRUE(dao_mpc_randomize::generate_pair_masks(f, n, a));
    ASSERT_TRUE(dao_mpc_randomize::generate_pair_masks(f, n, b));
    ASSERT_EQ(a.size(), b.size());
    bool different = false;
    for (size_t k = 0; k < a.size(); ++k) {
        if (a[k].rho != b[k].rho) { different = true; break; }
    }
    EXPECT_TRUE(different);
}

// ================================================================
// Full local sieve at production parameters.
//
// n parties, 130-primes, both P and Q factors. Runs the complete
// local pipeline (VSS deal of u_i, GRR tree across parties,
// to_additive_shares_masked, CRT reconstruct with mod-4, uniform
// lift) and asserts:
//   - each party's p_i and q_i in [L, U)
//   - aggregate P and Q coprime to every sieve prime
//   - aggregate P and Q in [2^lambda, 2^(lambda+sigma))
//   - party 1 gets mod-4 residue 3, others 0
//
// No wire. If this fails, wire integration is pointless.
// ================================================================

namespace {

struct sieve_result
{
    std::vector<BIGNUM*> p;    // per-party contributions to P
    std::vector<BIGNUM*> q;    // per-party contributions to Q
    BIGNUM* P = nullptr;
    BIGNUM* Q = nullptr;
    ~sieve_result() {
        for (auto* x : p) BN_free(x);
        for (auto* x : q) BN_free(x);
        if (P) BN_free(P);
        if (Q) BN_free(Q);
    }
};

// Run the local sieve once for one factor. n parties, t = (n+1)/2 - 1.
bool run_local_sieve_factor(
    const dao_mpc_field& f, const dao_vss_group& grp,
    uint32_t n, uint32_t t,
    const std::vector<uint32_t>& primes,
    const BIGNUM* M0,
    uint32_t lambda, uint32_t sigma,
    std::vector<BIGNUM*>& p_out, BN_CTX* ctx)
{
    p_out.clear();
    // Draw u_i^(r) for each party, each prime. Deal VSS in F_r.
    // For each prime: run multiply_tree across parties' VSS shares
    // to get a degree-t sharing of ∏ u_i. Then per party:
    // Lagrange → additive, apply pairwise masks, CRT-reconstruct
    // with mod-4, lift to [L,U).
    //
    // To keep this one process: all party private state is local,
    // but no party sees another's u_i (we honor the protocol by
    // only combining VSS shares, not the secrets).
    std::vector<std::vector<uint32_t>> u(primes.size(),
        std::vector<uint32_t>(n, 0));

    BIGNUM* rmod = BN_new();
    BIGNUM* tmp = BN_new();
    if (!rmod || !tmp) { if (rmod) BN_free(rmod); if (tmp) BN_free(tmp); return false; }

    for (size_t j = 0; j < primes.size(); ++j) {
        BN_set_word(rmod, primes[j]);
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t v = 0;
            for (int tries = 0; tries < 32 && v == 0; ++tries) {
                if (!BN_priv_rand_range(tmp, rmod)) {
                    BN_free(rmod); BN_free(tmp); return false;
                }
                v = (uint32_t)BN_get_word(tmp);
            }
            if (v == 0) { BN_free(rmod); BN_free(tmp); return false; }
            u[j][i] = v;
        }
    }
    BN_free(rmod); BN_free(tmp);

    // For each prime, produce party i's Shamir share of ∏_k u_k^(r).
    // Lay out: product_share[j][i] = party i's share for prime j.
    std::vector<std::vector<BIGNUM*>> product_share(primes.size());

    for (size_t j = 0; j < primes.size(); ++j) {
        dao_mpc_field fj; fj.r = primes[j];
        // Deal VSS of every party's u_i in F_r at degree t.
        std::vector<std::vector<BIGNUM*>> deals(n);   // [i][k] = share for party k
        std::vector<std::vector<BIGNUM*>> blind(n);
        for (uint32_t i = 0; i < n; ++i) {
            dao_vss_commitments c;
            if (!dao_mpc_vss::deal(fj, grp, u[j][i], n, t, c, deals[i], blind[i], ctx))
                return false;
        }
        // Build operands list for multiply_tree: operands[k] = vector of n shares of u_k.
        std::vector<std::vector<const BIGNUM*>> operands(n);
        for (uint32_t k = 0; k < n; ++k) {
            std::vector<const BIGNUM*> op(n);
            for (uint32_t i = 0; i < n; ++i) op[i] = deals[k][i];
            operands[k] = op;
        }
        std::vector<BIGNUM*> tree_out;
        if (!dao_mpc_mul::multiply_tree(fj, grp, n, t, operands, tree_out, ctx)) {
            for (auto& v : deals) for (auto* x : v) BN_free(x);
            for (auto& v : blind) for (auto* x : v) BN_free(x);
            return false;
        }
        product_share[j] = std::move(tree_out);
        for (auto& v : deals) for (auto* x : v) BN_free(x);
        for (auto& v : blind) for (auto* x : v) BN_free(x);
    }

    // Additive shares with pairwise masks per (j, party). Then CRT
    // per party across primes.
    std::vector<std::vector<uint32_t>> additive_per_party(n,
        std::vector<uint32_t>(primes.size(), 0));

    for (size_t j = 0; j < primes.size(); ++j) {
        dao_mpc_field fj; fj.r = primes[j];
        std::vector<const BIGNUM*> sh(product_share[j].begin(),
                                      product_share[j].end());
        std::vector<dao_pair_mask> masks;
        if (!dao_mpc_randomize::generate_pair_masks(fj, n, masks)) return false;
        std::vector<uint32_t> masked;
        if (!dao_mpc_additive::to_additive_shares_masked(fj, n, sh, masks, masked))
            return false;
        for (uint32_t i = 0; i < n; ++i)
            additive_per_party[i][j] = masked[i];
    }

    // CRT with mod-4 per party (party index 0 = party_id 1).
    std::vector<BIGNUM*> W;
    if (!dao_mpc_crt::crt_reconstruct_with_mod4(primes, additive_per_party, W, ctx)) {
        for (auto& v : product_share) for (auto* x : v) BN_free(x);
        return false;
    }

    // Lift each W_i to [L, U).
    if (!dao_mpc_crt::reconstruct_all_to_contributions(
            W, M0, lambda, sigma, p_out, ctx)) {
        for (auto* w : W) BN_free(w);
        for (auto& v : product_share) for (auto* x : v) BN_free(x);
        return false;
    }

    for (auto* w : W) BN_free(w);
    for (auto& v : product_share) for (auto* x : v) BN_free(x);
    return true;
}

} // namespace

TEST(dao_mpc_eratosthenes, full_local_sieve_n3_130primes)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 3, primes));
    EXPECT_GT(primes.size(), 100u);

    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);

    BIGNUM* M0 = BN_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_modulus_mod4(primes, M0, ctx));

    const uint32_t n = 3, t = 1;
    const uint32_t lambda = 1024, sigma = 80;

    BIGNUM* L = BN_new(); BIGNUM* U = BN_new();
    BN_one(L); BN_lshift(L, L, lambda);
    BIGNUM* n_bn = BN_new(); BN_set_word(n_bn, n);
    BIGNUM* rem = BN_new();
    BN_div(L, rem, L, n_bn, ctx);
    if (!BN_is_zero(rem)) BN_add_word(L, 1);
    BN_one(U); BN_lshift(U, U, lambda + sigma);
    BN_div(U, rem, U, n_bn, ctx);
    if (!BN_is_zero(rem)) BN_add_word(U, 1);

    auto t0 = std::chrono::steady_clock::now();

    // Factor P.
    std::vector<BIGNUM*> P_parts;
    ASSERT_TRUE(run_local_sieve_factor(dao_mpc_field{1000003}, grp, n, t,
        primes, M0, lambda, sigma, P_parts, ctx));
    ASSERT_EQ(P_parts.size(), (size_t)n);

    // Factor Q.
    std::vector<BIGNUM*> Q_parts;
    ASSERT_TRUE(run_local_sieve_factor(dao_mpc_field{1000003}, grp, n, t,
        primes, M0, lambda, sigma, Q_parts, ctx));
    ASSERT_EQ(Q_parts.size(), (size_t)n);

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "[n=3] full sieve P+Q: " << ms << " ms\n";

    BIGNUM* P = BN_new(); BIGNUM* Q = BN_new();
    BN_zero(P); BN_zero(Q);
    for (auto* p : P_parts) BN_add(P, P, p);
    for (auto* q : Q_parts) BN_add(Q, Q, q);

    std::cout << "[n=3] log2(P)=" << BN_num_bits(P)
              << " log2(Q)=" << BN_num_bits(Q)
              << " log2(N)=" << BN_num_bits(P) + BN_num_bits(Q) << "\n";

    // Aggregate bounds: individual p_i in [L, U), so sum in
    // [n*L, n*U). n*L >= 2^lambda, n*U >= 2^(lambda+sigma).
    BIGNUM* nL = BN_new(); BN_mul_word(BN_copy(nL, L), n);
    BIGNUM* nU = BN_new(); BN_mul_word(BN_copy(nU, U), n);
    EXPECT_GE(BN_cmp(P, nL), 0);
    EXPECT_LT(BN_cmp(P, nU), 0);
    EXPECT_GE(BN_cmp(Q, nL), 0);
    EXPECT_LT(BN_cmp(Q, nU), 0);
    BN_free(nL); BN_free(nU);

    // Coprime to every sieve prime.
    for (uint32_t r : primes) {
        EXPECT_NE(BN_mod_word(P, r), 0UL) << "P div by " << r;
        EXPECT_NE(BN_mod_word(Q, r), 0UL) << "Q div by " << r;
        EXPECT_NE(BN_mod_word(P, r), (BN_ULONG)-1);
        EXPECT_NE(BN_mod_word(Q, r), (BN_ULONG)-1);
    }

    // Aggregate mod 4.
    EXPECT_EQ(BN_mod_word(P, 4), 3UL);
    EXPECT_EQ(BN_mod_word(Q, 4), 3UL);

    // Each party's contribution in [L, U).
    for (uint32_t i = 0; i < n; ++i) {
        EXPECT_GE(BN_cmp(P_parts[i], L), 0);
        EXPECT_LT(BN_cmp(P_parts[i], U), 0);
        EXPECT_GE(BN_cmp(Q_parts[i], L), 0);
        EXPECT_LT(BN_cmp(Q_parts[i], U), 0);
    }

    for (auto* x : P_parts) BN_free(x);
    for (auto* x : Q_parts) BN_free(x);
    BN_free(P); BN_free(Q);
    BN_free(L); BN_free(U); BN_free(n_bn); BN_free(rem); BN_free(M0);
    BN_CTX_free(ctx);
}

TEST(dao_mpc_eratosthenes, full_local_sieve_n16_130primes)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 16, primes));
    // n=16, t=7, 2t+1=15. near_primorial_primes starts above 15, so
    // primes {3, 5, 7, 11, 13} are excluded. 127 primes remain
    // (130 minus 5 = 125... actually depends on where 17 falls in
    // the primorial sequence; the test below measures the actual).
    std::cout << "n=16: primes.size()=" << primes.size() << "\n";
    ASSERT_FALSE(primes.empty());
    ASSERT_GE(primes.front(), 17u);

    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);

    BIGNUM* M0 = BN_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_modulus_mod4(primes, M0, ctx));

    const uint32_t n = 16, t = 7;
    const uint32_t lambda = 1024, sigma = 80;

    BIGNUM* L = BN_new(); BIGNUM* U = BN_new();
    BN_one(L); BN_lshift(L, L, lambda);
    BIGNUM* n_bn = BN_new(); BN_set_word(n_bn, n);
    BIGNUM* rem = BN_new();
    BN_div(L, rem, L, n_bn, ctx);
    if (!BN_is_zero(rem)) BN_add_word(L, 1);
    BN_one(U); BN_lshift(U, U, lambda + sigma);
    BN_div(U, rem, U, n_bn, ctx);
    if (!BN_is_zero(rem)) BN_add_word(U, 1);

    auto t0 = std::chrono::steady_clock::now();

    std::vector<BIGNUM*> P_parts, Q_parts;
    ASSERT_TRUE(run_local_sieve_factor(dao_mpc_field{1000003}, grp, n, t,
        primes, M0, lambda, sigma, P_parts, ctx));
    ASSERT_TRUE(run_local_sieve_factor(dao_mpc_field{1000003}, grp, n, t,
        primes, M0, lambda, sigma, Q_parts, ctx));

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "[n=16] full sieve P+Q (126 primes, depth 4): " << ms << " ms\n";

    BIGNUM* P = BN_new(); BIGNUM* Q = BN_new();
    BN_zero(P); BN_zero(Q);
    for (auto* p : P_parts) BN_add(P, P, p);
    for (auto* q : Q_parts) BN_add(Q, Q, q);
    std::cout << "[n=16] log2(P)=" << BN_num_bits(P)
              << " log2(Q)=" << BN_num_bits(Q)
              << " log2(N)=" << BN_num_bits(P) + BN_num_bits(Q) << "\n";

    BIGNUM* nL16 = BN_new(); BN_mul_word(BN_copy(nL16, L), n);
    BIGNUM* nU16 = BN_new(); BN_mul_word(BN_copy(nU16, U), n);
    EXPECT_GE(BN_cmp(P, nL16), 0);
    EXPECT_LT(BN_cmp(P, nU16), 0);
    EXPECT_GE(BN_cmp(Q, nL16), 0);
    EXPECT_LT(BN_cmp(Q, nU16), 0);
    BN_free(nL16); BN_free(nU16);

    for (uint32_t r : primes) {
        EXPECT_NE(BN_mod_word(P, r), 0UL) << "P div by " << r;
        EXPECT_NE(BN_mod_word(Q, r), 0UL) << "Q div by " << r;
    }
    EXPECT_EQ(BN_mod_word(P, 4), 3UL);
    EXPECT_EQ(BN_mod_word(Q, 4), 3UL);

    for (auto* x : P_parts) BN_free(x);
    for (auto* x : Q_parts) BN_free(x);
    BN_free(P); BN_free(Q);
    BN_free(L); BN_free(U); BN_free(n_bn); BN_free(rem); BN_free(M0);
    BN_CTX_free(ctx);
}
