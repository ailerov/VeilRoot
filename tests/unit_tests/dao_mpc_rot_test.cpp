#include "gtest/gtest.h"
#include <chrono>
#include <openssl/bn.h>
#include <vector>

#include "governance/dao_dkg.h"
#include "governance/dao_mpc.h"
#include "governance/dao_mpc_abb.h"
#include "governance/dao_mpc_crt.h"
#include "governance/dao_mpc_rot.h"

using namespace cryptonote::dao;

// ------------------------------------------------------------------
// Cross-term identity: c_ij_i + c_ij_j == a_i * b_j mod r.
// ------------------------------------------------------------------

TEST(dao_mpc_rot, cross_term_identity_all_pairs_n3)
{
    dao_mpc_field f; f.r = 739;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);

    // Exhaustively verify for a modest set of (a_i, b_j).
    const uint32_t vals[] = {0, 1, 2, 3, 7, 100, 500, 738};
    for (uint32_t ai : vals) {
        for (uint32_t bj : vals) {
            dao_rot_cross_terms ct;
            ASSERT_TRUE(frot_simulate_cross_terms(f.r, ai, bj, ct, ctx));
            uint32_t sum = f.add(ct.c_ij_i, ct.c_ij_j);
            EXPECT_EQ(sum, f.mul(ai, bj))
                << "a_i=" << ai << " b_j=" << bj;
        }
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_rot, cross_term_identity_random_n16)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_mpc_field f; f.r = 739;
    BIGNUM* rmod = BN_new(); BN_set_word(rmod, f.r);
    BIGNUM* tmp  = BN_new();

    for (int trial = 0; trial < 200; ++trial) {
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        uint32_t ai = (uint32_t)BN_get_word(tmp);
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        uint32_t bj = (uint32_t)BN_get_word(tmp);
        dao_rot_cross_terms ct;
        ASSERT_TRUE(frot_simulate_cross_terms(f.r, ai, bj, ct, ctx));
        EXPECT_EQ(f.add(ct.c_ij_i, ct.c_ij_j), f.mul(ai, bj));
    }
    BN_free(rmod); BN_free(tmp); BN_CTX_free(ctx);
}

// ------------------------------------------------------------------
// Full triple: sum(a)*sum(b) == sum(c) mod r.
// ------------------------------------------------------------------

TEST(dao_mpc_rot, triple_generation_small_primes)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    for (uint32_t r : {3u, 5u, 7u, 11u, 13u, 17u, 101u, 739u}) {
        for (uint32_t n : {3u, 4u, 5u}) {
            std::vector<dao_abb_triple> t;
            ASSERT_TRUE(generate_triple_rot(r, n, t, ctx))
                << "r=" << r << " n=" << n;
            ASSERT_EQ(t.size(), (size_t)n);
            dao_mpc_field f; f.r = r;
            uint32_t sa = 0, sb = 0, sc = 0;
            for (uint32_t i = 0; i < n; ++i) {
                sa = f.add(sa, t[i].a.value);
                sb = f.add(sb, t[i].b.value);
                sc = f.add(sc, t[i].c.value);
            }
            EXPECT_EQ(f.mul(sa, sb), sc) << "r=" << r << " n=" << n;
        }
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_rot, triple_generation_n16)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t r = 739;
    const uint32_t n = 16;
    for (int trial = 0; trial < 20; ++trial) {
        std::vector<dao_abb_triple> t;
        ASSERT_TRUE(generate_triple_rot(r, n, t, ctx));
        ASSERT_EQ(t.size(), (size_t)n);
        dao_mpc_field f; f.r = r;
        uint32_t sa = 0, sb = 0, sc = 0;
        for (uint32_t i = 0; i < n; ++i) {
            sa = f.add(sa, t[i].a.value);
            sb = f.add(sb, t[i].b.value);
            sc = f.add(sc, t[i].c.value);
        }
        EXPECT_EQ(f.mul(sa, sb), sc);
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_rot, batch_100_triples_all_valid)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t r = 739, n = 3, count = 100;
    std::vector<std::vector<dao_abb_triple>> batch;
    ASSERT_TRUE(generate_triples_rot_batch(r, n, count, batch, ctx));
    ASSERT_EQ(batch.size(), (size_t)n);
    for (uint32_t i = 0; i < n; ++i) ASSERT_EQ(batch[i].size(), (size_t)count);
    dao_mpc_field f; f.r = r;
    for (uint32_t k = 0; k < count; ++k) {
        uint32_t sa = 0, sb = 0, sc = 0;
        for (uint32_t i = 0; i < n; ++i) {
            sa = f.add(sa, batch[i][k].a.value);
            sb = f.add(sb, batch[i][k].b.value);
            sc = f.add(sc, batch[i][k].c.value);
        }
        EXPECT_EQ(f.mul(sa, sb), sc) << "triple " << k;
    }
    BN_CTX_free(ctx);
}

// ------------------------------------------------------------------
// Beaver online on real ROT-generated triple: end-to-end check.
// ------------------------------------------------------------------

TEST(dao_mpc_rot, beaver_on_rot_triple_reproduces_product)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t r = 739, n = 5;
    dao_mpc_field f; f.r = r;

    std::vector<dao_abb_triple> triples;
    ASSERT_TRUE(generate_triple_rot(r, n, triples, ctx));

    // Random x, y with known sums.
    std::vector<dao_abb_share> xs(n), ys(n);
    BIGNUM* rmod = BN_new(); BN_set_word(rmod, r);
    BIGNUM* tmp  = BN_new();
    uint32_t x_sum = 0, y_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        xs[i].value = (uint32_t)BN_get_word(tmp);
        x_sum = f.add(x_sum, xs[i].value);
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        ys[i].value = (uint32_t)BN_get_word(tmp);
        y_sum = f.add(y_sum, ys[i].value);
    }
    BN_free(rmod); BN_free(tmp);

    uint32_t a_sum = 0, b_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        a_sum = f.add(a_sum, triples[i].a.value);
        b_sum = f.add(b_sum, triples[i].b.value);
    }
    uint32_t e   = f.sub(x_sum, a_sum);
    uint32_t rho = f.sub(y_sum, b_sum);

    std::vector<dao_abb_share> zs(n);
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(dao_mpc_abb::beaver_multiply(
            f, i+1, n, xs[i], ys[i], triples[i], e, rho, zs[i]));
    }
    uint32_t z_sum = 0;
    for (uint32_t i = 0; i < n; ++i) z_sum = f.add(z_sum, zs[i].value);
    EXPECT_EQ(z_sum, f.mul(x_sum, y_sum));
    BN_CTX_free(ctx);
}

// ------------------------------------------------------------------
// Session-bound triple store: unique consumption, isolation.
// ------------------------------------------------------------------

TEST(dao_mpc_rot, triple_store_unique_consumption)
{
    dao_triple_store s;
    dao_abb_triple t;
    t.a.value = 1; t.b.value = 2; t.c.value = 2;
    ASSERT_TRUE(s.insert(100, t));
    EXPECT_FALSE(s.insert(100, t));   // duplicate insert rejected
    EXPECT_TRUE(s.contains(100));
    EXPECT_EQ(s.unconsumed(), 1u);
    EXPECT_EQ(s.consumed(),   0u);

    dao_abb_triple got;
    ASSERT_TRUE(s.consume(100, got));
    EXPECT_EQ(got.a.value, 1u);
    EXPECT_EQ(s.unconsumed(), 0u);
    EXPECT_EQ(s.consumed(),   1u);
    EXPECT_FALSE(s.consume(100, got)); // double consume rejected
    EXPECT_TRUE(s.contains(100));      // still tracked as consumed
}

TEST(dao_mpc_rot, triple_store_isolated_sessions)
{
    dao_triple_store s;
    dao_abb_triple a, b;
    a.a.value = 1; b.a.value = 99;
    ASSERT_TRUE(s.insert(1, a));
    ASSERT_TRUE(s.insert(2, b));
    dao_abb_triple got_a, got_b;
    ASSERT_TRUE(s.consume(1, got_a));
    ASSERT_TRUE(s.consume(2, got_b));
    EXPECT_EQ(got_a.a.value, 1u);
    EXPECT_EQ(got_b.a.value, 99u);
    EXPECT_FALSE(s.consume(1, got_a));
    EXPECT_FALSE(s.consume(2, got_b));
}

// ------------------------------------------------------------------
// Communication accounting per expert's formula.
// ------------------------------------------------------------------

TEST(dao_mpc_rot, bytes_per_party_per_triple_formula)
{
    // Expert: (n - 1) * (128*k + k^2) bits per party per triple.
    // r = 739 → k = 10.
    EXPECT_EQ(dao_rot_k_of(739), 10u);
    EXPECT_EQ(dao_rot_k_of(101),  7u);
    EXPECT_EQ(dao_rot_k_of(3),    2u);

    // n=16, r=739: 15 * (1280 + 100) = 15 * 1380 = 20,700 bits = 2,587 bytes.
    const uint64_t bits = dao_rot_bytes_per_party_per_triple(739, 16);
    EXPECT_EQ(bits, 15ull * (128ull * 10 + 100ull));
    std::cout << "n=16 r=739: " << bits << " bits/party/triple = "
              << (bits / 8) << " bytes\n";
}

// ------------------------------------------------------------------
// Benchmark: per-triple arithmetic cost (in-process FROT simulation).
// This is a LOWER BOUND on real FROT (no network). Useful to separate
// Figure 19 arithmetic from MP-SPDZ Semi network cost.
// ------------------------------------------------------------------

TEST(dao_mpc_rot, bench_per_triple_arithmetic_n3)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t r = 739, n = 3, count = 100;
    auto t0 = std::chrono::steady_clock::now();
    for (uint32_t k = 0; k < count; ++k) {
        std::vector<dao_abb_triple> t;
        ASSERT_TRUE(generate_triple_rot(r, n, t, ctx));
    }
    auto t1 = std::chrono::steady_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    std::cout << "[n=3] per-triple: " << (us / count) << " us\n";
    std::cout << "[n=3] triples for 1 candidate (126 primes * 2 factors * (n-1) mult): "
              << (126ull * 2 * (n - 1)) << "\n";
    const uint64_t per_cand_ms = (uint64_t)(us / count) * (126ull * 2 * (n - 1)) / 1000;
    std::cout << "[n=3] extrapolated preprocessing per candidate: "
              << per_cand_ms << " ms\n";
    BN_CTX_free(ctx);
}

TEST(dao_mpc_rot, bench_per_triple_arithmetic_n16)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t r = 739, n = 16, count = 10;
    auto t0 = std::chrono::steady_clock::now();
    for (uint32_t k = 0; k < count; ++k) {
        std::vector<dao_abb_triple> t;
        ASSERT_TRUE(generate_triple_rot(r, n, t, ctx));
    }
    auto t1 = std::chrono::steady_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    std::cout << "[n=16] per-triple: " << (us / count) << " us\n";
    std::cout << "[n=16] triples for 1 candidate (126 primes * 2 factors * (n-1) mult): "
              << (126ull * 2 * (n - 1)) << "\n";
    const uint64_t per_cand_ms = (uint64_t)(us / count) * (126ull * 2 * (n - 1)) / 1000;
    std::cout << "[n=16] extrapolated preprocessing per candidate: "
              << per_cand_ms << " ms\n";
    std::cout << "[n=16] extrapolated batch-32 preprocessing: "
              << (per_cand_ms * 32) << " ms\n";
    BN_CTX_free(ctx);
}


// ================================================================
// Expert-required Combine tests.
// ================================================================

namespace {

dao_rot_frand_ctx make_ctx(uint32_t candidate = 1, uint8_t factor = 0,
                           uint16_t crt = 0, uint32_t triple_idx = 0)
{
    dao_rot_frand_ctx c;
    for (int i = 0; i < 32; ++i) {
        c.proposal_id[i]       = (uint8_t)(0x10 + i);
        c.committee_id_hash[i] = (uint8_t)(0x80 + i);
    }
    c.candidate_id = candidate;
    c.factor       = factor;
    c.crt_index    = crt;
    c.triple_index = triple_idx;
    return c;
}

} // namespace

// (1) Honest raw triple remains valid after Combine, every party.
TEST(dao_mpc_rot, combine_honest_triple_valid_n3)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_mpc_field f; f.r = 739;
    for (int trial = 0; trial < 20; ++trial) {
        std::vector<dao_abb_triple> raw;
        ASSERT_TRUE(generate_triple_rot(f.r, 3, raw, ctx));
        auto frand_ctx = make_ctx(1, 0, 0, (uint32_t)trial);
        uint32_t r = 0;
        ASSERT_TRUE(sample_nonzero_common_field_element(frand_ctx, f.r, r));
        std::vector<dao_abb_triple> out(3);
        for (uint32_t i = 0; i < 3; ++i) {
            ASSERT_TRUE(combine_triple(f, r, raw[i].a.value,
                                       raw[i].b.value, raw[i].c.value,
                                       out[i].a.value, out[i].b.value,
                                       out[i].c.value));
        }
        uint32_t sa = 0, sb = 0, sc = 0;
        for (uint32_t i = 0; i < 3; ++i) {
            sa = f.add(sa, out[i].a.value);
            sb = f.add(sb, out[i].b.value);
            sc = f.add(sc, out[i].c.value);
        }
        EXPECT_EQ(f.mul(sa, sb), sc) << "trial " << trial;
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_rot, combine_honest_triple_valid_n16)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_mpc_field f; f.r = 739;
    for (int trial = 0; trial < 10; ++trial) {
        std::vector<dao_abb_triple> raw;
        ASSERT_TRUE(generate_triple_rot(f.r, 16, raw, ctx));
        auto frand_ctx = make_ctx(1, 0, 0, (uint32_t)trial);
        uint32_t r = 0;
        ASSERT_TRUE(sample_nonzero_common_field_element(frand_ctx, f.r, r));
        uint32_t sa = 0, sb = 0, sc = 0;
        for (uint32_t i = 0; i < 16; ++i) {
            uint32_t ai, bi, ci;
            ASSERT_TRUE(combine_triple(f, r, raw[i].a.value, raw[i].b.value,
                                       raw[i].c.value, ai, bi, ci));
            sa = f.add(sa, ai); sb = f.add(sb, bi); sc = f.add(sc, ci);
        }
        EXPECT_EQ(f.mul(sa, sb), sc) << "trial " << trial;
    }
    BN_CTX_free(ctx);
}

// (2) All parties use the same session-bound r (determinism).
TEST(dao_mpc_rot, combine_same_r_for_all_parties)
{
    auto ctx = make_ctx(7, 1, 42, 3);
    uint32_t r1 = 0, r2 = 0, r3 = 0;
    ASSERT_TRUE(sample_nonzero_common_field_element(ctx, 739, r1));
    ASSERT_TRUE(sample_nonzero_common_field_element(ctx, 739, r2));
    ASSERT_TRUE(sample_nonzero_common_field_element(ctx, 739, r3));
    EXPECT_EQ(r1, r2);
    EXPECT_EQ(r2, r3);
    EXPECT_NE(r1, 0u);
    EXPECT_LT(r1, 739u);
}

// (3) Zero is rejected and resampled.
TEST(dao_mpc_rot, combine_rejects_zero_r)
{
    // Over 1000 fresh contexts, all nonzero.
    int zeros = 0;
    for (uint32_t i = 0; i < 1000; ++i) {
        auto ctx = make_ctx(1, 0, 0, i);
        uint32_t r = 0;
        ASSERT_TRUE(sample_nonzero_common_field_element(ctx, 3, r));
        if (r == 0) ++zeros;
        EXPECT_LT(r, 3u);
    }
    EXPECT_EQ(zeros, 0) << "nonzero sampling returned zero";
}

// (4) frand_common output is uniform over F_r across session ids.
TEST(dao_mpc_rot, combine_frand_uniform)
{
    const uint32_t trials = 5000;
    const uint32_t r_field = 5;
    std::vector<uint32_t> counts(r_field, 0);
    for (uint32_t i = 0; i < trials; ++i) {
        auto ctx = make_ctx(1, 0, 0, i);
        uint32_t r = 0;
        ASSERT_TRUE(frand_common(ctx, 0, r_field, r));
        ASSERT_LT(r, r_field);
        counts[r]++;
    }
    // Expected ~1000 per bucket; tolerance ±250.
    for (uint32_t v = 0; v < r_field; ++v) {
        EXPECT_GT(counts[v], 750u) << "bucket " << v;
        EXPECT_LT(counts[v], 1250u) << "bucket " << v;
    }
}

// (5) Injected error Δ transforms to r*Δ under Combine.
TEST(dao_mpc_rot, combine_error_transform)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_mpc_field f; f.r = 739;
    const uint32_t n = 3;

    for (uint32_t delta = 1; delta < 5; ++delta) {
        std::vector<dao_abb_triple> raw;
        ASSERT_TRUE(generate_triple_rot(f.r, n, raw, ctx));

        // Inject delta into party 1's raw c-share.
        raw[0].c.value = f.add(raw[0].c.value, delta);

        auto frand_ctx = make_ctx(1, 0, 0, delta);
        uint32_t r = 0;
        ASSERT_TRUE(sample_nonzero_common_field_element(frand_ctx, f.r, r));

        uint32_t sa = 0, sb = 0, sc = 0;
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t ai, bi, ci;
            ASSERT_TRUE(combine_triple(f, r, raw[i].a.value, raw[i].b.value,
                                       raw[i].c.value, ai, bi, ci));
            sa = f.add(sa, ai); sb = f.add(sb, bi); sc = f.add(sc, ci);
        }
        const uint32_t expected_valid = f.mul(sa, sb);
        const uint32_t observed_error = f.sub(sc, expected_valid);
        const uint32_t expected_error = f.mul(r, delta);
        EXPECT_EQ(observed_error, expected_error)
            << "delta=" << delta << " r=" << r;
    }
    BN_CTX_free(ctx);
}

// (6) Different session fields produce different r.
TEST(dao_mpc_rot, combine_distinct_sids_differ)
{
    auto a = make_ctx(1, 0, 0, 0);
    auto b = make_ctx(2, 0, 0, 0);   // candidate differs
    auto c = make_ctx(1, 1, 0, 0);   // factor differs
    auto d = make_ctx(1, 0, 5, 0);   // crt_index differs
    auto e = make_ctx(1, 0, 0, 5);   // triple_index differs

    uint32_t ra, rb, rc, rd, re;
    ASSERT_TRUE(frand_common(a, 0, 739, ra));
    ASSERT_TRUE(frand_common(b, 0, 739, rb));
    ASSERT_TRUE(frand_common(c, 0, 739, rc));
    ASSERT_TRUE(frand_common(d, 0, 739, rd));
    ASSERT_TRUE(frand_common(e, 0, 739, re));
    // Not all equal (collision prob per pair ~ 1/739; five distinct
    // pairs — expect high confidence all differ, but be lenient).
    int distinct = (ra != rb) + (ra != rc) + (ra != rd) + (ra != re);
    EXPECT_GE(distinct, 3) << "ra=" << ra << " rb=" << rb
                            << " rc=" << rc << " rd=" << rd << " re=" << re;
}

// (7) Hatted branch not exposed as additional triple.
TEST(dao_mpc_rot, hatted_branch_not_exposed)
{
    // Structural: dao_abb_triple has exactly three uint32 shares.
    EXPECT_EQ(sizeof(dao_abb_triple), 3u * sizeof(dao_abb_share));
    EXPECT_EQ(sizeof(dao_abb_share), sizeof(uint32_t));

    // generate_triple_rot_full returns exactly n triples, not 2n.
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    auto frand_ctx = make_ctx(1, 0, 0, 99);
    std::vector<dao_abb_triple> out;
    ASSERT_TRUE(generate_triple_rot_full(739, 3, frand_ctx, out, ctx));
    EXPECT_EQ(out.size(), 3u);
    // No .hat_a / .hat_c accessor exists on dao_abb_triple by design.
    BN_CTX_free(ctx);
}

// End-to-end production path: generate_triple_rot_full gives a valid
// Beaver triple that the online multiply consumes correctly.
TEST(dao_mpc_rot, full_pipeline_beaver_works)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_mpc_field f; f.r = 739;
    const uint32_t n = 5;

    auto frand_ctx = make_ctx(3, 0, 17, 0);
    std::vector<dao_abb_triple> triples;
    ASSERT_TRUE(generate_triple_rot_full(f.r, n, frand_ctx, triples, ctx));
    ASSERT_EQ(triples.size(), (size_t)n);

    // Random x, y with known sums.
    BIGNUM* rmod = BN_new(); BN_set_word(rmod, f.r);
    BIGNUM* tmp  = BN_new();
    std::vector<dao_abb_share> xs(n), ys(n);
    uint32_t x_sum = 0, y_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        xs[i].value = (uint32_t)BN_get_word(tmp);
        x_sum = f.add(x_sum, xs[i].value);
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        ys[i].value = (uint32_t)BN_get_word(tmp);
        y_sum = f.add(y_sum, ys[i].value);
    }
    BN_free(rmod); BN_free(tmp);

    uint32_t a_sum = 0, b_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        a_sum = f.add(a_sum, triples[i].a.value);
        b_sum = f.add(b_sum, triples[i].b.value);
    }
    uint32_t e   = f.sub(x_sum, a_sum);
    uint32_t rho = f.sub(y_sum, b_sum);

    std::vector<dao_abb_share> zs(n);
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(dao_mpc_abb::beaver_multiply(
            f, i+1, n, xs[i], ys[i], triples[i], e, rho, zs[i]));
    }
    uint32_t z_sum = 0;
    for (uint32_t i = 0; i < n; ++i) z_sum = f.add(z_sum, zs[i].value);
    EXPECT_EQ(z_sum, f.mul(x_sum, y_sum));
    BN_CTX_free(ctx);
}


// ================================================================
// Pi_InputTuple (Fig. 18 ACM / Fig. 14 ePrint revision) tests.
// ================================================================

TEST(dao_mpc_input, tuple_shares_sum_to_r)
{
    dao_mpc_field f; f.r = 739;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    for (uint32_t owner = 1; owner <= 5; ++owner) {
        for (int trial = 0; trial < 50; ++trial) {
            dao_input_tuple t;
            ASSERT_TRUE(input_tuple_generate(f, 5, owner, t, ctx));
            ASSERT_EQ(t.shares.size(), 5u);
            uint32_t s = 0;
            for (uint32_t v : t.shares) { EXPECT_LT(v, f.r); s = f.add(s, v); }
            EXPECT_EQ(s, t.r) << "owner=" << owner;
        }
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_input, owner_share_is_r_minus_others)
{
    dao_mpc_field f; f.r = 739;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t n = 6, owner = 3;
    for (int trial = 0; trial < 50; ++trial) {
        dao_input_tuple t;
        ASSERT_TRUE(input_tuple_generate(f, n, owner, t, ctx));
        uint32_t others = 0;
        for (uint32_t i = 0; i < n; ++i)
            if (i != owner - 1) others = f.add(others, t.shares[i]);
        EXPECT_EQ(t.shares[owner - 1], f.sub(t.r, others));
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_input, input_reconstruction_yields_x)
{
    dao_mpc_field f; f.r = 739;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t n = 4;
    BIGNUM* rmod = BN_new(); BN_set_word(rmod, f.r);
    BIGNUM* tmp  = BN_new();
    for (int trial = 0; trial < 100; ++trial) {
        // Random x to be input by party 2.
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        const uint32_t x = (uint32_t)BN_get_word(tmp);

        dao_input_tuple t;
        ASSERT_TRUE(input_tuple_generate(f, n, 2, t, ctx));
        uint32_t eps = 0;
        ASSERT_TRUE(input_mask_broadcast(f, x, t.r, eps));

        uint32_t sum = 0;
        for (uint32_t j = 0; j < n; ++j) {
            uint32_t sh = 0;
            ASSERT_TRUE(input_share_apply(f, j + 1, t.shares[j], eps, sh));
            sum = f.add(sum, sh);
        }
        EXPECT_EQ(sum, x) << "trial " << trial;
    }
    BN_free(rmod); BN_free(tmp); BN_CTX_free(ctx);
}

TEST(dao_mpc_input, epsilon_is_uniform_for_fixed_x)
{
    // For a fixed x, eps = x - r is uniform because r is uniform.
    dao_mpc_field f; f.r = 11;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t x = 4;
    std::vector<uint32_t> counts(f.r, 0);
    for (int trial = 0; trial < 4400; ++trial) {
        dao_input_tuple t;
        ASSERT_TRUE(input_tuple_generate(f, 3, 1, t, ctx));
        uint32_t eps = 0;
        ASSERT_TRUE(input_mask_broadcast(f, x, t.r, eps));
        counts[eps]++;
    }
    // Expected ~400 per bucket; tolerate ±150.
    for (uint32_t v = 0; v < f.r; ++v) {
        EXPECT_GT(counts[v], 250u) << "eps=" << v;
        EXPECT_LT(counts[v], 550u) << "eps=" << v;
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_input, count_matches_expert_numbers)
{
    // Expert: I = C * 2 * L * n.  L = 126, C = 32.
    EXPECT_EQ(input_tuple_count(32, 2, 126, 3), 24192ull);
    EXPECT_EQ(input_tuple_count(32, 2, 126, 16), 129024ull);
    // One candidate, one factor, one prime, one party.
    EXPECT_EQ(input_tuple_count(1, 1, 1, 1), 1ull);
}

TEST(dao_mpc_input, triple_with_inputs_valid_and_combines)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_mpc_field f; f.r = 739;
    for (uint32_t n : {3u, 5u, 16u}) {
        for (int trial = 0; trial < 10; ++trial) {
            std::vector<dao_abb_triple> raw;
            ASSERT_TRUE(generate_triple_rot_with_inputs(f.r, n, raw, ctx));
            ASSERT_EQ(raw.size(), (size_t)n);

            // Raw triple valid.
            uint32_t sa = 0, sb = 0, sc = 0;
            for (uint32_t i = 0; i < n; ++i) {
                sa = f.add(sa, raw[i].a.value);
                sb = f.add(sb, raw[i].b.value);
                sc = f.add(sc, raw[i].c.value);
            }
            EXPECT_EQ(f.mul(sa, sb), sc) << "n=" << n;

            // Combine preserves validity.
            dao_rot_frand_ctx sid;
            for (int i = 0; i < 32; ++i) sid.proposal_id[i] = (uint8_t)i;
            sid.candidate_id = 1; sid.factor = 0; sid.crt_index = 0;
            sid.triple_index = (uint32_t)trial;
            uint32_t r = 0;
            ASSERT_TRUE(sample_nonzero_common_field_element(sid, f.r, r));
            std::vector<dao_abb_triple> comb;
            ASSERT_TRUE(combine_triple_vector(f, r, raw, comb));
            uint32_t ca = 0, cb = 0, cc = 0;
            for (uint32_t i = 0; i < n; ++i) {
                ca = f.add(ca, comb[i].a.value);
                cb = f.add(cb, comb[i].b.value);
                cc = f.add(cc, comb[i].c.value);
            }
            EXPECT_EQ(f.mul(ca, cb), cc) << "n=" << n;
        }
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_input, input_triple_beaver_end_to_end)
{
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_mpc_field f; f.r = 739;
    const uint32_t n = 5;

    std::vector<dao_abb_triple> raw;
    ASSERT_TRUE(generate_triple_rot_with_inputs(f.r, n, raw, ctx));
    dao_rot_frand_ctx sid;
    for (int i = 0; i < 32; ++i) sid.proposal_id[i] = (uint8_t)(i + 1);
    sid.triple_index = 7;
    uint32_t rr = 0;
    ASSERT_TRUE(sample_nonzero_common_field_element(sid, f.r, rr));
    std::vector<dao_abb_triple> trip;
    ASSERT_TRUE(combine_triple_vector(f, rr, raw, trip));

    // Random x, y and a Beaver multiply on the input-backed triple.
    BIGNUM* rmod = BN_new(); BN_set_word(rmod, f.r);
    BIGNUM* tmp  = BN_new();
    std::vector<dao_abb_share> xs(n), ys(n);
    uint32_t x_sum = 0, y_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        xs[i].value = (uint32_t)BN_get_word(tmp);
        x_sum = f.add(x_sum, xs[i].value);
        ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
        ys[i].value = (uint32_t)BN_get_word(tmp);
        y_sum = f.add(y_sum, ys[i].value);
    }
    uint32_t a_sum = 0, b_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        a_sum = f.add(a_sum, trip[i].a.value);
        b_sum = f.add(b_sum, trip[i].b.value);
    }
    uint32_t e   = f.sub(x_sum, a_sum);
    uint32_t rho = f.sub(y_sum, b_sum);
    uint32_t z_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        dao_abb_share z;
        ASSERT_TRUE(dao_mpc_abb::beaver_multiply(
            f, i+1, n, xs[i], ys[i], trip[i], e, rho, z));
        z_sum = f.add(z_sum, z.value);
    }
    EXPECT_EQ(z_sum, f.mul(x_sum, y_sum));

    BN_free(rmod); BN_free(tmp); BN_CTX_free(ctx);
}

TEST(dao_mpc_input, distinct_tuples_have_independent_r)
{
    // Two tuples for the same owner must not share r (input tuple
    // fresh consumption; no reuse).
    dao_mpc_field f; f.r = 1000003;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_input_tuple t1, t2;
    ASSERT_TRUE(input_tuple_generate(f, 4, 1, t1, ctx));
    ASSERT_TRUE(input_tuple_generate(f, 4, 1, t2, ctx));
    EXPECT_NE(t1.r, t2.r);
    EXPECT_NE(t1.shares, t2.shares);
    BN_CTX_free(ctx);
}


TEST(dao_mpc_input, epsilon_lands_on_party_1_only)
{
    // For a fixed tuple and nonzero eps, only share 1 changes.
    dao_mpc_field f; f.r = 739;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    dao_input_tuple t;
    ASSERT_TRUE(input_tuple_generate(f, 5, 3, t, ctx));
    const uint32_t eps = 17;

    std::vector<uint32_t> derived(5);
    for (uint32_t j = 0; j < 5; ++j) {
        ASSERT_TRUE(input_share_apply(f, j + 1, t.shares[j], eps, derived[j]));
    }
    // Party 1: t.shares[0] + eps.  Others: unchanged.
    EXPECT_EQ(derived[0], f.add(t.shares[0], eps));
    for (uint32_t j = 1; j < 5; ++j) {
        EXPECT_EQ(derived[j], t.shares[j]);
    }
    // Sum still recovers the owner's r plus eps only once, i.e.
    // sum(derived) = r + eps (not r + 5*eps).
    uint32_t s = 0;
    for (uint32_t v : derived) s = f.add(s, v);
    EXPECT_EQ(s, f.add(t.r, eps));
    BN_CTX_free(ctx);
}
