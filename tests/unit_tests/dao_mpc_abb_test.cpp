#include "gtest/gtest.h"
#include <chrono>
#include <openssl/bn.h>
#include <vector>

#include "governance/dao_dkg.h"
#include "governance/dao_mpc.h"
#include "governance/dao_mpc_abb.h"
#include "governance/dao_mpc_crt.h"

using namespace cryptonote::dao;

// ------------------------------------------------------------------
// Beaver online multiply correctness.
// ------------------------------------------------------------------

TEST(dao_mpc_abb, beaver_multiply_hand_case)
{
    // Fixed triple, fixed x, y, verify z shares sum to x*y.
    // a=3, b=4, c=12. x=5, y=7, z=35.
    // a-share (1,1,1), b-share (2,1,1), c-share (4,4,4).
    // x-share (2,3,0), y-share (3,2,2).
    // e = x-a = 2, rho = y-b = 3.
    // z_1 = 4 + 2*2 + 3*1 + 2*3 = 17
    // z_2 = 4 + 2*1 + 3*1 = 9
    // z_3 = 4 + 2*1 + 3*1 = 9
    // sum = 35 ✓
    dao_mpc_field f; f.r = 1000003;
    dao_abb_share z1, z2, z3;
    dao_abb_triple t1 = {{1},{2},{4}};
    dao_abb_triple t2 = {{1},{1},{4}};
    dao_abb_triple t3 = {{1},{1},{4}};
    dao_abb_share x1 = {2}, x2 = {3}, x3 = {0};
    dao_abb_share y1 = {3}, y2 = {2}, y3 = {2};
    ASSERT_TRUE(dao_mpc_abb::beaver_multiply(f, 1, 3, x1, y1, t1, 2, 3, z1));
    ASSERT_TRUE(dao_mpc_abb::beaver_multiply(f, 2, 3, x2, y2, t2, 2, 3, z2));
    ASSERT_TRUE(dao_mpc_abb::beaver_multiply(f, 3, 3, x3, y3, t3, 2, 3, z3));
    EXPECT_EQ(z1.value, 17u);
    EXPECT_EQ(z2.value, 9u);
    EXPECT_EQ(z3.value, 9u);
    uint32_t sum = 0;
    sum = f.add(sum, z1.value);
    sum = f.add(sum, z2.value);
    sum = f.add(sum, z3.value);
    EXPECT_EQ(sum, 35u);
}

TEST(dao_mpc_abb, beaver_multiply_random_fuzz)
{
    dao_mpc_field f; f.r = 65537;
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    const uint32_t n = 5;

    for (int trial = 0; trial < 100; ++trial) {
        std::vector<std::vector<dao_abb_triple>> trips;
        ASSERT_TRUE(generate_consistent_triples_trusted_dealer(
            n, f.r, 1, trips, ctx));

        // Random x, y with known sums.
        std::vector<dao_abb_share> xs(n), ys(n);
        BIGNUM* rmod = BN_new(); BN_set_word(rmod, f.r);
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

        uint32_t e = f.sub(x_sum, trips[0][0].a.value);   // x-a
        // Recompute true a and b from shares:
        uint32_t a_sum = 0, b_sum = 0;
        for (uint32_t i = 0; i < n; ++i) {
            a_sum = f.add(a_sum, trips[i][0].a.value);
            b_sum = f.add(b_sum, trips[i][0].b.value);
        }
        e = f.sub(x_sum, a_sum);
        uint32_t rho = f.sub(y_sum, b_sum);

        std::vector<dao_abb_share> zs(n);
        for (uint32_t i = 0; i < n; ++i) {
            ASSERT_TRUE(dao_mpc_abb::beaver_multiply(
                f, i+1, n, xs[i], ys[i], trips[i][0], e, rho, zs[i]));
        }
        uint32_t z_sum = 0;
        for (uint32_t i = 0; i < n; ++i) z_sum = f.add(z_sum, zs[i].value);
        EXPECT_EQ(z_sum, f.mul(x_sum, y_sum)) << "trial " << trial;
    }
    BN_CTX_free(ctx);
}

TEST(dao_mpc_abb, beaver_rejects_bad_party_id)
{
    dao_mpc_field f; f.r = 101;
    dao_abb_triple t = {{1},{2},{3}};
    dao_abb_share zi;
    dao_abb_share x = {1}, y = {2};
    EXPECT_FALSE(dao_mpc_abb::beaver_multiply(f, 0, 3, x, y, t, 1, 1, zi));
    EXPECT_FALSE(dao_mpc_abb::beaver_multiply(f, 4, 3, x, y, t, 1, 1, zi));
    EXPECT_FALSE(dao_mpc_abb::beaver_multiply(f, 1, 3, x, y, t, f.r, 1, zi));
}

TEST(dao_mpc_abb, session_binding_init)
{
    dao_mpc_abb abb;
    dao_abb_session s;
    s.candidate_id = 42; s.factor = 1; s.crt_index = 17;
    s.mul_level = 2; s.mul_node = 3;
    ASSERT_TRUE(abb.initialize(s, 65537));
    EXPECT_EQ(abb.field_modulus(), 65537u);
    EXPECT_EQ(abb.session().candidate_id, 42u);
    EXPECT_EQ(abb.session().factor, 1u);
    EXPECT_EQ(abb.session().crt_index, 17u);
    EXPECT_EQ(abb.session().mul_level, 2u);
    EXPECT_EQ(abb.session().mul_node, 3u);
    EXPECT_FALSE(abb.initialize(s, 2));
}

// ------------------------------------------------------------------
// Split measurement: how expensive is the online-only phase?
// ------------------------------------------------------------------

TEST(dao_mpc_abb, online_only_measurement_n16)
{
    const uint32_t n = 16;
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, n, primes));
    ASSERT_GT(primes.size(), 100u);

    // Total multiplies for one candidate: (n-1) per (factor, prime).
    const uint32_t n_ops = (n - 1) * (uint32_t)primes.size() * 2;
    std::cout << "[n=16] online-only multiplies per candidate: " << n_ops << "\n";

    // Field for beaver ops is the per-prime field, but for measurement
    // we use the largest prime as a proxy (worst case).
    dao_mpc_field f; f.r = primes.back();

    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);

    std::vector<std::vector<dao_abb_triple>> triples;
    ASSERT_TRUE(generate_consistent_triples_trusted_dealer(
        n, f.r, n_ops, triples, ctx));

    std::vector<dao_abb_share> xs(n), ys(n);
    for (uint32_t i = 0; i < n; ++i) {
        xs[i].value = (i * 7 + 3) % f.r;
        ys[i].value = (i * 11 + 5) % f.r;
    }
    uint32_t a_sum = 0, b_sum = 0, x_sum = 0, y_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        a_sum = f.add(a_sum, triples[i][0].a.value);
        b_sum = f.add(b_sum, triples[i][0].b.value);
        x_sum = f.add(x_sum, xs[i].value);
        y_sum = f.add(y_sum, ys[i].value);
    }
    uint32_t e = f.sub(x_sum, a_sum);
    uint32_t rho = f.sub(y_sum, b_sum);

    auto t0 = std::chrono::steady_clock::now();
    uint32_t checksum = 0;
    for (uint32_t k = 0; k < n_ops; ++k) {
        for (uint32_t i = 0; i < n; ++i) {
            dao_abb_share z;
            ASSERT_TRUE(dao_mpc_abb::beaver_multiply(
                f, i+1, n, xs[i], ys[i], triples[i][k], e, rho, z));
            checksum = f.add(checksum, z.value);
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    std::cout << "[n=16] online-only time (n_ops=" << n_ops << "): "
              << ms << " ms per candidate (checksum=" << checksum << ")\n";

    // Sanity: 100x speedup vs 61s → expect < 1000 ms.
    EXPECT_LT(ms, 1000u) << "online phase should be <1s if diagnosis holds";

    BN_CTX_free(ctx);
}

TEST(dao_mpc_abb, online_only_measurement_n3)
{
    const uint32_t n = 3;
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, n, primes));

    const uint32_t n_ops = (n - 1) * (uint32_t)primes.size() * 2;
    std::cout << "[n=3] online-only multiplies per candidate: " << n_ops << "\n";

    dao_mpc_field f; f.r = primes.back();
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);

    std::vector<std::vector<dao_abb_triple>> triples;
    ASSERT_TRUE(generate_consistent_triples_trusted_dealer(
        n, f.r, n_ops, triples, ctx));

    std::vector<dao_abb_share> xs(n), ys(n);
    for (uint32_t i = 0; i < n; ++i) {
        xs[i].value = (i * 3 + 1) % f.r;
        ys[i].value = (i * 5 + 2) % f.r;
    }
    uint32_t a_sum = 0, b_sum = 0, x_sum = 0, y_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        a_sum = f.add(a_sum, triples[i][0].a.value);
        b_sum = f.add(b_sum, triples[i][0].b.value);
        x_sum = f.add(x_sum, xs[i].value);
        y_sum = f.add(y_sum, ys[i].value);
    }
    uint32_t e = f.sub(x_sum, a_sum);
    uint32_t rho = f.sub(y_sum, b_sum);

    auto t0 = std::chrono::steady_clock::now();
    for (uint32_t k = 0; k < n_ops; ++k) {
        for (uint32_t i = 0; i < n; ++i) {
            dao_abb_share z;
            ASSERT_TRUE(dao_mpc_abb::beaver_multiply(
                f, i+1, n, xs[i], ys[i], triples[i][k], e, rho, z));
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "[n=3] online-only time (n_ops=" << n_ops << "): "
              << ms << " ms per candidate\n";
    EXPECT_LT(ms, 100u);
    BN_CTX_free(ctx);
}
