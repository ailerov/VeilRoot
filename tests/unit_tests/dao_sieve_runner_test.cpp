#include "gtest/gtest.h"
#include <chrono>
#include <openssl/bn.h>
#include <thread>
#include <vector>

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_mpc.h"
#include "governance/dao_mpc_crt.h"
#include "governance/dao_sieve_runner.h"

using namespace cryptonote::dao;

TEST(dao_sieve_runner, full_sieve_129_primes_n3_threads)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 3, primes));
    ASSERT_GT(primes.size(), 100u);
    std::cout << "[sieve-runner] prime count = " << primes.size() << "\n";

    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));

    const uint32_t n = 3, threshold = 2;
    dkg_inproc_network net = dkg_make_inproc_network(n, nullptr);

    uint8_t cid[32];
    for (int i = 0; i < 32; ++i) cid[i] = (uint8_t)(0x40 + i);

    std::vector<BIGNUM*> p_contrib(n, nullptr);
    std::vector<BIGNUM*> q_contrib(n, nullptr);
    std::vector<bool> ok_flags(n, false);
    std::vector<const char*> fail_stages(n, nullptr);

    auto t0 = std::chrono::steady_clock::now();

    std::vector<std::thread> workers;
    for (uint32_t i = 1; i <= n; ++i) {
        workers.emplace_back([&, i]() {
            BN_CTX* ctx = BN_CTX_new();
            if (!ctx) return;
            BIGNUM* pi = BN_new();
            BIGNUM* qi = BN_new();
            if (!pi || !qi) {
                if (pi) BN_free(pi);
                if (qi) BN_free(qi);
                BN_CTX_free(ctx);
                return;
            }
            const char* stage = nullptr;
            const bool ok = dkg_run_sieve_both_runner(
                net.endpoints[i - 1].get(), n, threshold, i, cid,
                /*candidate_id=*/1, primes, grp,
                /*lambda=*/1024, /*sigma=*/80,
                /*phase_timeout_s=*/10, pi, qi, ctx, &stage);
            if (ok) {
                p_contrib[i - 1] = pi;
                q_contrib[i - 1] = qi;
                ok_flags[i - 1] = true;
            } else {
                BN_free(pi); BN_free(qi);
                fail_stages[i - 1] = stage;
            }
            BN_CTX_free(ctx);
        });
    }
    for (auto& w : workers) w.join();

    for (uint32_t i = 0; i < n; ++i) {
        if (!ok_flags[i]) {
            std::cout << "[sieve-runner] party " << (i + 1)
                      << " FAIL at stage: "
                      << (fail_stages[i] ? fail_stages[i] : "(unknown)")
                      << "\n";
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "[sieve-runner] wall time: " << ms << " ms\n";

    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(ok_flags[i])
            << "party " << (i + 1) << " failed at stage: "
            << (fail_stages[i] ? fail_stages[i] : "(unknown)");
    }

    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);
    BIGNUM* aggP = BN_new(); BN_zero(aggP);
    BIGNUM* aggQ = BN_new(); BN_zero(aggQ);
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_NE(p_contrib[i], nullptr);
        ASSERT_NE(q_contrib[i], nullptr);
        BN_add(aggP, aggP, p_contrib[i]);
        BN_add(aggQ, aggQ, q_contrib[i]);
    }

    BIGNUM* lb = BN_new(); BN_one(lb); BN_lshift(lb, lb, 1024);
    BIGNUM* ub = BN_new(); BN_one(ub); BN_lshift(ub, ub, 1104);
    BIGNUM* N = BN_new(); BN_mul(N, aggP, aggQ, ctx);
    std::cout << "[sieve-runner] log2(P)=" << BN_num_bits(aggP)
              << " log2(Q)=" << BN_num_bits(aggQ)
              << " log2(N)=" << BN_num_bits(N) << "\n";
    EXPECT_GE(BN_cmp(aggP, lb), 0);
    EXPECT_LT(BN_cmp(aggP, ub), 0);
    EXPECT_GE(BN_cmp(aggQ, lb), 0);
    EXPECT_LT(BN_cmp(aggQ, ub), 0);

    BIGNUM* nlb = BN_new(); BN_one(nlb); BN_lshift(nlb, nlb, 2048);
    BIGNUM* nub = BN_new(); BN_one(nub); BN_lshift(nub, nub, 2208);
    EXPECT_GE(BN_cmp(N, nlb), 0);
    EXPECT_LT(BN_cmp(N, nub), 0);

    for (uint32_t r : primes) {
        EXPECT_NE(BN_mod_word(aggP, r), 0UL) << "P div by " << r;
        EXPECT_NE(BN_mod_word(aggQ, r), 0UL) << "Q div by " << r;
    }
    EXPECT_EQ(BN_mod_word(aggP, 4), 3UL);
    EXPECT_EQ(BN_mod_word(aggQ, 4), 3UL);

    for (auto* c : p_contrib) BN_free(c);
    for (auto* c : q_contrib) BN_free(c);
    BN_free(aggP); BN_free(aggQ); BN_free(N);
    BN_free(lb); BN_free(ub); BN_free(nlb); BN_free(nub);
    BN_CTX_free(ctx);
}
