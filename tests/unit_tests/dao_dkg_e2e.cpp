// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// End-to-end DKG test with an independent test oracle.
//
// The driver runs the full 16-party Nishide-Sakurai protocol. When a
// candidate passes all gates (biprimality and distributed trial
// division), the driver records out.N. The test oracle then factors
// out.N locally and verifies:
//
//   - N is exactly 128 bits
//   - N == p * q for prime p, q
//   - p = q = 3 mod 4
//   - (p-1)/2 and (q-1)/2 have no small prime factor in {3,5,7,11,13}
//
// The oracle exists ONLY in the test. Production DKG never recovers
// p or q.

#include <cstdint>
#include <cstring>
#include <iostream>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "gtest/gtest.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

// Deterministic OpenSSL RNG seeding for reproducible test runs.
void seed_openssl_rng(uint64_t seed)
{
    unsigned char buf[64];
    for (int i = 0; i < 64; ++i)
        buf[i] = static_cast<unsigned char>((seed >> ((i % 8) * 8)) & 0xff);
    RAND_seed(buf, sizeof(buf));
}

} // namespace

TEST(dao_dkg_e2e, sixteen_party_128bit_with_oracle)
{
    // Deterministic seed for reproducibility.
    seed_openssl_rng(0xC0FFEE);

    dkg_config cfg;
    cfg.committee_size = DAO_DKG_COMMITTEE_SIZE;
    cfg.threshold      = DAO_DKG_THRESHOLD;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 8000;

    auto net = dkg_make_inproc_network(cfg.committee_size, nullptr);

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

    std::cerr << "[dkg-e2e] candidate_accepted=" << out.candidate_accepted
              << " attempts=" << out.candidate_attempts
              << " biprimality_failures=" << out.biprimality_failures
              << " trial_division_failures=" << out.trial_division_failures
              << "\n";

    ASSERT_GT(out.candidate_attempts, 0u)
        << "driver did not run any candidate attempts";

    if (!out.candidate_accepted) {
        // The candidate loop ran but did not find a valid candidate
        // within max_attempts. Report and fail loudly so we know to
        // raise the attempt ceiling or investigate.
        FAIL() << "no candidate accepted within " << out.candidate_attempts
               << " attempts";
    }

    // ---- Independent oracle ----
    //
    // Uses out.test_p and out.test_q, populated by the driver from
    // the party shares under VEILROOT_DAO_DKG_TESTING. Production DKG
    // never exposes these fields.

    ASSERT_FALSE(out.test_p.empty()) << "test_p not populated";
    ASSERT_FALSE(out.test_q.empty()) << "test_q not populated";

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* N = BN_bin2bn(out.N.data(), static_cast<int>(out.N.size()), nullptr);
    BIGNUM* p = BN_bin2bn(out.test_p.data(),
                          static_cast<int>(out.test_p.size()), nullptr);
    BIGNUM* q = BN_bin2bn(out.test_q.data(),
                          static_cast<int>(out.test_q.size()), nullptr);
    ASSERT_NE(N, nullptr);
    ASSERT_NE(p, nullptr);
    ASSERT_NE(q, nullptr);

    EXPECT_EQ(BN_num_bits(N), 128);
    EXPECT_TRUE(BN_is_prime_ex(p, 32, ctx, nullptr))
        << "oracle: p is not prime";
    EXPECT_TRUE(BN_is_prime_ex(q, 32, ctx, nullptr))
        << "oracle: q is not prime";

    BIGNUM* check = BN_new();
    BN_mul(check, p, q, ctx);
    EXPECT_EQ(BN_cmp(check, N), 0) << "oracle: p*q != N";

    BIGNUM* four = BN_new();
    BN_set_word(four, 4);
    BIGNUM* rp = BN_new();
    BIGNUM* rq = BN_new();
    BN_mod(rp, p, four, ctx);
    BN_mod(rq, q, four, ctx);
    BIGNUM* three = BN_new();
    BN_set_word(three, 3);
    EXPECT_EQ(BN_cmp(rp, three), 0) << "oracle: p != 3 mod 4";
    EXPECT_EQ(BN_cmp(rq, three), 0) << "oracle: q != 3 mod 4";

    const uint32_t small[] = { 3, 5, 7, 11, 13 };
    for (uint32_t r : small) {
        BIGNUM* one = BN_new();
        BN_one(one);
        BIGNUM* pm1 = BN_new();
        BIGNUM* qm1 = BN_new();
        BN_sub(pm1, p, one);
        BN_sub(qm1, q, one);
        BIGNUM* half_p = BN_new();
        BIGNUM* half_q = BN_new();
        BN_rshift1(half_p, pm1);
        BN_rshift1(half_q, qm1);

        BIGNUM* r_bn = BN_new();
        BN_set_word(r_bn, r);
        BIGNUM* rem_p = BN_new();
        BIGNUM* rem_q = BN_new();
        BN_mod(rem_p, half_p, r_bn, ctx);
        BN_mod(rem_q, half_q, r_bn, ctx);
        EXPECT_FALSE(BN_is_zero(rem_p))
            << "oracle: (p-1)/2 divisible by " << r;
        EXPECT_FALSE(BN_is_zero(rem_q))
            << "oracle: (q-1)/2 divisible by " << r;

        BN_free(one); BN_free(pm1); BN_free(qm1);
        BN_free(half_p); BN_free(half_q);
        BN_free(r_bn); BN_free(rem_p); BN_free(rem_q);
    }

    BN_free(N); BN_free(p); BN_free(q); BN_free(check);
    BN_free(four); BN_free(rp); BN_free(rq); BN_free(three);
    BN_CTX_free(ctx);

    std::cerr << "[dkg-e2e] oracle passed\n";
}