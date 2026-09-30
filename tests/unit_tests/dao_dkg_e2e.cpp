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
#include <cstdlib>

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
    // OpenSSL 3.x seeds its DRBG from OS entropy at process start;
    // RAND_seed only mixes in additional entropy. Runs are therefore
    // not byte-for-byte reproducible, and the test must tolerate
    // RNG-dependent variance in the candidate search.
    seed_openssl_rng(0xC0FFEE);

    dkg_config cfg;
    cfg.committee_size = DAO_DKG_COMMITTEE_SIZE;
    cfg.threshold      = DAO_DKG_THRESHOLD;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = 32;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F54ULL;   // fixed candidate

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

// ====================================================================
// Decryption round-trip against DKG-derived shares
//
// Runs the full DKG to obtain SK_i for all 16 parties and the public
// theta. Then:
//   - verifies theta == Delta * phi * beta mod N against the oracle
//   - encrypts a known plaintext
//   - partial-decrypts with 8 of 16 SK_i
//   - combines and finalizes with theta
//   - confirms the plaintext recovers exactly
//
// This is the end-to-end test that proves the entire §5 chain.
// ====================================================================

TEST(dao_dkg_e2e, decryption_roundtrip)
{
    seed_openssl_rng(0xFACE);

    dkg_config cfg;
    cfg.committee_size = DAO_DKG_COMMITTEE_SIZE;
    cfg.threshold      = DAO_DKG_THRESHOLD;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = 32;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F54ULL;   // fixed candidate

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

    ASSERT_TRUE(out.ok) << "DKG did not complete";
    ASSERT_TRUE(out.candidate_accepted);
    ASSERT_EQ(out.test_SK.size(), DAO_DKG_COMMITTEE_SIZE);

    // Rebuild Paillier public key from the record.
    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    // --- Oracle 1: theta == Delta * phi * beta mod N ---
    {
        BIGNUM* phi = BN_bin2bn(out.test_phi.data(),
                                static_cast<int>(out.test_phi.size()), nullptr);
        BIGNUM* beta = BN_bin2bn(out.test_beta.data(),
                                 static_cast<int>(out.test_beta.size()), nullptr);
        BIGNUM* prod = BN_new();
        BN_mul(prod, phi, beta, ctx);
        BN_mul(prod, prod, dao_dkg_delta(), ctx);
        BIGNUM* theta_exp = BN_new();
        BN_nnmod(theta_exp, prod, pk.N(), ctx);

        BIGNUM* theta_rec = BN_bin2bn(out.record.theta.data(),
                                      static_cast<int>(out.record.theta.size()),
                                      nullptr);
        EXPECT_EQ(BN_cmp(theta_exp, theta_rec), 0)
            << "theta does not match Delta*phi*beta mod N";

        BN_free(phi); BN_free(beta); BN_free(prod);
        BN_free(theta_exp); BN_free(theta_rec);
    }

    // --- Encrypt a known plaintext ---
    BIGNUM* M = BN_new();
    BN_set_word(M, 123456789);
    BIGNUM* r = BN_new();
    BN_set_word(r, 7);

    std::vector<uint8_t> c;
    ASSERT_TRUE(pk.encrypt(M, r, c));

    // --- Parse all 16 SK_i once ---
    std::vector<BIGNUM*> sk_all(DAO_DKG_COMMITTEE_SIZE, nullptr);
    for (size_t j = 0; j < DAO_DKG_COMMITTEE_SIZE; ++j) {
        const std::string dec(out.test_SK[j].begin(), out.test_SK[j].end());
        ASSERT_EQ(BN_dec2bn(&sk_all[j], dec.c_str()),
                  static_cast<int>(dec.size()))
            << "failed to parse SK_" << (j + 1);
        ASSERT_NE(sk_all[j], nullptr);
    }

    // --- Precompute all 16 partial decryptions of the same ciphertext ---
    std::vector<std::vector<uint8_t>> all_partials(DAO_DKG_COMMITTEE_SIZE);
    for (size_t j = 0; j < DAO_DKG_COMMITTEE_SIZE; ++j) {
        ASSERT_TRUE(dao_threshold_partial_decrypt(pk, c, sk_all[j],
                                                  all_partials[j]))
            << "partial_decrypt failed at j=" << (j + 1);
    }

    BIGNUM* theta = BN_bin2bn(out.record.theta.data(),
                              static_cast<int>(out.record.theta.size()),
                              nullptr);
    ASSERT_NE(theta, nullptr);

    // --- Round trip: one 8-of-16 subset ---
    {
        std::vector<uint32_t> subset = { 1, 2, 3, 4, 5, 6, 7, 8 };
        std::vector<std::vector<uint8_t>> partials;
        for (uint32_t j : subset) partials.push_back(all_partials[j - 1]);

        std::vector<uint8_t> C;
        ASSERT_TRUE(dao_threshold_combine(pk, subset, partials, C));

        BIGNUM* M_rec = BN_new();
        ASSERT_TRUE(dao_threshold_finalize(pk, C, theta, M_rec));
        EXPECT_EQ(BN_cmp(M, M_rec), 0) << "plaintext round-trip failed";
        BN_free(M_rec);
    }

    // --- 7-of-16 must be rejected ---
    {
        std::vector<uint32_t> subset7 = { 1, 2, 3, 4, 5, 6, 7 };
        std::vector<std::vector<uint8_t>> partials7;
        for (uint32_t j : subset7) partials7.push_back(all_partials[j - 1]);
        std::vector<uint8_t> C7;
        EXPECT_FALSE(dao_threshold_combine(pk, subset7, partials7, C7));
    }

    // --- Oracle 3: V_K_i == V^(Delta * SK_i) mod N^2 ---
    {
        BIGNUM* V = BN_bin2bn(out.record.V.data(),
                              static_cast<int>(out.record.V.size()), nullptr);
        ASSERT_NE(V, nullptr);
        BIGNUM* N2 = BN_new();
        BN_sqr(N2, pk.N(), ctx);

        for (size_t j = 0; j < DAO_DKG_COMMITTEE_SIZE; ++j) {
            BIGNUM* exp = BN_new();
            BN_mul(exp, dao_dkg_delta(), sk_all[j], ctx);

            BIGNUM* expected = BN_new();
            if (BN_is_negative(exp)) {
                BIGNUM* Vinv = BN_mod_inverse(nullptr, V, N2, ctx);
                BIGNUM* pos = BN_dup(exp);
                BN_set_negative(pos, 0);
                BN_mod_exp(expected, Vinv, pos, N2, ctx);
                BN_free(Vinv); BN_free(pos);
            } else {
                BN_mod_exp(expected, V, exp, N2, ctx);
            }

            std::vector<uint8_t> exp_bytes(PAILLIER_CT_BYTES, 0);
            BN_bn2binpad(expected, exp_bytes.data(), PAILLIER_CT_BYTES);
            EXPECT_EQ(exp_bytes, out.record.V_K_i[j])
                << "V_K_" << (j + 1) << " does not match V^(Delta*SK_i)";

            BN_free(exp); BN_free(expected);
        }
        BN_free(V); BN_free(N2);
    }

    // --- Oracle 4: any 8 SK_i interpolate to F(0) mod N == N - theta ---
    {
        // Modular Lagrange interpolation at x=0 of 8 SK_i over Z_N.
        // F(0) = -Delta*phi*beta, so F(0) mod N = N - theta.
        std::vector<uint32_t> subset = { 1, 3, 5, 7, 9, 11, 13, 15 };

        BIGNUM* result = BN_new();
        BN_zero(result);
        for (size_t k = 0; k < subset.size(); ++k) {
            BIGNUM* num = BN_new();
            BIGNUM* den = BN_new();
            BN_one(num); BN_one(den);
            for (size_t m = 0; m < subset.size(); ++m) {
                if (m == k) continue;
                BIGNUM* jj = BN_new();
                BN_set_word(jj, subset[m]);
                BN_mul(num, num, jj, ctx);
                BN_set_negative(num, !BN_is_negative(num));
                BN_free(jj);

                BIGNUM* diff = BN_new();
                BN_set_word(diff, subset[k]);
                BIGNUM* jj2 = BN_new();
                BN_set_word(jj2, subset[m]);
                BN_sub(diff, diff, jj2);
                BN_mul(den, den, diff, ctx);
                BN_free(diff); BN_free(jj2);
            }
            BIGNUM* term = BN_new();
            BN_mul(term, sk_all[subset[k] - 1], num, ctx);
            BIGNUM* den_inv = BN_mod_inverse(nullptr, den, pk.N(), ctx);
            BN_mul(term, term, den_inv, ctx);
            BN_nnmod(term, term, pk.N(), ctx);
            BN_add(result, result, term);
            BN_nnmod(result, result, pk.N(), ctx);
            BN_free(num); BN_free(den); BN_free(term); BN_free(den_inv);
        }

        BIGNUM* expected = BN_new();
        BN_sub(expected, pk.N(), theta);
        EXPECT_EQ(BN_cmp(result, expected), 0)
            << "8 SK_i do not interpolate to N - theta";

        BN_free(result); BN_free(expected);
    }

    // --- Exhaustive: all C(16,8) = 12870 subsets decrypt correctly ---
    {
        std::vector<int> idx = { 0, 1, 2, 3, 4, 5, 6, 7 };
        int tested = 0;
        while (true) {
            std::vector<uint32_t> subset;
            std::vector<std::vector<uint8_t>> partials;
            for (int k : idx) {
                subset.push_back(static_cast<uint32_t>(k + 1));
                partials.push_back(all_partials[k]);
            }

            std::vector<uint8_t> C;
            ASSERT_TRUE(dao_threshold_combine(pk, subset, partials, C));

            BIGNUM* M_rec = BN_new();
            ASSERT_TRUE(dao_threshold_finalize(pk, C, theta, M_rec));
            ASSERT_EQ(BN_cmp(M, M_rec), 0)
                << "subset round-trip failed at combination #" << tested;
            BN_free(M_rec);
            ++tested;

            int i = 7;
            while (i >= 0 && idx[i] == i + 8) --i;
            if (i < 0) break;
            ++idx[i];
            for (int j = i + 1; j < 8; ++j) idx[j] = idx[j - 1] + 1;
        }
        EXPECT_EQ(tested, 12870);
        std::cerr << "[dkg-e2e] exhaustive subsets tested: " << tested << "\n";
    }

    for (auto* s : sk_all) if (s) BN_free(s);
    BN_free(M); BN_free(r); BN_free(theta);
    BN_CTX_free(ctx);
}

// Randomized candidate search. Disabled by default; run manually with
// VEILROOT_DAO_DKG_SLOW=1 to exercise the production candidate loop
// and measure its timing behaviour.
TEST(dao_dkg_e2e, DISABLED_sixteen_party_128bit_randomized_smoke)
{
    const char* slow = std::getenv("VEILROOT_DAO_DKG_SLOW");
    if (!slow || std::strcmp(slow, "1") != 0) {
        GTEST_SKIP() << "slow randomized DKG test disabled";
    }

    dkg_config cfg;
    cfg.committee_size = DAO_DKG_COMMITTEE_SIZE;
    cfg.threshold      = DAO_DKG_THRESHOLD;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = 2;
    cfg.max_attempts   = 100000;
    // no test_seed: use the production randomized candidate loop

    auto net = dkg_make_inproc_network(cfg.committee_size, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : net.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    dkg_result out;
    const auto t0 = std::chrono::steady_clock::now();
    dkg_run_with_transport(cfg, factory, out);
    const auto t1 = std::chrono::steady_clock::now();

    std::cerr << "[dkg-smoke] elapsed="
              << std::chrono::duration_cast<std::chrono::seconds>(t1 - t0).count()
              << "s attempts=" << out.candidate_attempts
              << " biprimality_failures=" << out.biprimality_failures
              << " trial_division_failures=" << out.trial_division_failures
              << " accepted=" << out.candidate_accepted << "\n";

    ASSERT_GT(out.candidate_attempts, 0u);
}

// Inject a tamper hook that corrupts the first beta range proof it
// sees. The driver must reject the DKG when verification runs.
TEST(dao_dkg_e2e, tampered_range_proof_aborts)
{
    dkg_config cfg;
    cfg.committee_size = DAO_DKG_COMMITTEE_SIZE;
    cfg.threshold      = DAO_DKG_THRESHOLD;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = 32;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F54ULL;

    int tampered = 0;
    auto hook = [&tampered](dkg_msg& m) {
        if (tampered) return;
        if (m.hdr.type != dkg_msg_type::beta_range_proof) return;
        if (m.bytes_a.empty()) return;
        m.bytes_a[0] ^= 0x01;
        ++tampered;
    };

    auto net = dkg_make_inproc_network(cfg.committee_size, hook);

    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : net.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    dkg_result out;
    dkg_run_with_transport(cfg, factory, out);

    EXPECT_EQ(tampered, 1) << "hook did not fire on a range proof";
    EXPECT_FALSE(out.ok) << "DKG accepted a tampered range proof";
}

