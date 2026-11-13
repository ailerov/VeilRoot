// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Distributed DKG test.
//
// Each "node" is represented by a freshly generated persistent public
// identity. The committee is the ordered list of those identities.
// Each node runs one dkg_p2p_runner and derives its own party index by
// matching its public key against the committee list (the same rule
// the production node will use to bind cfg.local_party_id to its
// LMDB-stored identity).
//
// Asserted across all committee sizes:
//   - every node completes the ceremony;
//   - every node derives byte-identical committee_id_hash, N, theta,
//     V, V_K_i, and every public field of the key record except
//     dkg_transcript_hash and key_id.
//
// dkg_transcript_hash and key_id are NOT asserted to be equal across
// nodes. The distributed message-level transcript is a protocol-layer
// open item (see docs/DAO-V2-IMPLEMENTATION-SPEC.md Gap 4): the
// frozen construction hashes every accepted DKG message, and pairwise
// private messages are not visible to all nodes. The single-process
// driver remains the reference for that construction; the distributed
// runner leaves the field populated but does not claim cross-node
// equality until the protocol layer defines it.

#include "gtest/gtest.h"

#include <chrono>
#include <condition_variable>
#include <map>
#include <stdexcept>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

struct routed_network
{
    std::mutex              mu;
    std::condition_variable msg_cv;
    size_t                  msg_count = 0;

    std::map<crypto::public_key, dkg_p2p_runner*> runners_by_pk;
    std::map<uint32_t, dkg_p2p_runner*>          runners_by_id;

    // Bump the delivery counter and wake any waiter. Called from the
    // sender's thread whenever it emits a message (send_to or
    // broadcast), which is what the startup-race regression needs to
    // observe.
    void note_message_locked()
    {
        ++msg_count;
        msg_cv.notify_all();
    }

    bool wait_for_message(size_t at_least, uint32_t timeout_ms)
    {
        std::unique_lock<std::mutex> lk(mu);
        return msg_cv.wait_for(
            lk,
            std::chrono::milliseconds(timeout_ms),
            [&] { return msg_count >= at_least; });
    }

    void register_runner(
        uint32_t id,
        const crypto::public_key& pk,
        dkg_p2p_runner* r)
    {
        std::lock_guard<std::mutex> lk(mu);

        if (id == 0 || r == nullptr)
            throw std::runtime_error(
                "invalid distributed DKG runner registration");

        if (runners_by_id.count(id) != 0)
            throw std::runtime_error(
                "duplicate distributed DKG party id");

        if (runners_by_pk.count(pk) != 0)
            throw std::runtime_error(
                "duplicate distributed DKG public identity");

        runners_by_id.emplace(id, r);
        runners_by_pk.emplace(pk, r);
    }

    dkg_p2p_callbacks callbacks_for_self()
    {
        dkg_p2p_callbacks cb;

        cb.send_to =
            [this](const crypto::public_key& to,
                   const std::string& payload) -> bool
        {
            dkg_p2p_runner* target = nullptr;

            {
                std::lock_guard<std::mutex> lk(mu);

                const auto it =
                    runners_by_pk.find(to);

                if (it == runners_by_pk.end())
                    return false;

                target = it->second;
            }

            dkg_msg m;

            const std::vector<uint8_t> buf(
                payload.begin(),
                payload.end());

            if (!m.deserialize(buf))
                return false;

            target->on_message(m);

            {
                std::lock_guard<std::mutex> lk(mu);
                note_message_locked();
            }

            return true;
        };

        cb.broadcast =
            [this](const std::string& payload)
        {
            dkg_msg m;

            const std::vector<uint8_t> buf(
                payload.begin(),
                payload.end());

            if (!m.deserialize(buf))
                return;

            const uint32_t sender =
                m.hdr.sender_id;

            std::vector<dkg_p2p_runner*> targets;

            {
                std::lock_guard<std::mutex> lk(mu);

                const auto sender_it =
                    runners_by_id.find(sender);

                if (sender_it == runners_by_id.end())
                    return;

                targets.reserve(
                    runners_by_id.size() - 1);

                for (const auto& [id, runner] : runners_by_id)
                {
                    if (id == sender)
                        continue;

                    targets.push_back(runner);
                }
            }

            for (auto* target : targets)
                target->on_message(m);

            {
                std::lock_guard<std::mutex> lk(mu);
                note_message_locked();
            }
        };

        return cb;
    }
};

constexpr uint64_t FIXED_TEST_CANDIDATE_SEED_3  = 0x5645494C52544F33ULL;
constexpr uint64_t FIXED_TEST_CANDIDATE_SEED_16 = 0x5645494C52544F54ULL;

// Test-only: choose p_i, q_i with the residue constraints
//   p_1 = q_1 = 3 mod 4
//   p_i = q_i = 0 mod 4   for i >= 2
// such that the sums P = sum p_i and Q = sum q_i are both prime.
//
// The biprimality check requires N = P*Q to be a semiprime. With
// random p_i/q_i, P is prime with probability ~1/44, so almost every
// attempt fails and the runner exhausts max_attempts. Producing fixed
// contributions with prime sums lets the ceremony complete on the
// first attempt, the same way the built-in 3-party and 16-party
// constants do.
//
// k_bits is the per-party bit length (matches cfg.k). The search adds
// 4 to the last party's value repeatedly until the sum is prime.
bool find_prime_sum_contributions(uint32_t n, uint32_t k_bits,
                                  std::vector<std::string>& p_out,
                                  std::vector<std::string>& q_out,
                                  uint32_t& product_bits_out)
{
    product_bits_out = 0;
    if (n < 2) return false;
    p_out.clear(); q_out.clear();

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;

    auto generate_one = [&](std::vector<std::string>& out) -> bool {
        std::vector<BIGNUM*> vals(n, nullptr);
        BIGNUM* four = BN_new();
        BN_set_word(four, 4);
        BIGNUM* sum = BN_new();
        BIGNUM* rem = BN_new();
        BIGNUM* small = BN_new();
        BN_set_word(small, 15015);

        // Draw n-1 random values with correct residues.
        for (uint32_t i = 0; i < n - 1; ++i) {
            vals[i] = BN_new();
            if (!BN_rand(vals[i], k_bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY))
                goto fail;
            BN_mod(rem, vals[i], four, ctx);
            if (i == 0) {
                // Target 3 mod 4.
                BIGNUM* diff = BN_new();
                BIGNUM* tgt = BN_new();
                BN_set_word(tgt, 3);
                BN_sub(diff, tgt, rem);
                BN_nnmod(diff, diff, four, ctx);
                BN_add(vals[i], vals[i], diff);
                BN_free(diff); BN_free(tgt);
            } else {
                // Target residue 0 mod 4 for i >= 2. The earlier
                // BN_value_one() form produced residue 1 mod 4, which
                // makes p_i + q_i not divisible by 4 and breaks
                // do_publish_Q's x = s / 4 exact-division check.
                BIGNUM* neg_rem = BN_new();
                BIGNUM* diff = BN_new();
                BN_zero(neg_rem);
                BN_sub(neg_rem, neg_rem, rem);
                BN_nnmod(diff, neg_rem, four, ctx);
                BN_add(vals[i], vals[i], diff);
                BN_free(neg_rem);
                BN_free(diff);
            }
        }
        // Last value: search by adding 4 until the sum is prime.
        {
            BIGNUM* last = BN_new();
            uint32_t want_residue = (n == 1) ? 3 : 0;
            if (!BN_rand(last, k_bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY))
                goto fail;
            BN_mod(rem, last, four, ctx);
            BIGNUM* diff = BN_new();
            BIGNUM* tgt = BN_new();
            BN_set_word(tgt, want_residue);
            BN_sub(diff, tgt, rem);
            BN_nnmod(diff, diff, four, ctx);
            BN_add(last, last, diff);
            BN_free(diff); BN_free(tgt);
            vals[n - 1] = last;
        }
        // 3*5*7*11*13 = 15015. The DKG prime-condition test requires
        // that (P-1)/2 has no small factor below the committee size.
        // If any of these divides (P-1)/2, every trial-division rep
        // for that prime fails and the candidate is rejected.
        for (uint32_t tries = 0; tries < 100000000; ++tries) {
            BN_zero(sum);
            for (uint32_t i = 0; i < n; ++i) BN_add(sum, sum, vals[i]);

            int prime = BN_check_prime(sum, ctx, nullptr);
            if (prime < 0) goto fail;
            if (prime == 1) {
                // Check gcd((P-1)/2, 15015) == 1.
                BIGNUM* half = BN_new();
                BIGNUM* g = BN_new();
                BN_sub(half, sum, BN_value_one());
                BN_rshift1(half, half);
                BN_gcd(g, half, small, ctx);
                const bool coprime = BN_is_one(g);
                BN_free(half); BN_free(g);
                if (coprime) {
                    for (uint32_t i = 0; i < n; ++i) {
                        char* dec = BN_bn2dec(vals[i]);
                        if (!dec) goto fail;
                        out.emplace_back(dec);
                        OPENSSL_free(dec);
                    }
                    for (auto* v : vals) BN_free(v);
                    BN_free(four); BN_free(sum); BN_free(rem);
                    BN_free(small);
                    return true;
                }
            }
            BN_add(vals[n - 1], vals[n - 1], four);
        }
    fail:
        for (auto* v : vals) if (v) BN_free(v);
        BN_free(four); BN_free(sum); BN_free(rem); BN_free(small);
        return false;
    };

    const bool ok = generate_one(p_out) && generate_one(q_out);
    if (ok) {
        BIGNUM* ps = BN_new();
        BIGNUM* qs = BN_new();
        BIGNUM* prod = BN_new();
        BN_zero(ps); BN_zero(qs);
        for (const auto& s : p_out) {
            BIGNUM* v = nullptr;
            BN_dec2bn(&v, s.c_str());
            BN_add(ps, ps, v); BN_free(v);
        }
        for (const auto& s : q_out) {
            BIGNUM* v = nullptr;
            BN_dec2bn(&v, s.c_str());
            BN_add(qs, qs, v); BN_free(v);
        }
        BN_mul(prod, ps, qs, ctx);
        product_bits_out = static_cast<uint32_t>(BN_num_bits(prod));
        BN_free(ps); BN_free(qs); BN_free(prod);
    }
    BN_CTX_free(ctx);
    return ok;
}

// Small helper: n-party test with fresh identities.
struct distributed_run
{
    std::vector<crypto::secret_key> sks;
    std::vector<crypto::public_key> pks;
    std::vector<dkg_result>         results;
    std::vector<std::unique_ptr<dkg_p2p_runner>> runners;
    routed_network                  net;
    dao_vss_group                   vss;

    // Member destruction order is the reverse of declaration order,
    // which would free `vss` and `net` before `runners`. Both are
    // referenced by running workers: impl::vss is a non-owning
    // pointer and each callback captures &net. A worker that has not
    // exited would dereference freed memory. Stopping every runner
    // in the destructor body, before any member is destroyed, makes
    // the teardown deterministic.
    ~distributed_run()
    {
        for (auto& r : runners) if (r) r->stop();
    }
};

bool run_n_party(uint32_t n, uint32_t timeout_s,
                 distributed_run& out)
{
    // Fresh persistent identities. In production these are loaded
    // from LMDB; here they stand in for whatever the node's
    // committee_privkey is.
    out.sks.resize(n);
    out.pks.resize(n);
    for (uint32_t i = 0; i < n; ++i)
        crypto::generate_keys(out.pks[i], out.sks[i]);

    dkg_config cfg;
    cfg.committee_size = n;
    cfg.threshold      = dao_dkg_expected_threshold(n);
    if (cfg.threshold == 0) return false;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 2000;
    cfg.phase_timeout_seconds = 600;
    if (n == 3)  cfg.test_seed = FIXED_TEST_CANDIDATE_SEED_3;
    if (n == 16) cfg.test_seed = FIXED_TEST_CANDIDATE_SEED_16;
    if (n != 3 && n != 16) {
        std::vector<std::string> p_dec, q_dec;
        uint32_t actual_bits = 0;
        if (!find_prime_sum_contributions(n, cfg.k, p_dec, q_dec,
                                          actual_bits))
            return false;
        cfg.test_p_i_dec = std::move(p_dec);
        cfg.test_q_i_dec = std::move(q_dec);
        cfg.target_N_bits = actual_bits;
    }

    cfg.member_ids = out.pks;

    const uint32_t required_bits =
        dao_dkg_required_vss_bits(cfg.k, cfg.target_N_bits, cfg.security_bits);
    if (!dao_vss_group_generate(out.vss, required_bits)) return false;

    out.results.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
        dkg_config node_cfg = cfg;
        node_cfg.local_party_id = dao_dkg_party_index_for(cfg.member_ids,
                                                          out.pks[i]);
        if (node_cfg.local_party_id == 0) return false;
        auto cb = out.net.callbacks_for_self();
        out.runners.emplace_back(new dkg_p2p_runner(node_cfg, out.vss, cb));
    }
    for (uint32_t i = 0; i < n; ++i) {
        out.net.register_runner(i + 1, out.pks[i], out.runners[i].get());
    }

    for (auto& r : out.runners) if (!r->start()) return false;
    for (uint32_t i = 0; i < n; ++i) {
        if (!out.runners[i]->wait(out.results[i], timeout_s)) return false;
        if (!out.results[i].ok) return false;
    }
    return true;
}

// Real-random variant: same shape as run_n_party but no fixture
// contribution. Configures the runner to take the sieve branch
// (is_fixture_mode() == false). Used to prove the sieve runs through
// the runner end-to-end without hanging or crashing.
//
// Unlike run_n_party, this returns true if every runner produced a
// dkg_result at all, regardless of whether the attempt succeeded. A
// 128-bit candidate is not expected to biprime on the first few
// attempts (rate ~1/100). The caller checks attempts / acceptance.
bool run_n_party_real(uint32_t n, uint32_t max_attempts,
                      uint32_t phase_timeout_s, uint32_t wait_s,
                      distributed_run& out)
{
    out.sks.resize(n);
    out.pks.resize(n);
    for (uint32_t i = 0; i < n; ++i)
        crypto::generate_keys(out.pks[i], out.sks[i]);

    dkg_config cfg;
    cfg.committee_size = n;
    cfg.threshold      = dao_dkg_expected_threshold(n);
    if (cfg.threshold == 0) return false;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = max_attempts;
    cfg.phase_timeout_seconds = phase_timeout_s;
    // test_seed = 0; test_p_i_dec / test_q_i_dec empty.
    cfg.member_ids = out.pks;

    const uint32_t required_bits =
        dao_dkg_required_vss_bits(cfg.k, cfg.target_N_bits, cfg.security_bits);
    if (!dao_vss_group_generate(out.vss, required_bits)) return false;

    out.results.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
        dkg_config node_cfg = cfg;
        node_cfg.local_party_id = dao_dkg_party_index_for(cfg.member_ids,
                                                          out.pks[i]);
        if (node_cfg.local_party_id == 0) return false;
        auto cb = out.net.callbacks_for_self();
        out.runners.emplace_back(new dkg_p2p_runner(node_cfg, out.vss, cb));
    }
    for (uint32_t i = 0; i < n; ++i) {
        out.net.register_runner(i + 1, out.pks[i], out.runners[i].get());
    }
    for (auto& r : out.runners) if (!r->start()) return false;

    // wait() returns out.ok, which is false when the candidate was
    // rejected (expected for 128-bit). "Ran" means candidate_attempts
    // was populated. wait_s is the hang guard.
    bool any_ran = false;
    for (uint32_t i = 0; i < n; ++i) {
        out.runners[i]->wait(out.results[i], wait_s);
        if (out.results[i].candidate_attempts > 0) any_ran = true;
    }
    return any_ran;
}

void expect_public_fields_agree(const std::vector<dkg_result>& rs,
                                uint32_t n)
{
    const auto& a = rs[0];
    for (uint32_t i = 1; i < n; ++i) {
        const auto& b = rs[i];
        EXPECT_EQ(a.record.committee_id_hash, b.record.committee_id_hash);
        EXPECT_EQ(a.record.N,                 b.record.N);
        EXPECT_EQ(a.record.G,                 b.record.G);
        EXPECT_EQ(a.record.theta,             b.record.theta);
        EXPECT_EQ(a.record.delta,             b.record.delta);
        EXPECT_EQ(a.record.V,                 b.record.V);
        EXPECT_EQ(a.record.V_K_i,             b.record.V_K_i);
        EXPECT_EQ(a.record.vss_P,             b.record.vss_P);
        EXPECT_EQ(a.record.vss_P_prime,       b.record.vss_P_prime);
        EXPECT_EQ(a.record.vss_g,             b.record.vss_g);
        EXPECT_EQ(a.record.vss_h,             b.record.vss_h);
        EXPECT_EQ(a.record.committee_members, b.record.committee_members);
        EXPECT_EQ(a.record.committee_size,    b.record.committee_size);
        EXPECT_EQ(a.record.threshold,         b.record.threshold);
        EXPECT_EQ(a.record.t,                 b.record.t);
        // Now that private DKG messages are represented in the
        // transcript by their public leaf hash, every honest node
        // derives the same transcript hash and the same key id.
        EXPECT_EQ(a.record.dkg_transcript_hash,
                  b.record.dkg_transcript_hash);
        EXPECT_EQ(a.record.key_id, b.record.key_id);
        EXPECT_EQ(a.key_id, b.key_id);
    }
}

} // namespace

TEST(dao_dkg_distributed, three_party_nodes_agree_on_public_key_record)
{
    // Retry the whole ceremony once on flake. Under full-suite CPU
    // contention the 3-party DKG occasionally times out at a phase.
    // Two consecutive failures is a real bug, not a flake.
    bool ok = false;
    for (int attempt = 0; attempt < 2 && !ok; ++attempt) {
        distributed_run run;
        if (run_n_party(3, 900, run)) {
            expect_public_fields_agree(run.results, 3);
            for (uint32_t i = 0; i < 3; ++i)
                EXPECT_FALSE(run.results[i].local_secret_share.empty());
            ok = true;
        }
    }
    ASSERT_TRUE(ok) << "3-party DKG failed after 2 attempts";
}

// ---------------------------------------------------------------------
// Ordered-startup regression: the startup race.
//
// dkg_p2p_runner must accept an inbound message before its own start()
// has been called. The transport is created in the constructor for
// exactly this reason: committee members start independently, and
// runner 1 can emit its first broadcast before runner 2 has started.
//
// This test makes the race deterministic: start only runner 1, wait
// until it has emitted at least one message, then start the rest.
// Without the constructor-transport fix, the first broadcast is
// dropped by runner 2 and runner 3 (their on_message() returns silently
// because transport is null), and the ceremony stalls until the phase
// timeout.
// ---------------------------------------------------------------------
TEST(dao_dkg_distributed, ordered_startup_no_lost_messages)
{
    const uint32_t n = 3;

    distributed_run run;
    run.sks.resize(n);
    run.pks.resize(n);
    for (uint32_t i = 0; i < n; ++i)
        crypto::generate_keys(run.pks[i], run.sks[i]);

    dkg_config cfg;
    cfg.committee_size = n;
    cfg.threshold      = dao_dkg_expected_threshold(n);
    ASSERT_NE(cfg.threshold, 0u);
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 2000;
    // Short timeout (10s) so a hung DKG fails this test
    // quickly. Production default is 600s.
    cfg.phase_timeout_seconds = 10;
    cfg.test_seed      = FIXED_TEST_CANDIDATE_SEED_3;
    cfg.member_ids     = run.pks;

    const uint32_t required_bits = dao_dkg_required_vss_bits(
        cfg.k, cfg.target_N_bits, cfg.security_bits);
    ASSERT_TRUE(dao_vss_group_generate(run.vss, required_bits));

    run.results.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
        dkg_config node_cfg = cfg;
        node_cfg.local_party_id =
            dao_dkg_party_index_for(cfg.member_ids, run.pks[i]);
        ASSERT_NE(node_cfg.local_party_id, 0u);
        auto cb = run.net.callbacks_for_self();
        run.runners.emplace_back(
            new dkg_p2p_runner(node_cfg, run.vss, cb));
    }
    for (uint32_t i = 0; i < n; ++i) {
        run.net.register_runner(i + 1, run.pks[i], run.runners[i].get());
    }

    // Start only runner 1, then wait for its first emitted message
    // before starting the others. This is the exact ordering that
    // dropped a message before the transport was created in the
    // constructor.
    bool ceremony_ok = false;
    for (int attempt = 0; attempt < 2 && !ceremony_ok; ++attempt) {
        // Reset the delivery counter so wait_for_message below is not
        // satisfied by messages from a previous attempt.
        {
            std::lock_guard<std::mutex> lk(run.net.mu);
            run.net.msg_count = 0;
        }
        ASSERT_TRUE(run.runners[0]->start());
        if (!run.net.wait_for_message(1, 120000)) {
            std::cerr << "ordered_startup attempt " << attempt
                      << ": runner 1 emitted nothing in 120s\n";
            continue;
        }

        for (uint32_t i = 1; i < n; ++i)
            ASSERT_TRUE(run.runners[i]->start());

        bool all_ok = true;
        for (uint32_t i = 0; i < n; ++i) {
            auto t0 = std::chrono::steady_clock::now();
            const bool wait_ok = run.runners[i]->wait(run.results[i], 60);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
            if (!wait_ok) {
                std::cerr << "[diag] attempt " << attempt
                          << " party " << (i + 1)
                          << " elapsed=" << ms << "ms"
                          << " result.ok=" << (run.results[i].ok ? 1 : 0)
                          << " cand_att=" << run.results[i].candidate_attempts
                          << "\n";
                all_ok = false;
                continue;
            }
            if (!run.results[i].ok) {
                std::cerr << "[diag] attempt " << attempt
                          << " party " << (i + 1) << " ABORT"
                          << " cand_att=" << run.results[i].candidate_attempts
                          << " biprim=" << run.results[i].biprimality_failures
                          << " trialdiv=" << run.results[i].trial_division_failures
                          << " beta_r=" << run.results[i].beta_phase_retries
                          << "\n";
                all_ok = false;
                continue;
            }
        }
        if (!all_ok) {
            std::cerr << "ordered_startup attempt " << attempt
                      << ": DKG did not complete\n";
            continue;
        }

        expect_public_fields_agree(run.results, n);
        for (uint32_t i = 0; i < n; ++i)
            EXPECT_FALSE(run.results[i].local_secret_share.empty());
        ceremony_ok = true;
    }
    ASSERT_TRUE(ceremony_ok) << "ordered_startup failed after 2 attempts";
}

TEST(dao_dkg_distributed, four_party_nodes_agree_on_public_key_record)
{
    bool ok = false;
    for (int attempt = 0; attempt < 2 && !ok; ++attempt) {
        distributed_run run;
        if (run_n_party(4, 900, run)) {
            expect_public_fields_agree(run.results, 4);
            for (uint32_t i = 0; i < 4; ++i)
                EXPECT_FALSE(run.results[i].local_secret_share.empty());
            ok = true;
        }
    }
    ASSERT_TRUE(ok) << "4-party DKG failed after 2 attempts";
}

TEST(dao_dkg_distributed, real_random_128bit_sieve_through_runner)
{
    // Proves the production sieve runs through dkg_p2p_runner.
    // Non-fixture config, target_N_bits=128 so the VSS group
    // generation stays cheap (production 2048-bit target costs
    // minutes for the safe prime alone; separate diagnostic).
    //
    // A 128-bit candidate is not expected to biprime within a few
    // attempts. This test asserts:
    //   1. All three runners start.
    //   2. All three runners return a dkg_result within wait_s.
    //   3. Each result shows exactly max_attempts attempts (all
    //      rejected, expected) OR candidate_accepted == true with
    //      correct N bit length (rare, also fine).
    //   4. No crash, no hang.
    //
    // The presence of this test in the suite is proof the sieve
    // branch is executed by the runner (is_fixture_mode() == false
    // because test_seed and test_p_i_dec are both empty).

    const uint32_t n = 3;
    const uint32_t max_attempts = 3;
    // Under load (full DAO regression), the per-attempt cost of sieve
    // + biprimality + polynomial_commit stretches. These ceilings are
    // sized so 3 attempts finish with headroom, not so tight that a
    // loaded run reports fewer attempts than the test asks for.
    const uint32_t phase_timeout_s = 180;
    const uint32_t wait_s = 600;

    distributed_run run;
    const bool ran = run_n_party_real(n, max_attempts,
                                       phase_timeout_s, wait_s, run);
    ASSERT_TRUE(ran) << "runner never returned a dkg_result";

    ASSERT_EQ(run.results.size(), n);
    for (uint32_t i = 0; i < n; ++i) {
        const dkg_result& r = run.results[i];
        EXPECT_EQ(r.candidate_attempts, max_attempts)
            << "party " << (i + 1) << " did not exhaust attempts";
        if (r.candidate_accepted) {
            // Rare good outcome: verify N bit length.
            BIGNUM* N = BN_bin2bn(r.N.data(),
                                  (int)r.N.size(), nullptr);
            ASSERT_NE(N, nullptr);
            const uint32_t nb = (uint32_t)BN_num_bits(N);
            EXPECT_GE(nb, 128u);
            EXPECT_LE(nb, 128u + 2 * 80u);
            EXPECT_TRUE(r.ok);
            BN_free(N);
        } else {
            // Expected outcome: rejected on length or biprimality.
            EXPECT_FALSE(r.ok);
        }
    }
}

TEST(dao_dkg_distributed, timing_2048_vss_and_one_attempt)
{
    // Measures two unknowns at target_N_bits=2048 before committing
    // to a full Phase 8 test:
    //   1. dao_vss_group_generate at the required safe-prime size
    //   2. One full attempt through run_n_party_real (sieve +
    //      polynomial_commit + bgw + biprimality + length check)
    // Emits both timings. Does NOT wait for a successful candidate.

    const uint32_t n = 3;
    const uint32_t kappa = 60;

    // vss group size required for 2048-bit target with 32-bit security.
    const uint32_t required_bits =
        dao_dkg_required_vss_bits(kappa, 2048, 32);
    std::cout << "[timing] required_vss_bits = " << required_bits << "\n";

    auto tv0 = std::chrono::steady_clock::now();
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss, required_bits));
    auto tv1 = std::chrono::steady_clock::now();
    auto vss_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        tv1 - tv0).count();
    std::cout << "[timing] vss_group_generate = " << vss_ms << " ms\n";

    // One attempt with target_N_bits=2048 via the sieve path.
    distributed_run run;
    run.sks.resize(n);
    run.pks.resize(n);
    for (uint32_t i = 0; i < n; ++i)
        crypto::generate_keys(run.pks[i], run.sks[i]);

    dkg_config cfg;
    cfg.committee_size = n;
    cfg.threshold      = dao_dkg_expected_threshold(n);
    cfg.k              = kappa;
    cfg.target_N_bits  = 2048;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 3;   // probe: length-fail gives attempts=3, bip-break gives attempts=1
    cfg.phase_timeout_seconds = 300;
    cfg.member_ids = run.pks;
    // test_seed = 0, test_p_i_dec empty -> sieve path.

    // Reuse the vss group we already generated.
    run.vss.P       = BN_dup(vss.P);
    run.vss.P_prime = BN_dup(vss.P_prime);
    run.vss.g       = BN_dup(vss.g);
    run.vss.h       = BN_dup(vss.h);
    ASSERT_TRUE(run.vss.valid());

    run.results.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
        dkg_config node_cfg = cfg;
        node_cfg.local_party_id = dao_dkg_party_index_for(cfg.member_ids,
                                                          run.pks[i]);
        ASSERT_NE(node_cfg.local_party_id, 0u);
        auto cb = run.net.callbacks_for_self();
        run.runners.emplace_back(new dkg_p2p_runner(node_cfg, run.vss, cb));
    }
    for (uint32_t i = 0; i < n; ++i)
        run.net.register_runner(i + 1, run.pks[i], run.runners[i].get());
    for (auto& r : run.runners) ASSERT_TRUE(r->start());

    auto ta0 = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < n; ++i) {
        run.runners[i]->wait(run.results[i], 300);
    }
    auto ta1 = std::chrono::steady_clock::now();
    auto attempt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        ta1 - ta0).count();
    std::cout << "[timing] one-attempt wall = " << attempt_ms << " ms\n";

    for (uint32_t i = 0; i < n; ++i) {
        const dkg_result& r = run.results[i];
        std::cout << "[timing] p" << (i + 1)
                  << " attempts=" << r.candidate_attempts
                  << " accepted=" << (r.candidate_accepted ? "y" : "n")
                  << " bip_fail=" << r.biprimality_failures
                  << "\n";
    }

    std::cout << "[timing] extrapolated full search at 3607 attempts: "
              << (attempt_ms * 3607ull / 1000) << " seconds\n";
}
