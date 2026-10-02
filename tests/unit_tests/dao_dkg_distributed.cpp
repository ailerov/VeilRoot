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

#include <map>
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
    std::mutex mu;
    std::map<crypto::public_key, dkg_p2p_runner*> runners;
    std::map<uint32_t, crypto::public_key>        id_to_pk;

    void register_runner(const crypto::public_key& pk, dkg_p2p_runner* r)
    {
        std::lock_guard<std::mutex> lk(mu);
        runners[pk] = r;
    }

    void register_id(uint32_t id, const crypto::public_key& pk)
    {
        std::lock_guard<std::mutex> lk(mu);
        id_to_pk[id] = pk;
    }

    dkg_p2p_callbacks callbacks_for_self()
    {
        dkg_p2p_callbacks cb;
        cb.send_to = [this](const crypto::public_key& to,
                            const std::string& payload) -> bool {
            dkg_p2p_runner* target = nullptr;
            {
                std::lock_guard<std::mutex> lk(mu);
                auto it = runners.find(to);
                if (it == runners.end()) return false;
                target = it->second;
            }
            dkg_msg m;
            std::vector<uint8_t> buf(payload.begin(), payload.end());
            if (!m.deserialize(buf)) return false;
            target->on_message(m);
            return true;
        };
        cb.broadcast = [this](const std::string& payload) {
            dkg_msg m;
            std::vector<uint8_t> buf(payload.begin(), payload.end());
            if (!m.deserialize(buf)) return;
            // Broadcast from sender to peers only; matches
            // dkg_inproc_hub::route. The runner injects its own
            // broadcast locally.
            crypto::public_key sender_pk;
            bool have_sender = false;
            {
                std::lock_guard<std::mutex> lk(mu);
                auto it = id_to_pk.find(m.hdr.sender_id);
                if (it != id_to_pk.end()) {
                    sender_pk = it->second;
                    have_sender = true;
                }
            }
            std::vector<dkg_p2p_runner*> targets;
            {
                std::lock_guard<std::mutex> lk(mu);
                for (auto& [pk, r] : runners)
                    if (!have_sender || !(pk == sender_pk))
                        targets.push_back(r);
            }
            for (auto* r : targets) r->on_message(m);
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
                BIGNUM* diff = BN_new();
                BN_sub(diff, BN_value_one(), rem);
                BN_nnmod(diff, diff, four, ctx);
                BN_add(vals[i], vals[i], diff);
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
        for (uint32_t tries = 0; tries < 1000000; ++tries) {
            BN_zero(sum);
            for (uint32_t i = 0; i < n; ++i) BN_add(sum, sum, vals[i]);
            int prime = BN_check_prime(sum, ctx, nullptr);
            if (prime == 1) {
                for (uint32_t i = 0; i < n; ++i) {
                    char* dec = BN_bn2dec(vals[i]);
                    if (!dec) goto fail;
                    out.emplace_back(dec);
                    OPENSSL_free(dec);
                }
                for (auto* v : vals) BN_free(v);
                BN_free(four); BN_free(sum); BN_free(rem);
                return true;
            }
            if (prime < 0) goto fail;
            BN_add(vals[n - 1], vals[n - 1], four);
        }
    fail:
        for (auto* v : vals) if (v) BN_free(v);
        BN_free(four); BN_free(sum); BN_free(rem);
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
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 2000;
    cfg.phase_timeout_seconds = 20;
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
        out.net.register_runner(out.pks[i], out.runners[i].get());
        out.net.register_id(i + 1, out.pks[i]);
    }

    for (auto& r : out.runners) if (!r->start()) return false;
    for (uint32_t i = 0; i < n; ++i) {
        if (!out.runners[i]->wait(out.results[i], timeout_s)) return false;
        if (!out.results[i].ok) return false;
    }
    return true;
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
        EXPECT_EQ(a.record.epoch,             b.record.epoch);
        // dkg_transcript_hash and key_id are intentionally not
        // asserted equal here. See file header.
    }
}

} // namespace

TEST(dao_dkg_distributed, three_party_nodes_agree_on_public_key_record)
{
    distributed_run run;
    ASSERT_TRUE(run_n_party(3, 240, run));
    expect_public_fields_agree(run.results, 3);

    for (uint32_t i = 0; i < 3; ++i)
        EXPECT_FALSE(run.results[i].local_secret_share.empty());
}

TEST(dao_dkg_distributed, four_party_nodes_agree_on_public_key_record)
{
    distributed_run run;
    ASSERT_TRUE(run_n_party(4, 300, run));
    expect_public_fields_agree(run.results, 4);

    for (uint32_t i = 0; i < 4; ++i)
        EXPECT_FALSE(run.results[i].local_secret_share.empty());
}
