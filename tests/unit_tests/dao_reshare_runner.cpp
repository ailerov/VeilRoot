// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// P2P resharing runner test.
//
// Three nodes are the new committee (indices 4, 5, 6). Two old
// shareholders (indices 1, 2) publish deals. Each new-member runner
// collects both deals, verifies its own share, derives the full
// share-set record (VKs are public), and publishes a complete. All
// three must derive an identical record.

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_paillier.h"
#include "governance/dao_reshare_pipeline.h"
#include "crypto/crypto.h"

#include <openssl/bn.h>

#include <memory>
#include <string>
#include <vector>

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

struct BNFree {
    void operator()(BIGNUM* p) const { if (p) BN_free(p); }
};
using BN_ptr = std::unique_ptr<BIGNUM, BNFree>;

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
    for (int i = 0; i < 3; ++i) {
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

BN_ptr bn_from_dec(const std::string& s)
{
    BIGNUM* b = nullptr;
    if (BN_dec2bn(&b, s.c_str()) == 0) {
        if (b) BN_free(b);
        return BN_ptr();
    }
    return BN_ptr(b);
}

std::vector<uint8_t> mu_signed(const BIGNUM* m)
{
    std::vector<uint8_t> out(1 + 512, 0);
    out[0] = BN_is_negative(m) ? 1 : 0;
    BIGNUM* a = BN_dup(m); BN_set_negative(a, 0);
    BN_bn2binpad(a, out.data() + 1, 512);
    BN_free(a);
    return out;
}

} // namespace

TEST(DaoReshareRunner, ThreeNewMembersAgree)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    BIGNUM* delta_raw = BN_new();
    BN_dec2bn(&delta_raw, "20922789888000");
    BN_ptr delta(delta_raw);
    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);

    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new()), mu2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 2, mu2.get()));
    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    BN_ptr s2 = bn_from_dec(std::string(out.test_SK[1].begin(),
                                         out.test_SK[1].end()));
    ASSERT_NE(s1, nullptr);
    ASSERT_NE(s2, nullptr);

    std::vector<crypto::public_key> c_pks;
    std::vector<crypto::secret_key> c_sks;
    for (int i = 0; i < 2; ++i) {
        crypto::public_key p; crypto::secret_key s;
        crypto::generate_keys(p, s);
        c_pks.push_back(p);
        c_sks.push_back(s);
    }
    std::vector<uint32_t> c_idx = {1, 2};

    std::vector<uint32_t> new_idx = {4, 5, 6};
    std::vector<crypto::public_key> new_pks;
    std::vector<crypto::secret_key> new_sks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key p; crypto::secret_key s;
        crypto::generate_keys(p, s);
        new_pks.push_back(p);
        new_sks.push_back(s);
    }

    // -------- Step 1: build the two contributor deals directly, no
    // runners for contributors (they are simple publishers).
    auto make_contrib = [&](uint32_t idx, const BIGNUM* s_i,
                             const BIGNUM* mu_i,
                             const crypto::public_key& pub)
    {
        dao_reshare_link_context ctx;
        ctx.genesis_block_hash = []{
            crypto::hash h{}; std::memset(h.data, 0xAA, 32); return h;
        }();
        ctx.stable_key_record_hash.assign(32, 0xBB);
        ctx.share_set_id = 1;
        ctx.contributor_pubkey.assign(32, 0);
        std::memcpy(ctx.contributor_pubkey.data(), pub.data, 32);
        ctx.original_index = idx;
        ctx.contributor_subset = S;
        ctx.N = out.record.N;
        ctx.V = out.record.V;
        ctx.VK_i = out.record.V_K_i[idx - 1];
        ctx.C_i0.assign(PAILLIER_CT_BYTES, 0);
        ctx.Delta = delta_bytes;
        ctx.mu_i = mu_signed(mu_i);

        dao_reshare_contribution c;
        EXPECT_TRUE(dao_reshare_make_contribution(
            pk, grp, out.record.V, s_i, mu_i, delta.get(),
            1, new_idx, ctx, c));
        return c;
    };

    dao_reshare_contribution c1 = make_contrib(1, s1.get(), mu1.get(),
                                                 c_pks[0]);
    dao_reshare_contribution c2 = make_contrib(2, s2.get(), mu2.get(),
                                                 c_pks[1]);

    // -------- Step 2: three new-member runners.
    struct RunnerCtx {
        dao_reshare_runner::config cfg;
        std::unique_ptr<dao_reshare_runner> runner;
    };
    std::vector<RunnerCtx> ctxs(3);

    std::vector<std::string> mailbox;
    auto broadcast = [&mailbox](const std::string& s) {
        mailbox.push_back(s);
    };
    auto send_to = [](const crypto::public_key&, const std::string&) {
        return true;
    };

    for (int i = 0; i < 3; ++i) {
        RunnerCtx& rc = ctxs[i];
        rc.cfg.pk = &pk;
        rc.cfg.grp = &grp;
        rc.cfg.V_bytes = out.record.V;
        rc.cfg.delta = delta.get();
        rc.cfg.t_new = 1;
        rc.cfg.new_indices = new_idx;
        rc.cfg.new_members = new_pks;
        rc.cfg.contributor_indices = c_idx;
        rc.cfg.contributor_members = c_pks;
        rc.cfg.old_share_set_id = 1;
        rc.cfg.new_share_set_id = 2;
        rc.cfg.height = 9999;
        rc.cfg.threshold = 2;
        rc.cfg.key_id = out.record.key_id;
        rc.cfg.local_party_index = 0;
        rc.cfg.local_new_index = i + 1;
        rc.cfg.local_pub = new_pks[i];
        rc.cfg.local_priv = new_sks[i];
        // link_ctx_base unused when local_party_index == 0.

        dao_reshare_p2p_callbacks cb;
        cb.broadcast = broadcast;
        cb.send_to = send_to;
        rc.runner = std::make_unique<dao_reshare_runner>(rc.cfg, cb);
        ASSERT_TRUE(rc.runner->start());
    }

    // -------- Step 3: two contributor deals broadcast into the mailbox.
    for (size_t i = 0; i < new_idx.size(); ++i) {
        (void)i;
    }
    {
        // Build deals exactly as dao_reshare_runner::start does for a
        // contributor, and put them in the mailbox.
        auto publish = [&](const dao_reshare_contribution& c,
                            uint32_t sender_index,
                            const crypto::public_key& sender_pub,
                            const crypto::secret_key& sender_sk)
        {
            dao_reshare_msg m;
            m.old_share_set_id = 1;
            m.new_share_set_id = 2;
            m.sender_index = sender_index;
            m.type = 0;
            ASSERT_TRUE(dao_reshare_serialize_public(c, m.public_blob));
            for (size_t k = 0; k < new_idx.size(); ++k) {
                std::vector<uint8_t> shb;
                ASSERT_TRUE(dao_reshare_serialize_share(c.shares[k], shb));
                dao_reshare_share_bundle b;
                b.old_share_set_id = 1;
                b.sender_index = sender_index;
                b.share_bytes = std::move(shb);
                std::vector<uint8_t> bb;
                ASSERT_TRUE(b.serialize(bb));
                std::string bstr(bb.begin(), bb.end());
                std::string enc;
                ASSERT_TRUE(encrypt_dkg_private_payload(
                    bstr, sender_pub, new_pks[k], enc));
                m.recipient_indices.push_back(new_idx[k]);
                m.recipient_payloads.push_back(
                    std::vector<uint8_t>(enc.begin(), enc.end()));
            }
            std::vector<uint8_t> mb;
            ASSERT_TRUE(m.serialize(mb));
            mailbox.emplace_back(mb.begin(), mb.end());
        };
        publish(c1, 1, c_pks[0], c_sks[0]);
        publish(c2, 2, c_pks[1], c_sks[1]);
    }

    // -------- Step 4: deliver.
    for (const auto& s : mailbox) {
        std::vector<uint8_t> mb(s.begin(), s.end());
        dao_reshare_msg m;
        if (!m.deserialize(mb)) continue;
        for (auto& rc : ctxs)
            rc.runner->on_message(c_pks[m.sender_index - 1], m);
    }

    // -------- Step 5: all three must finalize with the same record.
    dao_share_set_record recs[3];
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(ctxs[i].runner->wait(recs[i], 10));
    }
    EXPECT_EQ(recs[0].share_set_id, recs[1].share_set_id);
    EXPECT_EQ(recs[0].share_set_id, recs[2].share_set_id);
    EXPECT_EQ(recs[0].committee_id_hash, recs[1].committee_id_hash);
    EXPECT_EQ(recs[0].committee_id_hash, recs[2].committee_id_hash);
    EXPECT_EQ(recs[0].VK_i, recs[1].VK_i);
    EXPECT_EQ(recs[0].VK_i, recs[2].VK_i);

    // Each new member derived its own share.
    for (int i = 0; i < 3; ++i) {
        std::vector<uint8_t> ls;
        EXPECT_TRUE(ctxs[i].runner->get_local_share(ls));
    }
}
