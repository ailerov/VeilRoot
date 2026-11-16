// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Chain-level CL reshare trigger tests. Each drives one node's
// Blockchain via the production reshare scheduler.

#include "gtest/gtest.h"

#ifdef VEILROOT_ENABLE_CL

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "blockchain_db/blockchain_db.h"
#include "cl_bootstrap_fixture.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_core/cryptonote_core.h"
#include "governance/dao_cl_ballot.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_reshare_runner.h"
#include "governance/dao_dkg.h"
#include "governance/dao_tally.h"
#include "governance/dao_tally_share.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace po = boost::program_options;

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

class DaoClReshareChain : public ::testing::Test
{
protected:
    std::string                       m_dir;
    std::unique_ptr<cryptonote::core> m_core;
    crypto::hash                      m_prop_id{};

    void SetUp() override
    {
        boost::filesystem::path tmp =
            boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_cl_ch_%%%%-%%%%");
        m_dir = tmp.string();
        boost::filesystem::create_directories(m_dir);

        po::options_description desc("");
        cryptonote::core::init_options(desc);
        std::vector<std::string> args = {
            "--regtest",
            "--data-dir", m_dir,
            "--offline",
            "--keep-fakechain",
            "--fixed-difficulty", "1",
        };
        po::variables_map vm;
        po::store(po::command_line_parser(args).options(desc).run(), vm);
        po::notify(vm);

        m_core.reset(new cryptonote::core(nullptr));
        ASSERT_TRUE(m_core->init(vm, nullptr, nullptr, false));

        crypto::secret_key sec;
        crypto::public_key pub;
        if (!m_core->get_blockchain_storage().get_db()
                 .get_committee_privkey(sec)) {
            crypto::generate_keys(pub, sec);
            m_core->get_blockchain_storage().get_db()
                   .set_committee_privkey(sec);
        } else {
            ASSERT_TRUE(crypto::secret_key_to_public_key(sec, pub));
        }
        m_core->set_node_key(sec);

        m_prop_id.data[0]  = 0xc3;
        m_prop_id.data[31] = 0xc3;
    }

    void TearDown() override
    {
        if (m_core) m_core->deinit();
        m_core.reset();
        boost::filesystem::remove_all(m_dir);
    }

    BlockchainDB& db()
    {
        return m_core->get_blockchain_storage().get_db();
    }

    Blockchain& bc()
    {
        return m_core->get_blockchain_storage();
    }

    void install_self_committee(const v2test::CLBootstrapFixture& fx)
    {
        m_core->set_node_key(fx.committee_sks[0]);
        bc().install_cl_tally_key_for_proposal_for_test(
            fx.record, fx.share_set, fx.local_shares[0]);
    }

    void add_proposal(const std::vector<uint8_t>& kid, uint64_t vote_end)
    {
        proposal_record pr;
        pr.proposal_id       = m_prop_id;
        pr.submission_height = 100;   // future: avoid trigger-on-mine
        pr.voting_end_height = vote_end;
        pr.status            = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(pr.tally_key_id.data, kid.data(), 32);
        db().block_wtxn_start();
        db().add_proposal_record(m_prop_id, pr);
        db().block_wtxn_stop();
    }

    void mine_to_height(uint64_t target)
    {
        auto& b = bc();
        while (b.get_current_blockchain_height() < target) {
            account_base ma; ma.generate();
            block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
            crypto::hash shh{}; blobdata en(8,0);
            ASSERT_TRUE(b.create_block_template(tmpl,
                ma.get_keys().m_account_address, diff, h, r, en, sh, shh));
            auto gbh = [&b](const block& bb, uint64_t hh,
                            const crypto::hash* s, unsigned int mn,
                            crypto::hash& o) -> bool {
                return get_block_longhash(&b, bb, o, hh, s,
                                          static_cast<int>(mn));
            };
            ASSERT_TRUE(miner::find_nonce_for_given_block(
                gbh, tmpl, diff, h, nullptr));
            block_verification_context bvc{}; pool_supplement e{};
            blobdata bb = block_to_blob(tmpl);
            ASSERT_TRUE(m_core->handle_single_incoming_block(
                bb, &tmpl, bvc, e, false));
            ASSERT_FALSE(bvc.m_verifivation_failed);
        }
    }

    void add_ready(const crypto::public_key& pk, uint64_t h,
                   const crypto::hash& bh)
    {
        db().block_wtxn_start();
        db().add_dao_v2_node_ready(pk, h, bh);
        db().block_wtxn_stop();
    }
};

} // namespace

TEST_F(DaoClReshareChain, declines_without_send_callback)
{
    v2test::CLBootstrapFixture fx;
    ASSERT_TRUE(v2test::make_cl_bootstrap_3party(fx, 0x1111));
    install_self_committee(fx);
    add_proposal(fx.record.key_id, /*vote_end=*/3);
    // m_dao_v2_dkg_send left unset.

    bc().maybe_start_dao_v2_reshare_for_proposal(m_prop_id, 3);
    EXPECT_FALSE(bc().has_dao_v2_reshare_runner_for_test());
}

TEST_F(DaoClReshareChain, declines_no_key_record)
{
    // Proposal points at a key id for which no key record is
    // installed. The scheduler must not start a runner.
    std::vector<uint8_t> kid(32, 0xab);
    add_proposal(kid, /*vote_end=*/3);

    bc().set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });
    bc().maybe_start_dao_v2_reshare_for_proposal(m_prop_id, 3);
    EXPECT_FALSE(bc().has_dao_v2_reshare_runner_for_test());
}

TEST_F(DaoClReshareChain, declines_roster_unchanged)
{
    v2test::CLBootstrapFixture fx;
    ASSERT_TRUE(v2test::make_cl_bootstrap_3party(fx, 0x3333));
    install_self_committee(fx);
    add_proposal(fx.record.key_id, /*vote_end=*/3);
    mine_to_height(3);

    crypto::hash can_hash_at_1 = bc().get_block_id_by_height(1);
    ASSERT_NE(can_hash_at_1, crypto::null_hash);
    for (int i = 0; i < 3; ++i)
        add_ready(fx.committee_pubs[i], 1, can_hash_at_1);

    bc().set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });
    bc().maybe_start_dao_v2_reshare_for_proposal(m_prop_id, 3);
    EXPECT_FALSE(bc().has_dao_v2_reshare_runner_for_test());
}

TEST_F(DaoClReshareChain, starts_runner_valid)
{
    v2test::CLBootstrapFixture fx;
    ASSERT_TRUE(v2test::make_cl_bootstrap_3party(fx, 0x4444));
    install_self_committee(fx);
    add_proposal(fx.record.key_id, /*vote_end=*/3);
    mine_to_height(3);

    crypto::hash can_hash_at_1 = bc().get_block_id_by_height(1);
    ASSERT_NE(can_hash_at_1, crypto::null_hash);
    for (int i = 0; i < 3; ++i)
        add_ready(fx.committee_pubs[i], 1, can_hash_at_1);
    crypto::public_key d_pub; crypto::secret_key d_sk;
    crypto::generate_keys(d_pub, d_sk);
    add_ready(d_pub, 1, can_hash_at_1);

    bc().set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });
    bc().maybe_start_dao_v2_reshare_for_proposal(m_prop_id, 3);
    EXPECT_TRUE(bc().has_dao_v2_reshare_runner_for_test());
    bc().stop_dao_v2_reshare_runner_for_test();
}

TEST_F(DaoClReshareChain, commit_preserves_runner_when_not_finished)
{
    v2test::CLBootstrapFixture fx;
    ASSERT_TRUE(v2test::make_cl_bootstrap_3party(fx, 0x7777));
    install_self_committee(fx);
    add_proposal(fx.record.key_id, /*vote_end=*/3);
    mine_to_height(3);

    crypto::hash can_hash_at_1 = bc().get_block_id_by_height(1);
    ASSERT_NE(can_hash_at_1, crypto::null_hash);
    for (int i = 0; i < 3; ++i)
        add_ready(fx.committee_pubs[i], 1, can_hash_at_1);
    crypto::public_key d_pub; crypto::secret_key d_sk;
    crypto::generate_keys(d_pub, d_sk);
    add_ready(d_pub, 1, can_hash_at_1);

    bc().set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });
    bc().maybe_start_dao_v2_reshare_for_proposal(m_prop_id, 3);
    ASSERT_TRUE(bc().has_dao_v2_reshare_runner_for_test());

    // Runner has not finished (no peer messages delivered). Commit
    // must not clear it, and must not block indefinitely.
    bc().commit_dao_v2_reshare_for_test();
    EXPECT_TRUE(bc().has_dao_v2_reshare_runner_for_test());
    bc().stop_dao_v2_reshare_runner_for_test();
}

TEST_F(DaoClReshareChain, failed_runner_is_cleared_and_retry_succeeds)
{
    v2test::CLBootstrapFixture fx;
    ASSERT_TRUE(v2test::make_cl_bootstrap_3party(fx, 0x6666));
    install_self_committee(fx);
    add_proposal(fx.record.key_id, /*vote_end=*/3);
    mine_to_height(3);

    crypto::hash can_hash_at_1 = bc().get_block_id_by_height(1);
    ASSERT_NE(can_hash_at_1, crypto::null_hash);
    for (int i = 0; i < 3; ++i)
        add_ready(fx.committee_pubs[i], 1, can_hash_at_1);
    crypto::public_key d_pub; crypto::secret_key d_sk;
    crypto::generate_keys(d_pub, d_sk);
    add_ready(d_pub, 1, can_hash_at_1);

    bc().set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });
    bc().maybe_start_dao_v2_reshare_for_proposal(m_prop_id, 3);
    ASSERT_TRUE(bc().has_dao_v2_reshare_runner_for_test());

    // Force the runner to finish with ok=false. On the resulting
    // commit, the runner is cleared (so the scheduler is not
    // blocked by a dead runner) and a fresh runner must then be
    // installable for the same proposal.
    ASSERT_TRUE(bc().force_dao_v2_reshare_runner_failure_for_test());
    bc().commit_dao_v2_reshare_for_test();
    EXPECT_FALSE(bc().has_dao_v2_reshare_runner_for_test());

    // Retry must be possible: scheduler is not blocked.
    bc().maybe_start_dao_v2_reshare_for_proposal(m_prop_id, 3);
    EXPECT_TRUE(bc().has_dao_v2_reshare_runner_for_test());
    bc().stop_dao_v2_reshare_runner_for_test();
}

TEST_F(DaoClReshareChain, commit_fails_closed_on_local_share_pack_failure)
{
    // A new committee member must persist its new local share, or
    // the reshare has not completed. dao_pack_local_share returning
    // empty (or the DB write failing) must abort the whole commit
    // transaction, including the share-set write.
    //
    // The test installs a runner whose ok result carries the
    // current share set's gamma map and the fixture's local
    // share, then forces pack failure. Commit must return false
    // and leave no new share set in the database.
    v2test::CLBootstrapFixture fx;
    ASSERT_TRUE(v2test::make_cl_bootstrap_3party(fx, 0x5555));
    install_self_committee(fx);  // self = party 0

    dao::dao_cl_proposal_key pkc;
    ASSERT_TRUE(dao::dao_cl_load_proposal_key(fx.record.cl_modulus, pkc));
    ASSERT_NE(pkc.pk, nullptr);

    std::vector<uint8_t> old_pk_qfi;
    ASSERT_TRUE(dao::cl_dkg_qfi_to_bytes(old_pk_qfi, pkc.pk->elt()));

    std::vector<uint8_t> D_signed;
    ASSERT_TRUE(dao::cl_dkg_mpz_to_bytes_signed(D_signed, pkc.D));

    Blockchain::dao_v2_reshare_commit_ctx ctx;
    ctx.proposal_id           = m_prop_id;
    ctx.key_id                = fx.record.key_id;
    ctx.old_share_set_id      = fx.share_set.share_set_id;
    ctx.new_share_set_id      = fx.share_set.share_set_id + 1;
    ctx.height                = 1;
    ctx.new_threshold         = fx.share_set.threshold;
    ctx.new_committee_id_hash = fx.share_set.committee_id_hash;
    ctx.old_pk_qfi            = old_pk_qfi;
    ctx.is_new_member         = true;
    ctx.new_local_id          = 0;
    ctx.new_members           = fx.record.committee_members;

    dao::cl_reshare_config cfg;
    cfg.cl                    = pkc.cl;
    cfg.D_signed              = D_signed;
    cfg.old_n                 = 3;
    cfg.old_t_internal        = 1;
    cfg.old_contributors      = {0, 1, 2};
    cfg.new_n                 = 3;
    cfg.new_t_internal        = 1;
    cfg.is_old_contributor    = true;
    cfg.old_local_id          = 0;
    cfg.is_new_member         = true;
    cfg.new_local_id          = 0;
    cfg.old_pk_qfi            = old_pk_qfi;
    cfg.old_gammas_serialized = fx.share_set.cl_gammas_serialized;
    cfg.old_share_bytes       = fx.local_shares[0];
    cfg.old_share_set_id      = fx.share_set.share_set_id;
    cfg.old_committee_id_hash = fx.share_set.committee_id_hash;
    cfg.new_committee_id_hash = fx.share_set.committee_id_hash;
    cfg.old_qualified_ids     = fx.share_set.qualified_ids;
    cfg.proposal_id           = m_prop_id;
    cfg.session_id            = dao::dao_cl_reshare_compute_session_id(
        m_prop_id, fx.share_set.share_set_id,
        fx.share_set.committee_id_hash, fx.share_set.committee_id_hash,
        {0u, 1u, 2u});

    auto net = dao::dkg_make_inproc_network(3);
    auto runner = std::make_unique<dao::cl_reshare_p2p_runner>(
        cfg, std::move(net.endpoints[0]));

    dao::cl_reshare_result fake;
    fake.ok                      = true;
    fake.pk_qfi                  = old_pk_qfi;
    fake.has_local_new_share     = true;
    fake.new_share_bytes         = fx.local_shares[0];
    fake.new_gammas_serialized   = fx.share_set.cl_gammas_serialized;
    fake.qualified_ids           = fx.share_set.qualified_ids;

    bc().install_dao_v2_reshare_state_for_test(std::move(runner), ctx);
    ASSERT_TRUE(bc().force_dao_v2_reshare_runner_success_for_test(fake));
    bc().force_dao_v2_local_share_pack_fail_for_test(true);

    EXPECT_FALSE(bc().commit_dao_v2_reshare_for_test());
    EXPECT_FALSE(bc().has_dao_v2_reshare_runner_for_test());

    dao::dao_share_set_record ss;
    EXPECT_FALSE(db().get_dao_share_set(ctx.new_share_set_id, ss));

    bc().force_dao_v2_local_share_pack_fail_for_test(false);
}

TEST_F(DaoClReshareChain, tally_ingress_accepts_cl_v3_rejects_v2)
{
    v2test::CLBootstrapFixture fx;
    ASSERT_TRUE(v2test::make_cl_bootstrap_3party(fx, 0x8888));
    install_self_committee(fx);  // self is party 0
    add_proposal(fx.record.key_id, /*vote_end=*/3);

    // Aggregate ciphertexts are unparsed at the ingress; any bytes
    // work as long as their hash matches what the shares claim.
    dao_proposal_aggregate agg;
    agg.aggregate_E_W.assign(64, 0xAA);
    agg.aggregate_E_S.assign(64, 0xBB);
    agg.aggregate_E_B.assign(64, 0xCC);
    db().block_wtxn_start();
    db().add_dao_proposal_aggregate(m_prop_id, agg);
    db().block_wtxn_stop();

    const crypto::hash agg_hash = dao::dao_aggregate_ciphertext_hash(
        agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B);

    // --- v3 (CL) share from party 0: must be accepted ---
    dao::dao_v2_tally_share s3;
    s3.version                  = dao::dao_v2_tally_share::WIRE_VERSION_CL;
    s3.proposal_id              = m_prop_id;
    s3.vote_end_height          = 3;
    s3.tally_key_id             = fx.record.key_id;
    s3.aggregate_ciphertext_hash = agg_hash;
    s3.member_index             = 1;
    s3.cl_partial_W.assign(64, 0x01);
    s3.cl_partial_S.assign(64, 0x02);
    s3.cl_partial_B.assign(64, 0x03);
    std::vector<uint8_t> wire3;
    ASSERT_TRUE(s3.serialize(wire3));
    ASSERT_EQ(wire3[0], dao::dao_v2_tally_share::WIRE_VERSION_CL);

    EXPECT_EQ(bc().get_dao_v2_tally_shares_size_for_test(m_prop_id), 0u);
    bc().handle_dao_v2_tally_share(fx.committee_pubs[0],
        std::string(wire3.begin(), wire3.end()));
    EXPECT_EQ(bc().get_dao_v2_tally_shares_size_for_test(m_prop_id), 1u);

    // --- v2 (Paillier) share from party 1: must be rejected ---
    dao::dao_v2_tally_share s2;
    s2.version                  = dao::dao_v2_tally_share::WIRE_VERSION;
    s2.proposal_id              = m_prop_id;
    s2.vote_end_height          = 3;
    s2.tally_key_id             = fx.record.key_id;
    s2.aggregate_ciphertext_hash = agg_hash;
    s2.member_index             = 2;
    s2.partial_W.assign(PAILLIER_CT_BYTES, 0x10);
    s2.partial_S.assign(PAILLIER_CT_BYTES, 0x11);
    s2.partial_B.assign(PAILLIER_CT_BYTES, 0x12);
    s2.proof_W.E.assign(32, 0x20);
    s2.proof_W.Z.assign(DAO_DKG_PARTIAL_PROOF_Z_BYTES, 0x21);
    s2.proof_S.E.assign(32, 0x22);
    s2.proof_S.Z.assign(DAO_DKG_PARTIAL_PROOF_Z_BYTES, 0x23);
    s2.proof_B.E.assign(32, 0x24);
    s2.proof_B.Z.assign(DAO_DKG_PARTIAL_PROOF_Z_BYTES, 0x25);
    std::vector<uint8_t> wire2;
    ASSERT_TRUE(s2.serialize(wire2));
    ASSERT_EQ(wire2[0], dao::dao_v2_tally_share::WIRE_VERSION);

    bc().handle_dao_v2_tally_share(fx.committee_pubs[1],
        std::string(wire2.begin(), wire2.end()));
    EXPECT_EQ(bc().get_dao_v2_tally_shares_size_for_test(m_prop_id), 1u);
}

#endif // VEILROOT_ENABLE_CL
