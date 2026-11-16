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
#include "governance/dao_dkg.h"
#include "governance/dao_tally.h"

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

#endif // VEILROOT_ENABLE_CL
