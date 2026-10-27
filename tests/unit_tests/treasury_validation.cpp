// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Treasury execution-tx authorization regression tests.
// Closes the pre-patch hole where a pure-treasury tx skipped
// validate_treasury_input via the all_special early return in
// Blockchain::check_tx_inputs, allowing arbitrary redirection of
// treasury funds to any recipient/amount.
//
// build_execution_transaction is private; the valid-tx baseline here
// is constructed from the same public primitives it uses (txkey from
// hash_to_scalar(proposal_id), ECDH derivation, derive_public_key,
// set_tx_out). check_tx_inputs is exercised via its public 6-arg
// overload (same one tx_memory_pool calls).

#include <boost/filesystem.hpp>
#include <cstring>
#include <memory>
#include <set>
#include <string>

#include "gtest/gtest.h"

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"

namespace {

class TreasuryValidation : public ::testing::Test {
protected:
    void SetUp() override {
        m_dir = (boost::filesystem::temp_directory_path()
                 / boost::filesystem::unique_path()).string();
        boost::filesystem::create_directories(m_dir);

        m_txpool.reset(new cryptonote::tx_memory_pool(*m_bc));
        m_bc.reset(new cryptonote::Blockchain(*m_txpool));

        m_db = new cryptonote::BlockchainLMDB();
        m_db->open(m_dir);

        m_hard_forks[0] = {1, 0};
        m_hard_forks[1] = {0, 0};
        m_test_opts.reset(new cryptonote::test_options{m_hard_forks, 0});

        ASSERT_TRUE(m_bc->init(m_db, cryptonote::FAKECHAIN, true,
                               m_test_opts.get(), 0, nullptr));
    }

    void TearDown() override {
        m_bc.reset();
        m_txpool.reset();
        boost::filesystem::remove_all(m_dir);
    }

    struct Seed {
        crypto::hash        proposal_id;
        uint64_t            out_id;
        uint64_t            proposal_amount;
        uint64_t            treasury_amount;
        std::string         recipient_str;
        crypto::public_key  recipient_view_key;
        crypto::public_key  recipient_spend_key;
    };

    Seed seed(const std::string& tag,
              uint64_t proposal_amount,
              uint64_t treasury_amount)
    {
        Seed s{};
        crypto::cn_fast_hash(tag.data(), tag.size(), s.proposal_id);
        s.proposal_amount = proposal_amount;
        s.treasury_amount = treasury_amount;

        cryptonote::account_base acct;
        acct.generate();
        s.recipient_str       = acct.get_public_address_str(cryptonote::FAKECHAIN);
        s.recipient_view_key  = acct.get_keys().m_account_address.m_view_public_key;
        s.recipient_spend_key = acct.get_keys().m_account_address.m_spend_public_key;

        cryptonote::proposal_record rec{};
        rec.proposal_id = s.proposal_id;
        rec.type = 0;
        std::strncpy(rec.recipient, s.recipient_str.c_str(),
                     sizeof(rec.recipient) - 1);
        rec.amount               = proposal_amount;
        rec.voting_period_days   = 7;
        rec.submission_height    = 10;
        rec.voting_end_height    = 50;
        rec.status               = 1;  // PROPOSAL_STATUS_PASSED
        rec.status_height        = 50;
        rec.recipient_view_public_key = s.recipient_view_key;

        m_db->add_proposal_record(s.proposal_id, rec);
        s.out_id = m_db->add_treasury_output(treasury_amount, 100);

        return s;
    }

    // Replicates Blockchain::build_execution_transaction from public
    // primitives (same sequence as src/cryptonote_core/blockchain.cpp).
    bool build_valid_exec(const Seed& s,
                          const cryptonote::proposal_record& rec,
                          uint64_t collected,
                          cryptonote::transaction& tx)
    {
        tx = cryptonote::transaction{};
        tx.version = 2;

        cryptonote::txin_treasury in{};
        in.proposal_id        = rec.proposal_id;
        in.treasury_output_id = s.out_id;
        tx.vin.push_back(in);

        crypto::secret_key txkey;
        crypto::hash_to_scalar(rec.proposal_id.data, sizeof(rec.proposal_id), txkey);
        crypto::public_key txkey_pub;
        crypto::secret_key_to_public_key(txkey, txkey_pub);
        cryptonote::add_tx_pub_key_to_extra(tx, txkey_pub);

        crypto::public_key ecdh_view_pub = rec.recipient_view_public_key;
        crypto::key_derivation deriv;
        if (!crypto::generate_key_derivation(ecdh_view_pub, txkey, deriv))
            return false;

        cryptonote::address_parse_info addr_info;
        if (!cryptonote::get_account_address_from_str(
                addr_info, cryptonote::FAKECHAIN, rec.recipient))
            return false;

        crypto::public_key eph_key;
        if (!crypto::derive_public_key(
                deriv, 0, addr_info.address.m_spend_public_key, eph_key))
            return false;

        const bool           use_view_tags = false;
        const crypto::view_tag view_tag{};

        cryptonote::tx_out payment_out;
        cryptonote::set_tx_out(rec.amount, eph_key, use_view_tags, view_tag, payment_out);
        tx.vout.push_back(payment_out);

        if (collected > rec.amount) {
            cryptonote::tx_out change_out;
            change_out.amount = collected - rec.amount;
            change_out.target = cryptonote::txout_treasury{};
            tx.vout.push_back(change_out);
        }

        tx.rct_signatures = rct::rctSig{};
        tx.rct_signatures.type = rct::RCTTypeNull;
        return true;
    }

    bool check(cryptonote::transaction& tx)
    {
        cryptonote::tx_verification_context tvc{};
        uint64_t     max_used_height = 0;
        crypto::hash max_used_id{};
        return m_bc->check_tx_inputs(tx, max_used_height, max_used_id,
                                     tvc, false, 200);
    }

    std::string                                 m_dir;
    cryptonote::BlockchainLMDB*                 m_db = nullptr;
    std::unique_ptr<cryptonote::tx_memory_pool> m_txpool;
    std::unique_ptr<cryptonote::Blockchain>     m_bc;
    std::unique_ptr<cryptonote::test_options>   m_test_opts;
    std::pair<uint8_t, uint64_t>                m_hard_forks[2];
};

TEST_F(TreasuryValidation, AcceptsValidExecution)
{
    cryptonote::db_wtxn_guard g(m_db);
    auto s = seed("prop-1", 1000, 1000);
    cryptonote::proposal_record rec;
    ASSERT_TRUE(m_db->get_proposal_record(s.proposal_id, rec));

    cryptonote::transaction tx;
    ASSERT_TRUE(build_valid_exec(s, rec, 1000, tx));
    EXPECT_TRUE(check(tx));
}

TEST_F(TreasuryValidation, RejectsWrongRecipient)
{
    cryptonote::db_wtxn_guard g(m_db);
    auto s = seed("prop-2", 1000, 1000);
    cryptonote::proposal_record rec;
    ASSERT_TRUE(m_db->get_proposal_record(s.proposal_id, rec));

    cryptonote::transaction tx;
    ASSERT_TRUE(build_valid_exec(s, rec, 1000, tx));

    // Re-derive eph_key against an attacker's spend pubkey using the
    // same (public) derivation; result is a valid one-time key for the
    // wrong recipient.
    cryptonote::account_base attacker;
    attacker.generate();

    crypto::secret_key txkey;
    crypto::hash_to_scalar(rec.proposal_id.data, sizeof(rec.proposal_id), txkey);

    crypto::key_derivation deriv;
    ASSERT_TRUE(crypto::generate_key_derivation(s.recipient_view_key, txkey, deriv));

    crypto::public_key attacker_eph;
    ASSERT_TRUE(crypto::derive_public_key(
        deriv, 0,
        attacker.get_keys().m_account_address.m_spend_public_key,
        attacker_eph));

    tx.vout[0].target = cryptonote::txout_to_key{attacker_eph};
    EXPECT_FALSE(check(tx));
}

TEST_F(TreasuryValidation, RejectsInflatedAmount)
{
    cryptonote::db_wtxn_guard g(m_db);
    auto s = seed("prop-3", 1000, 1000);
    cryptonote::proposal_record rec;
    ASSERT_TRUE(m_db->get_proposal_record(s.proposal_id, rec));

    cryptonote::transaction tx;
    ASSERT_TRUE(build_valid_exec(s, rec, 1000, tx));
    tx.vout[0].amount += 1;
    EXPECT_FALSE(check(tx));
}

TEST_F(TreasuryValidation, RejectsNonTreasuryChange)
{
    cryptonote::db_wtxn_guard g(m_db);
    auto s = seed("prop-4", 1000, 1100);
    cryptonote::proposal_record rec;
    ASSERT_TRUE(m_db->get_proposal_record(s.proposal_id, rec));

    cryptonote::transaction tx;
    ASSERT_TRUE(build_valid_exec(s, rec, 1100, tx));
    ASSERT_GE(tx.vout.size(), 2u);

    tx.vout[1].target = cryptonote::txout_to_key{crypto::null_pkey};
    EXPECT_FALSE(check(tx));
}

TEST_F(TreasuryValidation, RejectsAmountMismatch)
{
    cryptonote::db_wtxn_guard g(m_db);
    auto s = seed("prop-5", 1000, 1100);
    cryptonote::proposal_record rec;
    ASSERT_TRUE(m_db->get_proposal_record(s.proposal_id, rec));

    cryptonote::transaction tx;
    ASSERT_TRUE(build_valid_exec(s, rec, 1100, tx));
    ASSERT_GE(tx.vout.size(), 2u);

    tx.vout[1].amount += 1;   // inflate change, skim from treasury
    EXPECT_FALSE(check(tx));
}

}  // namespace
