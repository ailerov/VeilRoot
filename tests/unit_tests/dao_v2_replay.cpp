// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DAO V2 chain-replay test.
//
// Two real cryptonote::core instances, two independent LMDB
// directories, no P2P. Node B is fed Node A's blocks through the
// normal incoming-block path (handle_single_incoming_block) so that
// consensus validation and block application run on B exactly as they
// would after a network sync.
//
// The property under test: a node with a fresh database, no copied
// DKG key record, no copied governance state, reconstructs the same
// outcome by replaying the chain.
//
// The end-to-end activation replay test builds a DKG activation
// transaction on Node A, feeds the containing block to a freshly
// initialised Node B, and asserts that B reconstructs the key record
// and the active key record from chain state alone. It then replays the
// tally-result block on B and asserts both nodes carry identical
// outcomes, and that no block contains a private share.

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "gtest/gtest.h"

#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/tx_extra.h"
#include "serialization/binary_utils.h"
#include "serialization/binary_archive.h"
#include "serialization/variant.h"
#include "serialization/string.h"
#include "blockchain_db/blockchain_db.h"
#include "governance/tally_manager.h"
#include "governance/governance_params.h"
#include "governance/dao_tally_session_cycle.h"
#include "governance/dao_tally_share.h"
#include "governance/dao_tally.h"
#include "governance/dao_supply.h"
#include "governance/dao_paillier.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_dkg.h"
#include "governance/vote_proof_v2.h"
#include "governance/dao_wallet_v2.h"
#include "governance/vote_utils.h"
#include "crypto/crypto-ops.h"
#include "cryptonote_config.h"
#include <functional>
#include <iostream>
#include <ctime>
#include "crypto/crypto.h"
#include "common/varint.h"

namespace po = boost::program_options;
using namespace cryptonote;

namespace {

struct ReplayNode
{
    std::string                                dir;
    std::unique_ptr<cryptonote::core>          core;

    bool init(const std::string& data_dir)
    {
        dir = data_dir;
        boost::filesystem::create_directories(dir);

        po::options_description desc("");
        cryptonote::core::init_options(desc);

        std::vector<std::string> args = {
            "--regtest",
            "--data-dir", dir,
            "--offline",
            "--keep-fakechain",
            "--fixed-difficulty", "1",
        };
        po::variables_map vm;
        po::store(po::command_line_parser(args).options(desc).run(), vm);
        po::notify(vm);

        core.reset(new cryptonote::core(nullptr));
        if (!core->init(vm, nullptr, nullptr, false))
            return false;

        // Give the node a deterministic identity so committee selection
        // later in the test is reproducible.
        crypto::public_key pk;
        crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        core->set_node_key(sk);
        return true;
    }

    ~ReplayNode()
    {
        if (core)
            try { core->deinit(); } catch (...) {}
        core.reset();
        if (!dir.empty())
            boost::filesystem::remove_all(dir);
    }
};

} // namespace

TEST(DaoV2Replay, TwoCoresShareGenesis)
{
    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_%%%%-%%%%");

    ReplayNode a;
    ReplayNode b;

    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));

    // Heights after init in fakechain mode.
    const uint64_t ha = a.core->get_current_blockchain_height();
    const uint64_t hb = b.core->get_current_blockchain_height();
    EXPECT_EQ(ha, hb);

    // Genesis tip.
    crypto::hash tip_a{}, tip_b{};
    if (ha > 0) {
        tip_a = a.core->get_blockchain_storage().get_block_id_by_height(ha - 1);
        tip_b = b.core->get_blockchain_storage().get_block_id_by_height(hb - 1);
    } else {
        // Some fakechain modes report height 1 for the genesis block.
        tip_a = a.core->get_blockchain_storage().get_block_id_by_height(0);
        tip_b = b.core->get_blockchain_storage().get_block_id_by_height(0);
    }
    EXPECT_EQ(tip_a, tip_b);

    boost::filesystem::remove_all(base);
}

namespace {

// Build a minimal valid block on top of the given chain on `node`.
//
// The block contains only the coinbase transaction and no tx_hashes.
// A later step adds the tally-result transaction. Difficulty is 1
// because the fixture runs in --regtest mode.
bool construct_block_here(
    ReplayNode& node,
    const account_base& miner_acc,
    uint64_t height,
    const std::vector<transaction>& extra_txs,
    block& out,
    // Optional hook run after the coinbase is built but before PoW is
    // solved. Used by tests that need to tamper with the block and
    // still produce a PoW-valid result.
    const std::function<void(block&)>& modifier = {})
{
    std::cerr << "[cbh] enter height=" << height << "\n";

    auto& bc_storage = node.core->get_blockchain_storage();
    auto& db         = bc_storage.get_db();

    const uint8_t hf_version = bc_storage.get_current_hard_fork_version();

    block blk{};
    blk.major_version = hf_version;
    blk.minor_version = hf_version;
    blk.nonce = 0;

    crypto::hash prev_id = crypto::null_hash;
    uint64_t last_ts = 0;
    uint64_t already_generated = 0;

    if (height > 0)
    {
        prev_id = bc_storage.get_block_id_by_height(height - 1);
        if (prev_id == crypto::null_hash)
        {
            std::cerr << "[cbh] prev_id null at " << (height - 1) << "\n";
            return false;
        }

        try {
            const block prev = db.get_block_from_height(height - 1);
            last_ts = prev.timestamp;
        } catch (const std::exception& e) {
            std::cerr << "[cbh] get_block_from_height threw: "
                      << e.what() << "\n";
            return false;
        }
        try {
            already_generated = db.get_block_already_generated_coins(height - 1);
        } catch (...) {
            already_generated = 0;
        }
    }

    blk.prev_id = prev_id;
    blk.timestamp = std::max<uint64_t>(last_ts + 1,
                                       static_cast<uint64_t>(time(nullptr)));

    uint64_t reward = 0;
    if (!get_block_reward(0, 0, already_generated, reward, blk.major_version))
    {
        std::cerr << "[cbh] get_block_reward false\n";
        return false;
    }
    std::cerr << "[cbh] reward=" << reward << "\n";

    transaction miner_tx;
    // max_outs must be at least 2 because the treasury split in
    // construct_miner_tx creates a miner output plus a treasury
    // output. Passing 1 fails the out_amounts.size() <= max_outs
    // check even for the smallest reward.
    if (!construct_miner_tx(
            height, 0, already_generated, 0, 0,
            miner_acc.get_keys().m_account_address,
            miner_tx, {}, 999, blk.major_version, {}, 18))
    {
        std::cerr << "[cbh] construct_miner_tx false\n";
        return false;
    }

    blk.miner_tx = miner_tx;
    blk.tx_hashes.clear();
    for (const auto& tx : extra_txs)
        blk.tx_hashes.push_back(cryptonote::get_transaction_hash(tx));

    if (modifier)
        modifier(blk);

    auto gbh = [&bc_storage](
        const block& b,
        uint64_t h,
        const crypto::hash* seed,
        unsigned int miners,
        crypto::hash& hash_out) -> bool
    {
        return get_block_longhash(
            &bc_storage, b, hash_out, h, seed, static_cast<int>(miners));
    };

    const difficulty_type diff = 1;
    if (!miner::find_nonce_for_given_block(gbh, blk, diff, height, nullptr))
    {
        std::cerr << "[cbh] find_nonce false\n";
        return false;
    }
    std::cerr << "[cbh] ok nonce=" << blk.nonce << "\n";

    out = blk;
    return true;
}

} // namespace

TEST(DaoV2Replay, NodeBReceivesBlockOneFromNodeA)
{
    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_%%%%-%%%%");

    ReplayNode a;
    ReplayNode b;

    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));

    account_base miner_acc;
    miner_acc.generate();

    const uint64_t a_start = a.core->get_current_blockchain_height();
    std::cerr << "[replay] a_start=" << a_start
              << " hf_version=" << (int)a.core->get_blockchain_storage().get_current_hard_fork_version()
              << "\n";

    block blk;
    ASSERT_TRUE(construct_block_here(a, miner_acc, a_start, {}, blk));

    block_verification_context bvc{};
    pool_supplement extra_txs{};
    cryptonote::blobdata blk_blob = cryptonote::block_to_blob(blk);
    ASSERT_TRUE(a.core->handle_single_incoming_block(
        blk_blob, &blk, bvc, extra_txs, /*update_miner_blocktemplate*/ false));
    ASSERT_FALSE(bvc.m_verifivation_failed);

    ASSERT_EQ(a.core->get_current_blockchain_height(), a_start + 1);

    // Same block delivered to Node B through the normal incoming-block
    // path.
    {
        block_verification_context bvc_b{};
        pool_supplement extra_txs_b{};
        ASSERT_TRUE(b.core->handle_single_incoming_block(
            blk_blob, &blk, bvc_b, extra_txs_b,
            /*update_miner_blocktemplate*/ false));
        ASSERT_FALSE(bvc_b.m_verifivation_failed);
    }

    ASSERT_EQ(b.core->get_current_blockchain_height(), a_start + 1);

    // Same tip hash on both nodes.
    crypto::hash tip_a =
        a.core->get_blockchain_storage().get_block_id_by_height(a_start);
    crypto::hash tip_b =
        b.core->get_blockchain_storage().get_block_id_by_height(a_start);
    EXPECT_EQ(tip_a, tip_b);

    boost::filesystem::remove_all(base);
}


// ------------------------------------------------------------------
// Replay blocker: a block containing a tally-result transaction is
// accepted by Node A (which holds the DKG key record) and rejected by
// Node B (which does not).
//
// The rejection reason is captured by the validator's diagnostics. The
// expectation is "key record missing" — the DKG public key
// record is local-only state today, so a syncing node cannot validate
// any tally result.
// ------------------------------------------------------------------
TEST(DaoV2Replay, NodeBReconstructsKeyRecordFromActivationBlock)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_act_%%%%-%%%%");

    ReplayNode a;
    ReplayNode b;
    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));

    // Three committee members, sorted by public key ascending so that
    // select_dao_v2_dkg_shareholders (weight DESC, pubkey ASC) returns
    // them in the same order we hand to the DKG.
    std::vector<crypto::public_key> committee_pks;
    std::vector<crypto::secret_key> committee_sks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee_pks.push_back(pk);
        committee_sks.push_back(sk);
    }
    {
        std::vector<size_t> idx = {0, 1, 2};
        std::sort(idx.begin(), idx.end(), [&](size_t x, size_t y) {
            return std::memcmp(committee_pks[x].data,
                               committee_pks[y].data, 32) < 0;
        });
        std::vector<crypto::public_key> pk2;
        std::vector<crypto::secret_key> sk2;
        for (auto i : idx) {
            pk2.push_back(committee_pks[i]);
            sk2.push_back(committee_sks[i]);
        }
        committee_pks = std::move(pk2);
        committee_sks = std::move(sk2);
    }
    a.core->set_node_key(committee_sks[0]);
    b.core->set_node_key(committee_sks[1]);

    auto& adb = a.core->get_blockchain_storage().get_db();
    auto& bdb = b.core->get_blockchain_storage().get_db();

    // Advance both chains identically by a few empty blocks so the
    // activation block is not the first non-genesis block.
    account_base miner_acc;
    miner_acc.generate();
    for (int i = 0; i < 3; ++i) {
        const uint64_t h = a.core->get_current_blockchain_height();
        block empty;
        ASSERT_TRUE(construct_block_here(a, miner_acc, h, {}, empty));
        cryptonote::blobdata bb = cryptonote::block_to_blob(empty);
        { block_verification_context bvc{}; pool_supplement e{};
          ASSERT_TRUE(a.core->handle_single_incoming_block(
              bb, &empty, bvc, e, false)); }
        { block_verification_context bvc{}; pool_supplement e{};
          ASSERT_TRUE(b.core->handle_single_incoming_block(
              bb, &empty, bvc, e, false)); }
    }

    // Install equal-weight eligible records on both nodes.
    for (auto* db_ptr : { &adb, &bdb }) {
        for (size_t i = 0; i < 3; ++i) {
            committee_eligible_record rec{};
            rec.node_pubkey = committee_pks[i];
            rec.amount = 3000000;
            rec.unlock_height = 1;
            rec.stake_age_weight = 0;
            crypto::key_image ki{};
            std::memset(ki.data, 0, sizeof(ki.data));
            ki.data[0] = static_cast<uint8_t>(i + 1);
            db_wtxn_guard g(db_ptr);
            db_ptr->add_committee_eligible(ki, rec);
        }
    }

    // In-process DKG. Only Node A persists the result (local share),
    // which no longer installs the public key record.
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));
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
    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);
    cfg.member_ids     = committee_pks;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;

    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(cfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);

    a.core->get_blockchain_storage().queue_dao_v2_dkg_result(std::string{}, dkg_out);
    a.core->get_blockchain_storage().maybe_process_dao_v2_dkg_results();

    // Neither node has the key record yet: persistence writes only the
    // local share. Both records must still be absent.
    dao::dao_tally_key_record key_rec_a;
    dao::dao_tally_key_record key_rec_b;
    EXPECT_FALSE(adb.get_dao_tally_key(key_rec_a));
    EXPECT_FALSE(bdb.get_dao_tally_key(key_rec_b));

    // Build the activation certificate. Sign with members 1 and 2
    // (threshold = 2 of 3).
    const uint64_t act_height = a.core->get_current_blockchain_height();
    const uint64_t selection_height = act_height - 1;

    const crypto::hash genesis_hash =
        a.core->get_blockchain_storage().get_db()
            .get_block_hash_from_height(0);
    ASSERT_NE(genesis_hash, crypto::null_hash);

    const crypto::hash digest = dao::dao_dkg_activation_digest(genesis_hash, selection_height, dkg_out.record, crypto::null_hash);
    ASSERT_NE(digest, crypto::null_hash);

    dao::dao_dkg_key_activation act;
    act.version          = 2;
    act.selection_height = selection_height;
    act.record           = dkg_out.record;
    for (uint32_t idx : { 1u, 2u }) {
        crypto::signature sig;
        crypto::generate_signature(digest,
                                    committee_pks[idx - 1],
                                    committee_sks[idx - 1], sig);
        dao::dao_dkg_key_attestation att;
        att.member_index = idx;
        att.signature.resize(sizeof(crypto::signature));
        std::memcpy(att.signature.data(), &sig,
                    sizeof(crypto::signature));
        act.attestations.push_back(att);
    }

    // Build the activation transaction by direct field assignment.
    std::vector<uint8_t> act_blob;
    ASSERT_TRUE(act.serialize(act_blob));

    governance_payload gp;
    gp.type = governance_object::dkg_key_activation;
    gp.data = std::move(act_blob);

    tx_extra_governance_payload txgp;
    txgp.payload = std::move(gp);
    tx_extra_field extra_field = txgp;
    const std::string extra_blob =
        t_serializable_object_to_blob(extra_field);

    transaction act_tx{};
    act_tx.version = 2;
    act_tx.unlock_time = 0;
    act_tx.extra.assign(extra_blob.begin(), extra_blob.end());
    act_tx.rct_signatures = rct::rctSig{};
    act_tx.rct_signatures.type = rct::RCTTypeNull;

    // --------------------------------------------------------------
    // Mempool admission path. This exercises the fee bypass, the
    // MAX_TX_EXTRA_SIZE exception, the zero-input relay exception and
    // the full activation-certificate validator that the direct
    // block-supplement path bypasses.
    // --------------------------------------------------------------
    {
        const cryptonote::blobdata act_blob = tx_to_blob(act_tx);
        tx_verification_context tvc{};
        ASSERT_TRUE(a.core->handle_incoming_tx(
            act_blob, tvc, relay_method::local, false));
        EXPECT_FALSE(tvc.m_verifivation_failed);

        std::vector<crypto::hash> pool_hashes;
        a.core->get_pool_transaction_hashes(pool_hashes);
        const crypto::hash act_txid_pool = get_transaction_hash(act_tx);
        EXPECT_NE(std::find(pool_hashes.begin(), pool_hashes.end(),
                            act_txid_pool),
                  pool_hashes.end());
    }

    // Corrupt one attestation signature and assert mempool rejection.
    {
        dao::dao_dkg_key_activation bad = act;
        ASSERT_FALSE(bad.attestations.empty());
        ASSERT_FALSE(bad.attestations[0].signature.empty());
        bad.attestations[0].signature[0] ^= 0xFF;

        std::vector<uint8_t> bad_blob;
        ASSERT_TRUE(bad.serialize(bad_blob));

        governance_payload gp2;
        gp2.type = governance_object::dkg_key_activation;
        gp2.data = std::move(bad_blob);
        tx_extra_governance_payload txgp2;
        txgp2.payload = std::move(gp2);
        tx_extra_field extra2 = txgp2;
        const std::string extra2_blob =
            t_serializable_object_to_blob(extra2);

        transaction bad_tx{};
        bad_tx.version = 2;
        bad_tx.unlock_time = 0;
        bad_tx.extra.assign(extra2_blob.begin(), extra2_blob.end());
        bad_tx.rct_signatures = rct::rctSig{};
        bad_tx.rct_signatures.type = rct::RCTTypeNull;

        const cryptonote::blobdata bad_tx_blob = tx_to_blob(bad_tx);
        tx_verification_context tvc_bad{};
        EXPECT_FALSE(a.core->handle_incoming_tx(
            bad_tx_blob, tvc_bad, relay_method::local, false));
        EXPECT_TRUE(tvc_bad.m_verifivation_failed);

        std::vector<crypto::hash> pool_hashes;
        a.core->get_pool_transaction_hashes(pool_hashes);
        const crypto::hash bad_txid = get_transaction_hash(bad_tx);
        EXPECT_EQ(std::find(pool_hashes.begin(), pool_hashes.end(),
                            bad_txid),
                  pool_hashes.end());
    }

    // Build and feed the activation block to both nodes.
    std::vector<transaction> extra_txs{ act_tx };
    block blk_act;
    ASSERT_TRUE(construct_block_here(a, miner_acc, act_height,
                                      extra_txs, blk_act));
    cryptonote::blobdata blk_act_blob = cryptonote::block_to_blob(blk_act);

    const crypto::hash act_txid = get_transaction_hash(act_tx);
    for (ReplayNode* n : { &a, &b }) {
        block_verification_context bvc{};
        pool_supplement e{};
        e.txs_by_txid.emplace(
            act_txid,
            std::make_pair(act_tx, tx_to_blob(act_tx)));
        ASSERT_TRUE(n->core->handle_single_incoming_block(
            blk_act_blob, &blk_act, bvc, e, false));
        EXPECT_FALSE(bvc.m_verifivation_failed);
    }

    // Both nodes now reconstruct the key record and the active
    // by replaying the activation block alone.
    ASSERT_TRUE(adb.get_dao_tally_key(key_rec_a));
    ASSERT_TRUE(bdb.get_dao_tally_key(key_rec_b));
    EXPECT_EQ(key_rec_a.key_id, key_rec_b.key_id);
    EXPECT_EQ(key_rec_a.committee_size, key_rec_b.committee_size);
    EXPECT_EQ(key_rec_a.threshold, key_rec_b.threshold);
    {
        uint32_t e_a = 0, e_b = 0;
    }

    // No block on disk contains the private share.
    {
        const std::vector<uint8_t>& sk = dkg_out.local_secret_share;
        ASSERT_FALSE(sk.empty());
        const std::string needle(sk.begin(), sk.end());
        EXPECT_EQ(blk_act_blob.find(needle), std::string::npos);
    }

    // --------------------------------------------------------------
    // Replay the tally-result block on the freshly replayed key
    // record. Both nodes must derive the same outcome from chain
    // state alone.
    // --------------------------------------------------------------
    const uint64_t tally_height = a.core->get_current_blockchain_height();
    const uint64_t VOTE_END     = tally_height - 1;

    const crypto::hash prop_id = []{
        crypto::hash h{};
        std::memset(h.data, 0xEE, 32);
        return h;
    }();

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));
    BIGNUM* W = BN_new(); BN_set_word(W, 1000);
    BIGNUM* S = BN_new(); BN_set_word(S, 1000);
    BIGNUM* B = BN_new(); BN_set_word(B, 5000);
    BIGNUM* r1 = BN_new(); BN_set_word(r1, 3);
    BIGNUM* r2 = BN_new(); BN_set_word(r2, 5);
    BIGNUM* r3 = BN_new(); BN_set_word(r3, 7);
    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(W, r1, E_W));
    ASSERT_TRUE(pk.encrypt(S, r2, E_S));
    ASSERT_TRUE(pk.encrypt(B, r3, E_B));
    const crypto::hash agg_hash =
        dao::dao_aggregate_ciphertext_hash(E_W, E_S, E_B);

    for (auto* db_ptr : { &adb, &bdb }) {
        db_wtxn_guard g(db_ptr);

        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        std::memset(rec.tally_key_id.data, 0, 32);
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_ptr->add_proposal_record(prop_id, rec);

        dao_proposal_aggregate agg;
        agg.aggregate_E_W = E_W;
        agg.aggregate_E_S = E_S;
        agg.aggregate_E_B = E_B;
        agg.aggregate_C_W = rct::identity();
        agg.aggregate_C_S = rct::identity();
        agg.aggregate_C_B = rct::identity();
        db_ptr->add_dao_proposal_aggregate(prop_id, agg);

        dao::dao_supply_snapshot snap;
        snap.height = VOTE_END;
        snap.minted = dao::dao_u128(100000);
        snap.circulating = dao::dao_u128(50000);
        db_ptr->add_dao_supply_snapshot(snap);
    }

    // Produce share 1 with Node A (member 1) and share 2 directly
    // using the test oracle for member 2.
    a.core->get_blockchain_storage().set_dao_v2_dkg_send(
        [](const std::string&) -> bool { return true; });
    dao::dao_v2_tally_share first_share;
    bool captured_first = false;
    a.core->get_blockchain_storage().set_dao_v2_tally_broadcast(
        [&](const dao::dao_v2_tally_share& s) {
            first_share = s; captured_first = true;
        });
    {
        db_wtxn_guard g(&adb);
        a.core->get_blockchain_storage().maybe_produce_dao_v2_share(
            VOTE_END + 1);
    }
    ASSERT_TRUE(captured_first);

    dao::dao_v2_tally_share second_share{};
    second_share.version = 1;
    second_share.proposal_id = prop_id;
    second_share.vote_end_height = VOTE_END;
    second_share.tally_key_id.assign(32, 0);
    second_share.member_index = 2;
    second_share.aggregate_ciphertext_hash = agg_hash;
    {
        BIGNUM* dkg_sk = nullptr;
        const std::string dec(dkg_out.test_SK[1].begin(),
                              dkg_out.test_SK[1].end());
        BN_dec2bn(&dkg_sk, dec.c_str());
        ASSERT_NE(dkg_sk, nullptr);
        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& po,
                              dao::dao_partial_decryption_proof& proof)
                              -> bool {
            std::vector<uint8_t> ci;
            if (!dao::dao_threshold_partial_decrypt(pk, c, dkg_sk, ci))
                return false;
            BIGNUM* r = BN_new();
            if (!dao::dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao::dao_partial_decryption_prove(
                pk, dkg_out.record.V, dkg_out.record.V_K_i[1], 2,
                c, ci, dkg_sk, r, proof);
            BN_free(r);
            if (!ok) return false;
            po = std::move(ci);
            return true;
        };
        ASSERT_TRUE(do_channel(E_W, second_share.partial_W,
                                second_share.proof_W));
        ASSERT_TRUE(do_channel(E_S, second_share.partial_S,
                                second_share.proof_S));
        ASSERT_TRUE(do_channel(E_B, second_share.partial_B,
                                second_share.proof_B));
        BN_free(dkg_sk);
    }

    std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
    shares[committee_pks[0]] = first_share;
    shares[committee_pks[1]] = second_share;

    const governance_params params = governance_params::default_params();
    cryptonote::TallyManager tm(adb, params);
    transaction result_tx;
    ASSERT_TRUE(tm.build_tally_result_transaction(
        prop_id, shares, key_rec_a.threshold, result_tx));

    std::vector<transaction> tally_txs{ result_tx };
    block blk_tally;
    ASSERT_TRUE(construct_block_here(a, miner_acc, tally_height,
                                      tally_txs, blk_tally));
    cryptonote::blobdata blk_tally_blob =
        cryptonote::block_to_blob(blk_tally);

    const crypto::hash result_txid = get_transaction_hash(result_tx);
    for (ReplayNode* n : { &a, &b }) {
        block_verification_context bvc{};
        pool_supplement e{};
        e.txs_by_txid.emplace(
            result_txid,
            std::make_pair(result_tx, tx_to_blob(result_tx)));
        ASSERT_TRUE(n->core->handle_single_incoming_block(
            blk_tally_blob, &blk_tally, bvc, e, false));
        EXPECT_FALSE(bvc.m_verifivation_failed);
    }

    // Both nodes carry identical outcomes.
    dao::dao_v2_outcome_record out_a, out_b;
    ASSERT_TRUE(adb.get_dao_v2_outcome(prop_id, out_a));
    ASSERT_TRUE(bdb.get_dao_v2_outcome(prop_id, out_b));
    EXPECT_EQ(out_a.passed, out_b.passed);

    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
    boost::filesystem::remove_all(base);
}



// ---------------------------------------------------------------------
// Real V2 vote path.
//
// Mine empty blocks with a controlled miner account, enumerate the
// owned coinbase outputs, construct a real vote_proof_v2 via
// build_dao_v2_vote() on a ring of those outputs, wrap it in a
// txin_vns_vote transaction carrying a governance_object::vote_v2
// payload, submit it through handle_incoming_tx(), mine it into a
// block, feed the block to the node, and assert that the vote was
// counted and its nullifier stored.
//
// This is the missing end-to-end vote path: real coinbase outputs,
// real derived spend secret, real Paillier ciphertexts, real CLSAGs,
// real transcript, real block-apply through GovernanceManager.
// ---------------------------------------------------------------------
namespace {

// Pull the vote_proof_v2 out of a vote_v2 payload. Used by the fixture
// to expose the proof for downstream assertions without duplicating
// the wrapping logic.
bool VoteManager_ExtractProofForTest(const cryptonote::transaction& tx,
                                     cryptonote::vote_proof_v2& out)
{
    std::vector<cryptonote::tx_extra_field> fields;
    if (!cryptonote::parse_tx_extra(tx.extra, fields))
        return false;
    for (const auto& f : fields) {
        if (f.type() != typeid(cryptonote::tx_extra_governance_payload))
            continue;
        const auto& gp = boost::get<cryptonote::tx_extra_governance_payload>(f).payload;
        if (gp.type != cryptonote::governance_object::vote_v2)
            continue;
        epee::span<const uint8_t> sp(gp.data.data(), gp.data.size());
        binary_archive<false> ar(sp);
        return ::serialization::serialize(ar, out);
    }
    return false;
}

struct V2VoteFixture
{
    boost::filesystem::path                  base;
    std::unique_ptr<ReplayNode>              node;
    account_base                             miner_acc;
    crypto::hash                             prop_id{};
    cryptonote::dao::dao_tally_key_record    key_rec;
    crypto::hash                             tally_key_id{};
    uint64_t                                 chain_height = 0;
    uint64_t                                 vote_height  = 0;
    uint64_t                                 prop_submit  = 0;
    cryptonote::dao::dao_v2_vote_output      vote_output;
    cryptonote::transaction                  vote_tx;
    cryptonote::vote_proof_v2                proof;
    size_t                                   serialized_proof_bytes = 0;

    ~V2VoteFixture()
    {
        node.reset();
        if (!base.empty())
            boost::filesystem::remove_all(base);
    }
};

bool build_v2_vote_fixture(V2VoteFixture& fx, const std::string& tag)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    fx.base = boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_" + tag + "_%%%%-%%%%");
    fx.node.reset(new ReplayNode);
    if (!fx.node->init((fx.base / "a").string())) return false;

    auto& bc_a = fx.node->core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();
    bc_a.set_dao_v2_active_for_test(true);

    fx.miner_acc.generate();

    // 3-party bootstrap DKG for a real key record.
    std::vector<crypto::public_key> cps;
    std::vector<crypto::secret_key> css;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        cps.push_back(pk); css.push_back(sk);
    }
    {
        std::vector<size_t> idx = {0,1,2};
        std::sort(idx.begin(), idx.end(), [&](size_t x, size_t y){
            return std::memcmp(cps[x].data, cps[y].data, 32) < 0; });
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : idx) { p2.push_back(cps[i]); s2.push_back(css[i]); }
        cps = std::move(p2); css = std::move(s2);
    }
    fx.node->core->set_node_key(css[0]);

    dao_vss_group vss;
    if (!dao_vss_group_generate(vss,
            dao_dkg_required_vss_bits(60, 128, 32)))
        return false;
    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);
    cfg.member_ids     = cps;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;
    dkg_result dkg_out;
    if (!dkg_run_with_transport(cfg, factory, dkg_out)) return false;
    if (!dkg_out.candidate_accepted) return false;
    if (dkg_out.record.key_id.size() != 32) return false;
    if (dkg_out.record.N.size() != 256) return false;
    fx.key_rec = dkg_out.record;
    bc_a.install_dao_tally_key_for_test(dkg_out.record);

    // Mine empty blocks so real coinbase outputs exist.
    for (int i = 0; i < 5; ++i) {
        const uint64_t h = fx.node->core->get_current_blockchain_height();
        block blk;
        if (!construct_block_here(*fx.node, fx.miner_acc, h, {}, blk))
            return false;
        cryptonote::blobdata bb = cryptonote::block_to_blob(blk);
        block_verification_context bvc{};
        pool_supplement e{};
        if (!fx.node->core->handle_single_incoming_block(
                bb, &blk, bvc, e, false))
            return false;
        if (bvc.m_verifivation_failed) return false;
    }

    // Enumerate owned coinbase outputs.
    struct OwnedOutput {
        uint64_t           global_index;
        crypto::public_key pubkey;
        rct::key           commitment;
        uint64_t           height;
        uint64_t           amount;
        crypto::secret_key output_secret;
    };
    std::vector<OwnedOutput> owned;
    {
        const uint64_t n = db_a.get_num_outputs(0);
        for (uint64_t g = 0; g < n; ++g) {
            output_data_t od;
            try { od = db_a.get_output_key_from_global(g); }
            catch (...) { continue; }
            tx_out_index toi;
            try { toi = db_a.get_output_tx_and_index_from_global(g); }
            catch (...) { continue; }
            transaction tx;
            if (!db_a.get_tx(toi.first, tx)) continue;
            if (tx.vin.empty() ||
                tx.vin[0].type() != typeid(txin_gen)) continue;
            const crypto::public_key tx_pub =
                get_tx_pub_key_from_extra(tx);
            if (tx_pub == crypto::null_pkey) continue;
            crypto::key_derivation der;
            if (!crypto::generate_key_derivation(
                    tx_pub, fx.miner_acc.get_keys().m_view_secret_key, der))
                continue;
            crypto::public_key expected;
            if (!crypto::derive_public_key(
                    der, toi.second,
                    fx.miner_acc.get_keys().m_account_address.m_spend_public_key,
                    expected))
                continue;
            if (std::memcmp(&expected, &od.pubkey, 32) != 0) continue;
            block blk;
            try { blk = db_a.get_block_from_height(od.height); }
            catch (...) { continue; }
            if (toi.second >= blk.miner_tx.vout.size()) continue;
            crypto::ec_scalar der_scalar;
            crypto::derivation_to_scalar(der, toi.second, der_scalar);
            OwnedOutput oo{};
            oo.global_index = g;
            oo.pubkey       = od.pubkey;
            oo.commitment   = od.commitment;
            oo.height       = od.height;
            oo.amount       = blk.miner_tx.vout[toi.second].amount;
            {
                rct::key der_k{};   std::memcpy(der_k.bytes,
                    der_scalar.data, 32);
                rct::key spend_k{}; std::memcpy(spend_k.bytes,
                    fx.miner_acc.get_keys().m_spend_secret_key.data, 32);
                rct::key out_k{};
                sc_add(out_k.bytes, der_k.bytes, spend_k.bytes);
                std::memcpy(oo.output_secret.data, out_k.bytes, 32);
            }
            owned.push_back(oo);
        }
    }
    if (owned.size() < 4) return false;
    std::sort(owned.begin(), owned.end(),
              [](const OwnedOutput& x, const OwnedOutput& y) {
                  return x.global_index < y.global_index; });

    // Proposal record the verifier reads.
    fx.chain_height = fx.node->core->get_current_blockchain_height();
    fx.vote_height  = fx.chain_height + 1;
    const uint64_t prop_submit = fx.chain_height - 1;
    fx.prop_submit  = prop_submit;
    const uint64_t prop_end    = fx.vote_height + 100;
    std::memset(fx.prop_id.data, 0x5A, 32);

    proposal_record rec{};
    rec.proposal_id        = fx.prop_id;
    rec.voting_period_days = 7;
    rec.submission_height  = prop_submit;
    rec.voting_end_height  = prop_end;
    std::memcpy(rec.tally_key_id.data, fx.key_rec.key_id.data(), 32);
    rec.submission_tx_hash = fx.prop_id;
    rec.status             = PROPOSAL_STATUS_ACTIVE;
    rec.status_height      = prop_submit;
    {
        db_wtxn_guard g(&db_a);
        db_a.add_proposal_record(fx.prop_id, rec);
    }

    // One vote output on a ring of 4 owned coinbase outputs. The
    // ring is expressed in the shared dao_v2_vote_output shape, which
    // is exactly the input type of dao::build_dao_v2_vote_tx() -- the
    // same function wallet2::create_vote_v2_tx() now calls.
    dao::dao_v2_vote_output vo;
    vo.ring.reserve(4);
    for (size_t i = 0; i < 4; ++i) {
        dao::dao_v2_ring_member_data rm;
        rm.P = rct::pk2rct(owned[i].pubkey);
        rm.C = owned[i].commitment;
        rm.global_index = owned[i].global_index;
        rm.height       = owned[i].height;
        vo.ring.push_back(std::move(rm));
    }
    vo.real_index    = 0;
    vo.output_secret = owned[0].output_secret;
    {
        // BlockchainDB::add_block() stores every coinbase v2 output
        // with rct::zeroCommit(amount) == G + amount*H, so the
        // Pedersen mask is the scalar one.
        rct::key one{};
        one.bytes[0] = 1;
        vo.mask = one;
    }
    vo.amount = owned[0].amount;

    fx.vote_output = vo;
    std::memcpy(fx.tally_key_id.data, fx.key_rec.key_id.data(), 32);

    // Build the transaction via the same shared helper that the wallet
    // uses. The fixture keeps the proof for later assertions.
    if (!dao::build_dao_v2_vote_tx(
            fx.prop_id, prop_submit, fx.vote_height, fx.tally_key_id,
            fx.key_rec.N, /*direction=YES*/ 0,
            std::vector<dao::dao_v2_vote_output>{vo}, fx.vote_tx))
        return false;

    if (!VoteManager_ExtractProofForTest(fx.vote_tx, fx.proof))
        return false;
    fx.serialized_proof_bytes =
        cryptonote::t_serializable_object_to_blob(fx.proof).size();

    return true;
}

} // namespace

// ---------------------------------------------------------------------
// Real V2 vote path.
//
// Real coinbase outputs, real derived spend secret, real Paillier
// ciphertexts, real CLSAGs, real transcript, and a real block-apply
// through GovernanceManager. Asserts the outer transaction shape is
// the zero-input, zero-output version-3 form, that the payload
// exceeds the legacy MAX_TX_EXTRA_SIZE limit, and that the legacy
// input-based V1 classifier does not match.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, RealVoteTxEntersPoolAndBlock)
{
    using namespace cryptonote;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "vote"));

    // Shape assertions.
    EXPECT_EQ(fx.vote_tx.version, (size_t)TX_VERSION_DAO_VOTE);
    EXPECT_TRUE(fx.vote_tx.vin.empty());
    EXPECT_TRUE(fx.vote_tx.vout.empty());
    EXPECT_EQ(fx.vote_tx.rct_signatures.type, rct::RCTTypeNull);
    EXPECT_GT(fx.vote_tx.extra.size(), (size_t)MAX_TX_EXTRA_SIZE);
    EXPECT_GT(fx.serialized_proof_bytes, (size_t)MAX_TX_EXTRA_SIZE);
    EXPECT_TRUE(is_dao_v2_vote_tx(fx.vote_tx));
    EXPECT_FALSE(is_vote_tx(fx.vote_tx));

    auto& db_a = fx.node->core->get_blockchain_storage().get_db();

    // Mempool admission.
    {
        const cryptonote::blobdata vb = tx_to_blob(fx.vote_tx);
        tx_verification_context tvc{};
        ASSERT_TRUE(fx.node->core->handle_incoming_tx(
            vb, tvc, relay_method::local, false));
        EXPECT_FALSE(tvc.m_verifivation_failed);

        std::vector<crypto::hash> pool_hashes;
        fx.node->core->get_pool_transaction_hashes(pool_hashes);
        const crypto::hash vote_txid = get_transaction_hash(fx.vote_tx);
        EXPECT_NE(std::find(pool_hashes.begin(), pool_hashes.end(),
                            vote_txid),
                  pool_hashes.end());
    }

    // Mine and apply.
    {
        block blk;
        ASSERT_TRUE(construct_block_here(*fx.node, fx.miner_acc,
                                          fx.chain_height, {fx.vote_tx},
                                          blk));
        cryptonote::blobdata bb = cryptonote::block_to_blob(blk);
        block_verification_context bvc{};
        pool_supplement e{};
        e.txs_by_txid.emplace(
            get_transaction_hash(fx.vote_tx),
            std::make_pair(fx.vote_tx, tx_to_blob(fx.vote_tx)));
        ASSERT_TRUE(fx.node->core->handle_single_incoming_block(
            bb, &blk, bvc, e, false));
        EXPECT_FALSE(bvc.m_verifivation_failed);
    }

    // Aggregate and nullifier written.
    dao_proposal_aggregate agg;
    ASSERT_TRUE(db_a.get_dao_proposal_aggregate(fx.prop_id, agg));
    EXPECT_FALSE(agg.aggregate_E_W.empty());
    EXPECT_FALSE(agg.aggregate_E_S.empty());
    EXPECT_FALSE(agg.aggregate_E_B.empty());
    EXPECT_TRUE(!(agg.aggregate_C_W == rct::identity()));
    EXPECT_TRUE(!(agg.aggregate_C_B == rct::identity()));

    EXPECT_TRUE(db_a.has_vote_nullifier(fx.prop_id,
                                         fx.proof.nullifiers[0]));
}

// ---------------------------------------------------------------------
// Reorg rollback of a V2 vote.
//
// A block containing a V2 vote is added, the aggregate and nullifier
// are written, and the block is then popped. VoteManager::rollback_block
// must remove both the aggregate contribution and the nullifier, so
// the same vote can be re-included on the new chain. The proposal
// record itself must be untouched.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, ReorgRollsBackV2Vote)
{
    using namespace cryptonote;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "votereorg"));

    auto& db_a = fx.node->core->get_blockchain_storage().get_db();

    // Admit and mine.
    {
        const cryptonote::blobdata vb = tx_to_blob(fx.vote_tx);
        tx_verification_context tvc{};
        ASSERT_TRUE(fx.node->core->handle_incoming_tx(
            vb, tvc, relay_method::local, false));
        ASSERT_FALSE(tvc.m_verifivation_failed);
    }
    {
        block blk;
        ASSERT_TRUE(construct_block_here(*fx.node, fx.miner_acc,
                                          fx.chain_height, {fx.vote_tx},
                                          blk));
        cryptonote::blobdata bb = cryptonote::block_to_blob(blk);
        block_verification_context bvc{};
        pool_supplement e{};
        e.txs_by_txid.emplace(
            get_transaction_hash(fx.vote_tx),
            std::make_pair(fx.vote_tx, tx_to_blob(fx.vote_tx)));
        ASSERT_TRUE(fx.node->core->handle_single_incoming_block(
            bb, &blk, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    // Pre-pop: aggregate present, nullifier recorded.
    {
        dao_proposal_aggregate agg;
        ASSERT_TRUE(db_a.get_dao_proposal_aggregate(fx.prop_id, agg));
        ASSERT_TRUE(db_a.has_vote_nullifier(fx.prop_id,
                                             fx.proof.nullifiers[0]));
    }

    const uint64_t height_before =
        fx.node->core->get_current_blockchain_height();
    ASSERT_EQ(height_before, fx.chain_height + 1);

    // Pop the block containing the vote.
    fx.node->core->get_blockchain_storage().pop_blocks(1);

    const uint64_t height_after =
        fx.node->core->get_current_blockchain_height();
    ASSERT_EQ(height_after, fx.chain_height);

    // Nullifier removed.
    EXPECT_FALSE(db_a.has_vote_nullifier(fx.prop_id,
                                          fx.proof.nullifiers[0]));

    // Aggregate removed (byte-for-byte rollback: when the aggregate
    // returns to identity, the row is deleted, not persisted).
    {
        dao_proposal_aggregate agg;
        EXPECT_FALSE(db_a.get_dao_proposal_aggregate(fx.prop_id, agg));
    }

    // Proposal record is untouched.
    proposal_record rec;
    ASSERT_TRUE(db_a.get_proposal_record(fx.prop_id, rec));
    EXPECT_EQ(rec.status, PROPOSAL_STATUS_ACTIVE);
}

// ---------------------------------------------------------------------
// Successive multi-block pop.
//
// pop_blocks(2) must remove two blocks cleanly, leaving the chain at
// the expected height, and must not throw MDB_NOTFOUND from the
// hard-fork rollback path. The two-block variant exercises the
// on_block_popped loop more than once and the batch is stopped once at
// the end, not per pop.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, MultiBlockPopSucceeds)
{
    using namespace cryptonote;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "multipop"));

    const uint64_t h0 = fx.node->core->get_current_blockchain_height();
    ASSERT_GE(h0, 3u);

    fx.node->core->get_blockchain_storage().pop_blocks(2);

    const uint64_t h1 = fx.node->core->get_current_blockchain_height();
    EXPECT_EQ(h1, h0 - 2);
}

// ---------------------------------------------------------------------
// Oversized V2 vote extra.
//
// A zero-input version-3 vote whose governance payload exceeds the
// 128 KiB ceiling must be rejected by the mempool AND by block
// validation, even though the classifier still recognises it.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, OversizedV2VoteExtraRejectedByMempoolAndBlock)
{
    using namespace cryptonote;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "votebig"));

    // Rebuild the tx with a payload larger than the ceiling. The
    // classifier only inspects the outer shape, so the extra can be
    // padded without changing the shape.
    transaction big_tx = fx.vote_tx;
    {
        std::vector<uint8_t> padded(
            DAO_VOTE_V2_MAX_EXTRA_BYTES + 4096, 0x00);

        governance_payload gp;
        gp.type = governance_object::vote_v2;
        gp.data = std::move(padded);

        tx_extra_governance_payload txgp;
        txgp.payload = std::move(gp);
        tx_extra_field ef = txgp;
        const std::string extra_blob = t_serializable_object_to_blob(ef);
        big_tx.extra.assign(extra_blob.begin(), extra_blob.end());
    }
    ASSERT_GT(big_tx.extra.size(), DAO_VOTE_V2_MAX_EXTRA_BYTES);
    ASSERT_TRUE(is_dao_v2_vote_tx(big_tx));

    // Mempool must reject.
    {
        const cryptonote::blobdata bb = tx_to_blob(big_tx);
        tx_verification_context tvc{};
        EXPECT_FALSE(fx.node->core->handle_incoming_tx(
            bb, tvc, relay_method::local, false));
        EXPECT_TRUE(tvc.m_verifivation_failed);

        std::vector<crypto::hash> pool_hashes;
        fx.node->core->get_pool_transaction_hashes(pool_hashes);
        const crypto::hash big_txid = get_transaction_hash(big_tx);
        EXPECT_EQ(std::find(pool_hashes.begin(), pool_hashes.end(),
                            big_txid),
                  pool_hashes.end());
    }

    // Block validation must reject even when the mempool is skipped.
    {
        block blk;
        ASSERT_TRUE(construct_block_here(*fx.node, fx.miner_acc,
                                          fx.chain_height, {big_tx}, blk));
        cryptonote::blobdata bb = cryptonote::block_to_blob(blk);
        block_verification_context bvc{};
        pool_supplement e{};
        e.txs_by_txid.emplace(
            get_transaction_hash(big_tx),
            std::make_pair(big_tx, tx_to_blob(big_tx)));
        const bool ok = fx.node->core->handle_single_incoming_block(
            bb, &blk, bvc, e, false);
        EXPECT_FALSE(ok && !bvc.m_verifivation_failed);
        EXPECT_TRUE(bvc.m_verifivation_failed);
    }
}

// ---------------------------------------------------------------------
// Invalid V2 proof.
//
// A tampered vote_proof_v2 must be rejected by the mempool dry-run.
// VoteProofVerifier step 21 rejects a non-canonical Paillier
// ciphertext, so a single bit flip in E_W is sufficient.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, InvalidV2VoteProofRejectedByMempool)
{
    using namespace cryptonote;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "votebad"));

    // Tamper one byte of E_W.
    vote_proof_v2 bad = fx.proof;
    bad.E_W.data[0] ^= 0xFF;

    transaction bad_tx = fx.vote_tx;
    {
        const std::string proof_blob =
            cryptonote::t_serializable_object_to_blob(bad);
        governance_payload gp;
        gp.type = governance_object::vote_v2;
        gp.data.assign(proof_blob.begin(), proof_blob.end());
        tx_extra_governance_payload txgp;
        txgp.payload = std::move(gp);
        tx_extra_field ef = txgp;
        const std::string extra_blob = t_serializable_object_to_blob(ef);
        bad_tx.extra.assign(extra_blob.begin(), extra_blob.end());
    }
    ASSERT_TRUE(is_dao_v2_vote_tx(bad_tx));

    const cryptonote::blobdata bb = tx_to_blob(bad_tx);
    tx_verification_context tvc{};
    EXPECT_FALSE(fx.node->core->handle_incoming_tx(
        bb, tvc, relay_method::local, false));
    EXPECT_TRUE(tvc.m_verifivation_failed);

    std::vector<crypto::hash> pool_hashes;
    fx.node->core->get_pool_transaction_hashes(pool_hashes);
    const crypto::hash bad_txid = get_transaction_hash(bad_tx);
    EXPECT_EQ(std::find(pool_hashes.begin(), pool_hashes.end(),
                        bad_txid),
              pool_hashes.end());
}

// ---------------------------------------------------------------------
// Duplicate nullifier.
//
// A V2 vote that was already applied to the chain must be rejected
// when resubmitted. VoteProofVerifier step27 checks prior-chain DAO
// nullifiers before VoteManager can write a second aggregate.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, DuplicateV2VoteNullifierRejected)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "votedup"));

    auto& db_a = fx.node->core->get_blockchain_storage().get_db();

    // First submission and inclusion.
    {
        const cryptonote::blobdata vb = tx_to_blob(fx.vote_tx);
        tx_verification_context tvc{};
        ASSERT_TRUE(fx.node->core->handle_incoming_tx(
            vb, tvc, relay_method::local, false));
        ASSERT_FALSE(tvc.m_verifivation_failed);
    }
    {
        block blk;
        ASSERT_TRUE(construct_block_here(*fx.node, fx.miner_acc,
                                          fx.chain_height, {fx.vote_tx},
                                          blk));
        cryptonote::blobdata bb = cryptonote::block_to_blob(blk);
        block_verification_context bvc{};
        pool_supplement e{};
        e.txs_by_txid.emplace(
            get_transaction_hash(fx.vote_tx),
            std::make_pair(fx.vote_tx, tx_to_blob(fx.vote_tx)));
        ASSERT_TRUE(fx.node->core->handle_single_incoming_block(
            bb, &blk, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }
    ASSERT_TRUE(db_a.has_vote_nullifier(fx.prop_id,
                                         fx.proof.nullifiers[0]));

    // Build a SECOND, independent proof from the same output. The
    // CLSAG randomness makes the tx hash different, but the
    // proposal-scoped nullifier x*H_vote(P, proposal_id) is
    // deterministic and must match the first one.
    transaction tx2{};
    ASSERT_TRUE(dao::build_dao_v2_vote_tx(
        fx.prop_id, fx.prop_submit, fx.vote_height + 1,
        fx.tally_key_id, fx.key_rec.N, /*direction=YES*/ 0,
        std::vector<dao::dao_v2_vote_output>{fx.vote_output}, tx2));

    vote_proof_v2 proof2;
    ASSERT_TRUE(VoteManager_ExtractProofForTest(tx2, proof2));
    ASSERT_EQ(proof2.nullifiers.size(), 1u);
    EXPECT_EQ(std::memcmp(proof2.nullifiers[0].data,
                          fx.proof.nullifiers[0].data, 32), 0);

    EXPECT_NE(get_transaction_hash(tx2), get_transaction_hash(fx.vote_tx));
    EXPECT_TRUE(is_dao_v2_vote_tx(tx2));

    // The chain-committed nullifier must reject the fresh proof.
    {
        const cryptonote::blobdata vb2 = tx_to_blob(tx2);
        tx_verification_context tvc{};
        EXPECT_FALSE(fx.node->core->handle_incoming_tx(
            vb2, tvc, relay_method::local, false));
        EXPECT_TRUE(tvc.m_verifivation_failed);

        std::vector<crypto::hash> pool_hashes;
        fx.node->core->get_pool_transaction_hashes(pool_hashes);
        const crypto::hash id2 = get_transaction_hash(tx2);
        EXPECT_EQ(std::find(pool_hashes.begin(), pool_hashes.end(), id2),
                  pool_hashes.end());
    }
}



// ---------------------------------------------------------------------
// Coinbase overpayment.
//
// A block whose coinbase pays more than the permitted fixed subsidy
// must be rejected. Overpayment by a single atomic unit is enough.
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Duplicate treasury execution for the same proposal must be rejected
// at block level. Two individually-valid execution transactions, each
// consuming a distinct unspent treasury output, both pointing at the
// same PASSED proposal, must not both apply. Without this guard the
// grant amount would be deducted twice while the proposal only
// transitions to EXECUTED once.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, RejectsDuplicateTreasuryExecutionInBlock)
{
    using namespace cryptonote;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_duptx_%%%%-%%%%");

    ReplayNode a;
    ASSERT_TRUE(a.init((base / "a").string()));

    account_base miner_acc;
    miner_acc.generate();

    // Mine one block so the chain has some depth.
    const uint64_t h0 = a.core->get_current_blockchain_height();
    block blk0;
    ASSERT_TRUE(construct_block_here(a, miner_acc, h0, {}, blk0));
    {
        cryptonote::blobdata blob0 = cryptonote::block_to_blob(blk0);
        block_verification_context bvc0{};
        pool_supplement e0{};
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            blob0, &blk0, bvc0, e0, false));
        ASSERT_FALSE(bvc0.m_verifivation_failed);
    }

    auto& bs = a.core->get_blockchain_storage();
    BlockchainDB& db = const_cast<BlockchainDB&>(bs.get_db());

    // Proposal + two treasury outputs, seeded directly.
    crypto::hash prop_id{};
    crypto::cn_fast_hash("vr-dup-prop", 11, prop_id);

    account_base recipient;
    recipient.generate();
    std::string recip_str = recipient.get_public_address_str(
        cryptonote::FAKECHAIN);

    const uint64_t proposal_amount = 10000;
    const uint64_t seed_height = h0;
    uint64_t out_id_1 = 0, out_id_2 = 0;
    {
        db_wtxn_guard g(&db);

        proposal_record rec{};
        rec.proposal_id = prop_id;
        rec.type = 0; // GRANT
        std::strncpy(rec.recipient, recip_str.c_str(),
                     sizeof(rec.recipient) - 1);
        rec.amount = proposal_amount;
        rec.voting_period_days = 7;
        rec.submission_height = seed_height;
        rec.voting_end_height = seed_height;
        rec.status = PROPOSAL_STATUS_PASSED;
        rec.status_height = seed_height;
        rec.recipient_view_public_key =
            recipient.get_keys().m_account_address.m_view_public_key;
        db.add_proposal_record(prop_id, rec);

        out_id_1 = db.add_treasury_output(proposal_amount, seed_height);
        out_id_2 = db.add_treasury_output(proposal_amount, seed_height);
    }

    // Build one exec tx per output, both pointing at the same proposal.
    auto build_exec = [&](uint64_t out_id) -> transaction {
        transaction tx;
        tx.version = 2;

        txin_treasury in{};
        in.proposal_id = prop_id;
        in.treasury_output_id = out_id;
        tx.vin.push_back(in);

        crypto::secret_key txkey;
        crypto::hash_to_scalar(prop_id.data, sizeof(prop_id), txkey);
        crypto::public_key txkey_pub;
        crypto::secret_key_to_public_key(txkey, txkey_pub);
        add_tx_pub_key_to_extra(tx, txkey_pub);

        crypto::key_derivation deriv;
        crypto::generate_key_derivation(
            recipient.get_keys().m_account_address.m_view_public_key,
            txkey, deriv);

        crypto::public_key eph_key;
        crypto::derive_public_key(
            deriv, 0,
            recipient.get_keys().m_account_address.m_spend_public_key,
            eph_key);

        tx_out payment_out;
        cryptonote::set_tx_out(proposal_amount, eph_key, false,
                               crypto::view_tag{}, payment_out);
        tx.vout.push_back(payment_out);

        tx.rct_signatures = rct::rctSig{};
        tx.rct_signatures.type = rct::RCTTypeNull;
        return tx;
    };

    transaction tx1 = build_exec(out_id_1);
    transaction tx2 = build_exec(out_id_2);

    const uint64_t apply_height = bs.get_current_blockchain_height();
    {
        tx_verification_context tvc1{}, tvc2{};
        uint64_t muh1 = 0, muh2 = 0;
        crypto::hash mui1{}, mui2{};
        EXPECT_TRUE(bs.check_tx_inputs(
            tx1, muh1, mui1, tvc1, false, apply_height));
        EXPECT_TRUE(bs.check_tx_inputs(
            tx2, muh2, mui2, tvc2, false, apply_height));
    }

    block bad_block;
    std::vector<transaction> both{ tx1, tx2 };
    ASSERT_TRUE(construct_block_here(
        a, miner_acc, apply_height, both, bad_block));

    cryptonote::blobdata bblob = cryptonote::block_to_blob(bad_block);
    block_verification_context bvc{};
    pool_supplement e{};
    e.txs_by_txid.emplace(get_transaction_hash(tx1),
                          std::make_pair(tx1, tx_to_blob(tx1)));
    e.txs_by_txid.emplace(get_transaction_hash(tx2),
                          std::make_pair(tx2, tx_to_blob(tx2)));

    (void)a.core->handle_single_incoming_block(
        bblob, &bad_block, bvc, e, false);

    EXPECT_TRUE(bvc.m_verifivation_failed);
    EXPECT_FALSE(bvc.m_added_to_main_chain);

    proposal_record after{};
    ASSERT_TRUE(db.get_proposal_record(prop_id, after));
    EXPECT_EQ(after.status, PROPOSAL_STATUS_PASSED);
    EXPECT_FALSE(after.executed);

    boost::filesystem::remove_all(base);
}

namespace {

inline void write_u64_le_ready(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}

dao::dkg_msg make_node_ready_msg_v2(
    const crypto::hash& genesis,
    const crypto::public_key& pk,
    const crypto::secret_key& sk,
    uint64_t height,
    const crypto::hash& block_hash)
{
    const char* domain = "VeilRoot-DAO-DKG-NODE-READY-V2";
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), domain, domain + std::strlen(domain));
    msg.insert(msg.end(), genesis.data, genesis.data + 32);
    msg.insert(msg.end(), pk.data, pk.data + 32);
    uint8_t h_le[8];
    write_u64_le_ready(h_le, height);
    msg.insert(msg.end(), h_le, h_le + 8);
    msg.insert(msg.end(), block_hash.data, block_hash.data + 32);
    crypto::hash digest{};
    crypto::cn_fast_hash(msg.data(), msg.size(), digest);
    crypto::signature sig{};
    crypto::generate_signature(digest, pk, sk, sig);

    dao::dkg_msg m;
    m.hdr.type         = dao::dkg_msg_type::node_ready;
    m.hdr.recipient_id = 0;
    m.bytes_a.resize(sizeof(crypto::signature));
    std::memcpy(m.bytes_a.data(), &sig, sizeof(crypto::signature));
    m.bytes_b.resize(8 + 32);
    write_u64_le_ready(m.bytes_b.data(), height);
    std::memcpy(m.bytes_b.data() + 8, block_hash.data, 32);
    return m;
}

void send_ready_via_core(cryptonote::core& c,
                         const crypto::public_key& sender,
                         const dao::dkg_msg& m)
{
    std::vector<uint8_t> wire;
    ASSERT_TRUE(m.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    c.get_blockchain_storage().handle_dao_v2_dkg_msg(sender, payload);
}

}  // namespace

// ---------------------------------------------------------------------
// Reorg eviction: a node_ready stored at (height H, hash X) must be
// evicted once the chain reorgs to a different hash at height H.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, NodeReadyEvictedAfterReorg)
{
    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_readyreorg_%%%%-%%%%");

    ReplayNode a;
    ASSERT_TRUE(a.init((base / "a").string()));

    account_base miner;
    miner.generate();

    for (int i = 0; i < 2; ++i) {
        uint64_t h = a.core->get_current_blockchain_height();
        block b;
        ASSERT_TRUE(construct_block_here(a, miner, h, {}, b));
        cryptonote::blobdata bb = cryptonote::block_to_blob(b);
        block_verification_context bvc{};
        pool_supplement e{};
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            bb, &b, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    auto& bs = a.core->get_blockchain_storage();
    ASSERT_EQ(bs.get_current_blockchain_height(), 3u);

    crypto::hash genesis{};
    ASSERT_TRUE(bs.get_dao_v2_genesis_hash(genesis));

    const crypto::hash old_hash_at_1 = bs.get_block_id_by_height(1);

    crypto::public_key peer_pk;
    crypto::secret_key peer_sk;
    crypto::generate_keys(peer_pk, peer_sk);

    dao::dkg_msg m = make_node_ready_msg_v2(
        genesis, peer_pk, peer_sk, 1, old_hash_at_1);
    send_ready_via_core(*a.core, peer_pk, m);

    ASSERT_TRUE(bs.has_dao_v2_ready_peer_for_test(peer_pk));

    // Reorg: pop blocks 1 and 2, remine a different block at height 1.
    bs.pop_blocks(2);
    ASSERT_EQ(bs.get_current_blockchain_height(), 1u);

    {
        block new_b1;
        ASSERT_TRUE(construct_block_here(
            a, miner, 1, {}, new_b1,
            [](block& b) { b.timestamp += 7; }));
        cryptonote::blobdata nb = cryptonote::block_to_blob(new_b1);
        block_verification_context bvc{};
        pool_supplement e{};
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            nb, &new_b1, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    const crypto::hash new_hash_at_1 = bs.get_block_id_by_height(1);
    ASSERT_NE(new_hash_at_1, old_hash_at_1);

    bs.evict_stale_dao_v2_ready_peers_for_test();
    EXPECT_FALSE(bs.has_dao_v2_ready_peer_for_test(peer_pk));

    boost::filesystem::remove_all(base);
}

TEST(DaoV2Replay, CoinbaseOverpaymentRejected)
{
    using namespace cryptonote;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_overpay_%%%%-%%%%");

    ReplayNode a;
    ASSERT_TRUE(a.init((base / "a").string()));

    account_base miner_acc;
    miner_acc.generate();

    // Mine a couple of clean blocks so we are past the genesis.
    for (int i = 0; i < 3; ++i) {
        const uint64_t h = a.core->get_current_blockchain_height();
        block empty;
        ASSERT_TRUE(construct_block_here(a, miner_acc, h, {}, empty));
        cryptonote::blobdata bb = cryptonote::block_to_blob(empty);
        block_verification_context bvc{};
        pool_supplement e{};
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            bb, &empty, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    // Build a block whose coinbase pays one atomic unit too much. The
    // modifier runs before the PoW nonce is solved, so the block hash
    // is still valid; only the sum check inside
    // validate_miner_transaction() should reject it.
    const uint64_t h = a.core->get_current_blockchain_height();
    block bad;
    ASSERT_TRUE(construct_block_here(
        a, miner_acc, h, {}, bad,
        [](block& b) {
            // First vout is the miner payout in the treasury-fork
            // layout used by construct_miner_tx().
            ASSERT_FALSE(b.miner_tx.vout.empty());
            b.miner_tx.vout[0].amount += 1;
        }));

    cryptonote::blobdata bb = cryptonote::block_to_blob(bad);
    block_verification_context bvc{};
    pool_supplement e{};
    // handle_single_incoming_block() returns true when the block was
    // processed, regardless of acceptance; the verdict is in bvc.
    (void)a.core->handle_single_incoming_block(bb, &bad, bvc, e, false);
    EXPECT_TRUE(bvc.m_verifivation_failed);
    EXPECT_FALSE(bvc.m_added_to_main_chain);

    boost::filesystem::remove_all(base);
}

// ---------------------------------------------------------------------
// Coinbase underpayment.
//
// A block whose coinbase pays less than the permitted subsidy must
// also be rejected, so that the recorded increase in supply always
// matches the actual coinbase outputs.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, CoinbaseUnderpaymentRejected)
{
    using namespace cryptonote;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_underpay_%%%%-%%%%");

    ReplayNode a;
    ASSERT_TRUE(a.init((base / "a").string()));

    account_base miner_acc;
    miner_acc.generate();

    for (int i = 0; i < 3; ++i) {
        const uint64_t h = a.core->get_current_blockchain_height();
        block empty;
        ASSERT_TRUE(construct_block_here(a, miner_acc, h, {}, empty));
        cryptonote::blobdata bb = cryptonote::block_to_blob(empty);
        block_verification_context bvc{};
        pool_supplement e{};
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            bb, &empty, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    const uint64_t h = a.core->get_current_blockchain_height();
    block bad;
    ASSERT_TRUE(construct_block_here(
        a, miner_acc, h, {}, bad,
        [](block& b) {
            ASSERT_FALSE(b.miner_tx.vout.empty());
            ASSERT_GE(b.miner_tx.vout[0].amount, 1u);
            b.miner_tx.vout[0].amount -= 1;
        }));

    cryptonote::blobdata bb = cryptonote::block_to_blob(bad);
    block_verification_context bvc{};
    pool_supplement e{};
    (void)a.core->handle_single_incoming_block(bb, &bad, bvc, e, false);
    EXPECT_TRUE(bvc.m_verifivation_failed);
    EXPECT_FALSE(bvc.m_added_to_main_chain);

    boost::filesystem::remove_all(base);
}

// ---------------------------------------------------------------------
// Legacy V1 vote rejection at mempool admission.
//
// Once DAO V2 is active (via the fixture's forced-active override), an
// input-based V1 vote carries no vote_v2 payload, is not reachable
// through any handler, and would be mined as a tally-inert transaction.
// The mempool must refuse it outright.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, LegacyV1VoteRejectedInMempoolWhenV2Active)
{
    using namespace cryptonote;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "v1reject"));

    // Build the legacy V1 shape: a single txin_vns_vote input, empty
    // vout, RCTTypeNull, no vote_v2 payload in extra.
    transaction v1_tx{};
    v1_tx.version     = 2;
    v1_tx.unlock_time = 0;
    {
        txin_vns_vote vin{};
        vin.amount = 1000000000000ULL;
        vin.key_offsets = {0, 0};
        std::memset(vin.k_image.data, 0xAA, sizeof(vin.k_image.data));
        vin.ring_sig.s.resize(2);
        v1_tx.vin.push_back(vin);
    }
    v1_tx.rct_signatures = rct::rctSig{};
    v1_tx.rct_signatures.type = rct::RCTTypeNull;

    const cryptonote::blobdata vb = tx_to_blob(v1_tx);
    tx_verification_context tvc{};
    EXPECT_FALSE(fx.node->core->handle_incoming_tx(
        vb, tvc, relay_method::local, false));
    EXPECT_TRUE(tvc.m_verifivation_failed);
    EXPECT_TRUE(tvc.m_invalid_input);

    std::vector<crypto::hash> pool_hashes;
    fx.node->core->get_pool_transaction_hashes(pool_hashes);
    const crypto::hash id = get_transaction_hash(v1_tx);
    EXPECT_EQ(std::find(pool_hashes.begin(), pool_hashes.end(), id),
              pool_hashes.end());
}

// ------------------------------------------------------------------
// B3c-3: full runner-driven reshare, end-to-end.
//
// Two live nodes A and B (positions 1 and 2 of a 3-party DKG committee
// with offline member C). A fourth node D joins the ready roster.
// Reshare of the proposal's key to the 4-member roster {A,B,C,D} runs
// through the runner via P2P. The resulting share set carries reshare
// evidence. A v6 certificate built by the producer path verifies.
// ------------------------------------------------------------------
TEST(DaoV2Replay, B3c3RunnerReshareEndToEnd)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_b3c3_%%%%-%%%%");

    ReplayNode a;
    ReplayNode b;
    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));

    auto& bc_a = a.core->get_blockchain_storage();
    auto& bc_b = b.core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();
    auto& db_b = bc_b.get_db();
    bc_a.set_dao_v2_active_for_test(true);
    bc_b.set_dao_v2_active_for_test(true);

    // 3-party committee, sorted.
    std::vector<crypto::public_key> committee;
    std::vector<crypto::secret_key> committee_sks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
        committee_sks.push_back(sk);
    }
    std::vector<size_t> ord = { 0, 1, 2 };
    std::sort(ord.begin(), ord.end(), [&](size_t x, size_t y) {
        return std::memcmp(committee[x].data, committee[y].data, 32) < 0;
    });
    {
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : ord) { p2.push_back(committee[i]); s2.push_back(committee_sks[i]); }
        committee = std::move(p2);
        committee_sks = std::move(s2);
    }
    a.core->set_node_key(committee_sks[0]);
    b.core->set_node_key(committee_sks[1]);
    crypto::public_key a_pub = committee[0];
    crypto::public_key b_pub = committee[1];

    crypto::public_key d_pub; crypto::secret_key d_sk;
    crypto::generate_keys(d_pub, d_sk);

    // Real DKG.
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));
    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config dcfg;
    dcfg.committee_size = 3;
    dcfg.threshold = dao_dkg_expected_threshold(3);
    dcfg.member_ids = committee;
    dcfg.k = 60; dcfg.target_N_bits = 128; dcfg.security_bits = 32;
    dcfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    dcfg.max_attempts = 1;
    dcfg.test_seed = 0x5645494C52544F33ULL;
    dcfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(dcfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);

    // Install per-proposal key.
    bc_a.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, dkg_out.local_secret_share);
    {
        const std::string dec(dkg_out.test_SK[1].begin(),
                              dkg_out.test_SK[1].end());
        BIGNUM* bn = nullptr;
        ASSERT_NE(BN_dec2bn(&bn, dec.c_str()), 0);
        const bool neg = BN_is_negative(bn) != 0;
        BIGNUM* abs_bn = BN_dup(bn);
        BN_set_negative(abs_bn, 0);
        const int nb = BN_num_bytes(abs_bn);
        std::vector<uint8_t> raw(1 + nb, 0);
        raw[0] = neg ? 1 : 0;
        BN_bn2bin(abs_bn, raw.data() + 1);
        BN_free(abs_bn);
        BN_free(bn);
        bc_b.install_dao_tally_key_for_proposal_for_test(
            dkg_out.record, raw);
    }

    // Ready roster: {A, B, C, D} at genesis.
    crypto::hash g_a = bc_a.get_block_id_by_height(0);
    crypto::hash g_b = bc_b.get_block_id_by_height(0);
    ASSERT_EQ(g_a, g_b);

    std::vector<crypto::public_key> roster = { a_pub, b_pub, committee[2], d_pub };
    std::sort(roster.begin(), roster.end(), [](const auto& x, const auto& y) {
        return std::memcmp(x.data, y.data, 32) < 0;
    });
    for (auto* db : { &db_a, &db_b }) {
        db_wtxn_guard g(db);
        for (const auto& pk : roster)
            db->add_dao_v2_node_ready(pk, 0, g_a);
    }

    // Proposal.
    const uint64_t vote_end = 3;
    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xC3, 32);
    for (auto* db : { &db_a, &db_b }) {
        proposal_record rec{};
        rec.proposal_id = prop_id;
        rec.submission_height = 0;
        rec.voting_end_height = vote_end;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(rec.tally_key_id.data, dkg_out.record.key_id.data(), 32);
        db_wtxn_guard g(db);
        db->add_proposal_record(prop_id, rec);
    }

    // Aggregate + supply snapshot.
    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));
    BIGNUM* Wb = BN_new(); BN_set_word(Wb, 100);
    BIGNUM* Sb = BN_new(); BN_set_word(Sb, 100);
    BIGNUM* Bb = BN_new(); BN_set_word(Bb, 50000);
    BIGNUM* r1 = BN_new(); BN_set_word(r1, 3);
    BIGNUM* r2 = BN_new(); BN_set_word(r2, 5);
    BIGNUM* r3 = BN_new(); BN_set_word(r3, 7);
    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(Wb, r1, E_W));
    ASSERT_TRUE(pk.encrypt(Sb, r2, E_S));
    ASSERT_TRUE(pk.encrypt(Bb, r3, E_B));
    for (auto* db : { &db_a, &db_b }) {
        dao_proposal_aggregate agg;
        agg.aggregate_E_W = E_W;
        agg.aggregate_E_S = E_S;
        agg.aggregate_E_B = E_B;
        agg.aggregate_C_W = rct::identity();
        agg.aggregate_C_S = rct::identity();
        agg.aggregate_C_B = rct::identity();
        db_wtxn_guard g(db);
        db->add_dao_proposal_aggregate(prop_id, agg);
        dao_supply_snapshot snap;
        snap.height = vote_end;
        snap.minted = dao_u128(100000);
        snap.circulating = dao_u128(50000);
        db->add_dao_supply_snapshot(snap);
    }

    // Mailbox.
    std::vector<std::pair<crypto::public_key, std::string>> mailbox;
    std::mutex mb_mu;
    bc_a.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(a_pub, s);
        return true;
    });
    bc_b.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(b_pub, s);
        return true;
    });
    bc_a.set_dao_v2_tally_broadcast([](const dao_v2_tally_share&) {});
    bc_b.set_dao_v2_tally_broadcast([](const dao_v2_tally_share&) {});

    // Trigger.
    bc_a.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    bc_b.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);

    // Deliver + commit.
    auto find_reshared = [](BlockchainDB& db,
                            const std::vector<uint8_t>& kid) -> uint64_t {
        uint64_t sid = 0;
        db.for_all_dao_share_sets(
            [&](uint64_t id, const dao_share_set_record& rec) -> bool {
                if (rec.key_id == kid && !rec.contributions.empty())
                    sid = id;
                return true;
            });
        return sid;
    };
    for (int round = 0; round < 20; ++round) {
        std::vector<std::pair<crypto::public_key, std::string>> batch;
        {
            std::lock_guard<std::mutex> lk(mb_mu);
            batch.swap(mailbox);
        }
        for (auto& [sender, payload] : batch) {
            if (std::memcmp(sender.data, a_pub.data, 32) == 0)
                bc_b.handle_dao_v2_dkg_msg(a_pub, payload);
            else
                bc_a.handle_dao_v2_dkg_msg(b_pub, payload);
        }
        {
            bc_a.maybe_commit_dao_v2_reshare();
        }
        {
            bc_b.maybe_commit_dao_v2_reshare();
        }
        if (find_reshared(db_a, dkg_out.record.key_id) != 0 &&
            find_reshared(db_b, dkg_out.record.key_id) != 0)
            break;
    }

    uint64_t new_sid_a = find_reshared(db_a, dkg_out.record.key_id);
    uint64_t new_sid_b = find_reshared(db_b, dkg_out.record.key_id);
    ASSERT_NE(new_sid_a, 0u) << "no reshared share set on node A";
    ASSERT_NE(new_sid_b, 0u) << "no reshared share set on node B";
    EXPECT_EQ(new_sid_a, new_sid_b);

    dao_share_set_record active_ss;
    ASSERT_TRUE(db_a.get_dao_share_set(new_sid_a, active_ss));
    EXPECT_EQ(active_ss.committee_members.size(), 4u);
    EXPECT_EQ(active_ss.VK_i.size(), 4u);
    EXPECT_GT(active_ss.contributions.size(), 0u);
    EXPECT_EQ(active_ss.contributor_indices.size(), active_ss.contributions.size());
    EXPECT_EQ(active_ss.contributor_vk.size(), active_ss.contributions.size());
    EXPECT_EQ(active_ss.threshold, dao_dkg_expected_threshold(4));
    EXPECT_EQ(active_ss.base_share_set_id,
              static_cast<uint64_t>(share_set_id_for_key_id(dkg_out.record.key_id)));

    // Producer.
    // Named locals: if TallyManager stores a reference and not a
    // copy, passing a temporary leaves it dangling. Binding to named
    // variables keeps the params alive for the full test scope.
    const governance_params params_a = governance_params::default_params();
    const governance_params params_b = governance_params::default_params();
    TallyManager tm_a(db_a, params_a);
    TallyManager tm_b(db_b, params_b);

    uint32_t a_pos = 0, b_pos = 0;
    for (size_t i = 0; i < active_ss.committee_members.size(); ++i) {
        crypto::public_key pk_i{};
        std::memcpy(pk_i.data, active_ss.committee_members[i].data(), 32);
        if (pk_i == a_pub) a_pos = static_cast<uint32_t>(i) + 1;
        if (pk_i == b_pub) b_pos = static_cast<uint32_t>(i) + 1;
    }
    ASSERT_NE(a_pos, 0u);
    ASSERT_NE(b_pos, 0u);

    dao_v2_tally_share share_a, share_b;
    ASSERT_TRUE(tm_a.produce_local_share(
        prop_id, dkg_out.record, a_pos, share_a, &active_ss));
    ASSERT_TRUE(tm_b.produce_local_share(
        prop_id, dkg_out.record, b_pos, share_b, &active_ss));

    std::map<crypto::public_key, dao_v2_tally_share> shares;
    shares[a_pub] = share_a;
    shares[b_pub] = share_b;

    transaction result_tx;
    ASSERT_TRUE(tm_a.build_tally_result_transaction(
        prop_id, shares, active_ss.threshold, result_tx));

    // Extract + verify cert.
    std::vector<tx_extra_field> xf;
    ASSERT_TRUE(parse_tx_extra(result_tx.extra, xf));
    dao_tally_certificate cert;
    bool found = false;
    for (const auto& f : xf) {
        if (f.type() != typeid(tx_extra_governance_payload)) continue;
        const auto& gpf = boost::get<tx_extra_governance_payload>(f);
        if (gpf.payload.type != governance_object::tally_result) continue;
        ASSERT_TRUE(cert.deserialize(gpf.payload.data));
        found = true;
        break;
    }
    ASSERT_TRUE(found);

    EXPECT_EQ(cert.per_event_share_set_id, new_sid_a);
    EXPECT_GT(cert.contributions.size(), 0u);
    EXPECT_EQ(cert.member_pubkeys.size(), 4u);
    EXPECT_EQ(cert.per_event_VK_i.size(), 4u);
    EXPECT_EQ(cert.threshold, dao_dkg_expected_threshold(4));

    dao_supply_snapshot snap;
    ASSERT_TRUE(db_a.get_dao_supply_snapshot(vote_end, snap));
    EXPECT_TRUE(dao_verify_tally_certificate(
        dkg_out.record, snap, 10, E_W, E_S, E_B, cert));

    // Tamper.
    {
        dao_tally_certificate bad = cert;
        ASSERT_FALSE(bad.contributions[0].empty());
        bad.contributions[0][bad.contributions[0].size() / 2] ^= 0xFF;
        EXPECT_FALSE(dao_verify_tally_certificate(
            dkg_out.record, snap, 10, E_W, E_S, E_B, bad));
    }
    {
        dao_tally_certificate bad = cert;
        ASSERT_FALSE(bad.W.partials.empty());
        ASSERT_FALSE(bad.W.partials[0].empty());
        bad.W.partials[0][bad.W.partials[0].size() / 2] ^= 0xFF;
        EXPECT_FALSE(dao_verify_tally_certificate(
            dkg_out.record, snap, 10, E_W, E_S, E_B, bad));
    }

    BN_free(Wb); BN_free(Sb); BN_free(Bb);
    BN_free(r1); BN_free(r2); BN_free(r3);
    boost::filesystem::remove_all(base);
}

// ------------------------------------------------------------------
// B3d: dropout replacement.
//
// Real 3-party DKG gives base committee {A,B,C} threshold 2.
// First reshare to a 4-node committee {A,B,C,D} (D joins ready pool).
// After commit, D "drops": ready pool keeps A,B,C but D goes silent.
// Advance past stall window. Second trigger must re-reshare to a
// 3-member committee {A,B,C} (survivors, D removed). All 3 nodes
// contribute, combine succeeds, new share set commits with evidence,
// certificate built against it verifies.
// ------------------------------------------------------------------
static void run_b3d_dropout_case(int target_slot)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;
    SCOPED_TRACE(::testing::Message() << "target_slot=" << target_slot);

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_b3d_%%%%-%%%%");

    ReplayNode a, b, c;
    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));
    ASSERT_TRUE(c.init((base / "c").string()));

    auto& bc_a = a.core->get_blockchain_storage();
    auto& bc_b = b.core->get_blockchain_storage();
    auto& bc_c = c.core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();
    auto& db_b = bc_b.get_db();
    auto& db_c = bc_c.get_db();
    bc_a.set_dao_v2_active_for_test(true);
    bc_b.set_dao_v2_active_for_test(true);
    bc_c.set_dao_v2_active_for_test(true);

    // 3-party base DKG committee.
    std::vector<crypto::public_key> committee;
    std::vector<crypto::secret_key> committee_sks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
        committee_sks.push_back(sk);
    }
    std::vector<size_t> ord = { 0, 1, 2 };
    std::sort(ord.begin(), ord.end(), [&](size_t x, size_t y) {
        return std::memcmp(committee[x].data, committee[y].data, 32) < 0;
    });
    {
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : ord) { p2.push_back(committee[i]); s2.push_back(committee_sks[i]); }
        committee = std::move(p2);
        committee_sks = std::move(s2);
    }
    crypto::public_key a_pub = committee[0];
    crypto::public_key b_pub = committee[1];
    crypto::public_key c_pub = committee[2];
    a.core->set_node_key(committee_sks[0]);
    b.core->set_node_key(committee_sks[1]);
    c.core->set_node_key(committee_sks[2]);

    // Force D's pubkey to sort into position `target_slot` among
    // {A,B,C,D}. A,B,C are already fixed and sorted. Retry until
    // D falls into the desired slot; expected attempts per slot is
    // small because the four possible sorted positions of a random
    // fourth key among three fixed keys are roughly equiprobable.
    crypto::public_key d_pub; crypto::secret_key d_sk;
    {
        int attempts = 0;
        for (;;) {
            crypto::generate_keys(d_pub, d_sk);
            std::vector<crypto::public_key> sorted = committee;
            sorted.push_back(d_pub);
            std::sort(sorted.begin(), sorted.end(),
                [](const auto& x, const auto& y) {
                    return std::memcmp(x.data, y.data, 32) < 0;
                });
            int slot = 0;
            for (size_t i = 0; i < sorted.size(); ++i) {
                if (std::memcmp(sorted[i].data, d_pub.data, 32) == 0) {
                    slot = static_cast<int>(i) + 1;
                    break;
                }
            }
            if (slot == target_slot) break;
            if (++attempts > 100000) {
                FAIL() << "could not force D into slot " << target_slot;
            }
        }
    }

    // Real DKG.
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));
    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config dcfg;
    dcfg.committee_size = 3;
    dcfg.threshold = dao_dkg_expected_threshold(3);
    dcfg.member_ids = committee;
    dcfg.k = 60; dcfg.target_N_bits = 128; dcfg.security_bits = 32;
    dcfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    dcfg.max_attempts = 1;
    dcfg.test_seed = 0x5645494C52544F33ULL;
    dcfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(dcfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_EQ(dkg_out.test_SK.size(), 3u);

    auto decode_sk = [](const std::vector<uint8_t>& dec) {
        std::string s(dec.begin(), dec.end());
        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, s.c_str()) == 0) return std::vector<uint8_t>{};
        bool neg = BN_is_negative(bn) != 0;
        BIGNUM* abs_bn = BN_dup(bn); BN_set_negative(abs_bn, 0);
        int nb = BN_num_bytes(abs_bn);
        std::vector<uint8_t> raw(1 + nb, 0);
        raw[0] = neg ? 1 : 0;
        BN_bn2bin(abs_bn, raw.data() + 1);
        BN_free(abs_bn); BN_free(bn);
        return raw;
    };

    bc_a.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, dkg_out.local_secret_share);
    bc_b.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_sk(dkg_out.test_SK[1]));
    bc_c.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_sk(dkg_out.test_SK[2]));

    // Mine to height 5 first (so first reshare commit lands at 5).
    account_base miner; miner.generate();
    while (bc_a.get_current_blockchain_height() < 5) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc_a.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc_a](const block& bb, uint64_t hh,
                           const crypto::hash* s, unsigned int mn,
                           crypto::hash& o) -> bool {
            return get_block_longhash(&bc_a, bb, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata blob = block_to_blob(tmpl);
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
        ASSERT_TRUE(b.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
        ASSERT_TRUE(c.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    crypto::hash g_hash = bc_a.get_block_id_by_height(0);
    const uint64_t vote_end = 3;

    // Ready at vote_end=3: A, B, C, D.
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        for (const auto& pk : { a_pub, b_pub, c_pub, d_pub })
            db->add_dao_v2_node_ready(pk, 0, g_hash);
    }

    // Proposal + aggregate + supply.
    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xD3, 32);
    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));
    BIGNUM* Wb = BN_new(); BN_set_word(Wb, 1000);
    BIGNUM* Sb = BN_new(); BN_set_word(Sb, 1000);
    BIGNUM* Bb = BN_new(); BN_set_word(Bb, 50000);
    BIGNUM* r1 = BN_new(); BN_set_word(r1, 3);
    BIGNUM* r2 = BN_new(); BN_set_word(r2, 5);
    BIGNUM* r3 = BN_new(); BN_set_word(r3, 7);
    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(Wb, r1, E_W));
    ASSERT_TRUE(pk.encrypt(Sb, r2, E_S));
    ASSERT_TRUE(pk.encrypt(Bb, r3, E_B));
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        proposal_record rec{};
        rec.proposal_id = prop_id;
        rec.submission_height = 0;
        rec.voting_end_height = vote_end;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(rec.tally_key_id.data, dkg_out.record.key_id.data(), 32);
        db->add_proposal_record(prop_id, rec);
        dao_proposal_aggregate agg;
        agg.aggregate_E_W = E_W;
        agg.aggregate_E_S = E_S;
        agg.aggregate_E_B = E_B;
        agg.aggregate_C_W = rct::identity();
        agg.aggregate_C_S = rct::identity();
        agg.aggregate_C_B = rct::identity();
        db->add_dao_proposal_aggregate(prop_id, agg);
        dao_supply_snapshot snap;
        snap.height = vote_end;
        snap.minted = dao_u128(100000);
        snap.circulating = dao_u128(50000);
        db->add_dao_supply_snapshot(snap);
    }

    // Mailbox.
    std::vector<std::pair<crypto::public_key, std::string>> mailbox;
    std::mutex mb_mu;
    bc_a.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(a_pub, s);
        return true;
    });
    bc_b.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(b_pub, s);
        return true;
    });
    bc_c.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(c_pub, s);
        return true;
    });
    for (auto* bc : { &bc_a, &bc_b, &bc_c })
        bc->set_dao_v2_tally_broadcast([](const dao_v2_tally_share&) {});

    auto find_latest = [](BlockchainDB& db,
                          const std::vector<uint8_t>& kid) -> uint64_t {
        uint64_t sid = 0;
        db.for_all_dao_share_sets(
            [&](uint64_t id, const dao_share_set_record& r) -> bool {
                if (r.key_id == kid && !r.contributions.empty() && id > sid)
                    sid = id;
                return true;
            });
        return sid;
    };

    auto drive = [&](int max_rounds) {
        for (int r = 0; r < max_rounds; ++r) {
            std::vector<std::pair<crypto::public_key, std::string>> batch;
            {
                std::lock_guard<std::mutex> lk(mb_mu);
                batch.swap(mailbox);
            }
            for (auto& [sender, payload] : batch) {
                if (sender != a_pub) bc_a.handle_dao_v2_dkg_msg(sender, payload);
                if (sender != b_pub) bc_b.handle_dao_v2_dkg_msg(sender, payload);
                if (sender != c_pub) bc_c.handle_dao_v2_dkg_msg(sender, payload);
            }
            bc_a.maybe_commit_dao_v2_reshare();
            bc_b.maybe_commit_dao_v2_reshare();
            bc_c.maybe_commit_dao_v2_reshare();
        }
    };

    // -------- First reshare (base -> {A,B,C,D}) --------
    bc_a.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    bc_b.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    bc_c.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    drive(15);

    uint64_t sid1 = find_latest(db_a, dkg_out.record.key_id);
    ASSERT_NE(sid1, 0u) << "first reshare did not commit";
    {
        dao_share_set_record ss;
        ASSERT_TRUE(db_a.get_dao_share_set(sid1, ss));
        EXPECT_EQ(ss.committee_members.size(), 4u);
        EXPECT_EQ(ss.threshold, dao_dkg_expected_threshold(4));
    }

    // -------- Advance past stall window --------
    while (bc_a.get_current_blockchain_height() < 20) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc_a.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc_a](const block& bb, uint64_t hh,
                           const crypto::hash* s, unsigned int mn,
                           crypto::hash& o) -> bool {
            return get_block_longhash(&bc_a, bb, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata blob = block_to_blob(tmpl);
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(b.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(c.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
    }

    // Refresh ready for A, B, C at current height; D drops.
    crypto::hash tip_hash = bc_a.get_block_id_by_height(
        bc_a.get_current_blockchain_height() - 1);
    const uint64_t now_h = bc_a.get_current_blockchain_height() - 1;
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        for (const auto& pk : { a_pub, b_pub, c_pub })
            db->add_dao_v2_node_ready(pk, now_h, tip_hash);
        // D's height-0 ready entry auto-expires via TTL (k_ready_ttl_now).
    }

    // -------- Re-reshare (survivors, D dropped) --------
    bc_a.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    bc_b.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    bc_c.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);

    // Negative test: forged reshare messages must not increase the
    // contribution count on node A. The runner is fresh; only the
    // local contribution (if any) is present. Any accepted deal
    // would be visible as a count bump. Both forged messages are
    // delivered before drive() so no legitimate peer deal has
    // been processed yet.
    {
        const size_t pre_forged =
            bc_a.get_dao_v2_reshare_contribution_count_for_test();

        // Forged 1: invalid sender index (0).
        {
            dao_reshare_msg bogus;
            bogus.old_share_set_id = sid1;
            bogus.new_share_set_id = sid1 + 1;
            bogus.sender_index = 0;
            bogus.type = 0;
            bogus.public_blob.assign(16, 0xAB);
            std::vector<uint8_t> raw;
            ASSERT_TRUE(bogus.serialize(raw));
            dkg_msg env;
            env.hdr.type = dkg_msg_type::share_set_deal;
            env.bytes_a.assign(raw.begin(), raw.end());
            std::vector<uint8_t> wire;
            ASSERT_TRUE(env.serialize(wire));
            std::string payload(wire.begin(), wire.end());
            bc_a.handle_dao_v2_dkg_msg(a_pub, payload);
        }

        // Forged 2: non-selected sender. D's original slot in
        // the first-reshape committee is not in the second-reshape
        // fixed interpolation subset S, so the receiver must
        // reject the message.
        {
            dao_share_set_record ss1_check;
            ASSERT_TRUE(db_a.get_dao_share_set(sid1, ss1_check));
            uint32_t d_slot = 0;
            for (size_t i = 0; i < ss1_check.committee_members.size(); ++i) {
                crypto::public_key pk_i{};
                std::memcpy(pk_i.data, ss1_check.committee_members[i].data(), 32);
                if (std::memcmp(pk_i.data, d_pub.data, 32) == 0) {
                    d_slot = static_cast<uint32_t>(i) + 1;
                    break;
                }
            }
            ASSERT_NE(d_slot, 0u);
            dao_reshare_msg bogus;
            bogus.old_share_set_id = sid1;
            bogus.new_share_set_id = sid1 + 1;
            bogus.sender_index = d_slot;
            bogus.type = 0;
            bogus.public_blob.assign(16, 0xCD);
            std::vector<uint8_t> raw;
            ASSERT_TRUE(bogus.serialize(raw));
            dkg_msg env;
            env.hdr.type = dkg_msg_type::share_set_deal;
            env.bytes_a.assign(raw.begin(), raw.end());
            std::vector<uint8_t> wire;
            ASSERT_TRUE(env.serialize(wire));
            std::string payload(wire.begin(), wire.end());
            bc_a.handle_dao_v2_dkg_msg(d_pub, payload);
        }

        const size_t post_forged =
            bc_a.get_dao_v2_reshare_contribution_count_for_test();
        EXPECT_EQ(pre_forged, post_forged)
            << "forged reshare message was accepted; sender "
               "validation in dao_reshare_runner::on_message is not "
               "enforcing the contributor_indices allowlist";
    }

    drive(15);

    uint64_t sid2 = find_latest(db_a, dkg_out.record.key_id);
    ASSERT_NE(sid2, 0u) << "re-reshare did not commit";
    EXPECT_NE(sid2, sid1);

    dao_share_set_record ss2;
    ASSERT_TRUE(db_a.get_dao_share_set(sid2, ss2));
    EXPECT_EQ(ss2.committee_members.size(), 3u);
    EXPECT_EQ(ss2.threshold, dao_dkg_expected_threshold(3));
    EXPECT_FALSE(ss2.contributions.empty());
    EXPECT_EQ(ss2.contributor_indices.size(), ss2.contributions.size());

    // Every node in the new committee must have persisted its own
    // local share under the new share-set id. This is the assertion
    // the previous version of this test did not make; its absence
    // is why the recipient-only bug went undetected even on
    // passing runs.
    {
        struct Triple {
            BlockchainDB*      db;
            crypto::public_key pk;
            const char*        name;
        };
        Triple triples[] = {
            { &db_a, a_pub, "A" },
            { &db_b, b_pub, "B" },
            { &db_c, c_pub, "C" },
        };
        for (auto& t : triples) {
            uint32_t pos = 0;
            for (size_t i = 0; i < ss2.committee_members.size(); ++i) {
                crypto::public_key pk_i{};
                std::memcpy(pk_i.data, ss2.committee_members[i].data(), 32);
                if (std::memcmp(pk_i.data, t.pk.data, 32) == 0) {
                    pos = static_cast<uint32_t>(i) + 1;
                    break;
                }
            }
            ASSERT_NE(pos, 0u) << t.name
                << " is not in the new committee";
            std::vector<uint8_t> packed;
            ASSERT_TRUE(t.db->get_dao_local_share(
                static_cast<uint32_t>(sid2), pos, packed))
                << "node " << t.name << " missing local share at sid2="
                << sid2 << " pos=" << pos;
            ASSERT_FALSE(packed.empty())
                << "node " << t.name << " has empty packed share at sid2="
                << sid2;
        }
    }

    BN_free(Wb); BN_free(Sb); BN_free(Bb);
    BN_free(r1); BN_free(r2); BN_free(r3);
    boost::filesystem::remove_all(base);
}

// Four iterations, one per possible sorted position of D in the
// post-first-reshape committee. Each iteration runs in isolation.
TEST(DaoV2Replay, B3dDropoutReplacement)
{
    for (int target_slot = 1; target_slot <= 4; ++target_slot)
        run_b3d_dropout_case(target_slot);
}

// ------------------------------------------------------------------
// Focused regression for the reshape-chain witness bound.
//
// Proves that dao_reshare_link_prove and dao_reshare_link_verify handle
// a 9000-bit witness -- the size produced by a first reshape. The
// previous SCALAR_BYTES = 1041 (= 8328 bits) rejected it and the
// previous randomizer draw (8196+128) did not statistically mask it.
// ------------------------------------------------------------------
TEST(DaoV2Replay, LinkProofHandlesResharedWitness)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_linkproof_%%%%-%%%%");

    ReplayNode a;
    ASSERT_TRUE(a.init((base / "a").string()));
    auto& bc_a = a.core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();

    // Real DKG for one small committee so we have a canonical N and V.
    std::vector<crypto::public_key> committee;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
    }
    std::sort(committee.begin(), committee.end(),
              [](const auto& x, const auto& y) {
                return std::memcmp(x.data, y.data, 32) < 0;
              });

    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold = dao_dkg_expected_threshold(3);
    cfg.member_ids = committee;
    cfg.k = 60; cfg.target_N_bits = 128; cfg.security_bits = 32;
    cfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts = 1;
    cfg.test_seed = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;

    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(cfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));

    // Synthetic witness at the size the reshape chain produces.
    BIGNUM* s_witness = BN_new();
    ASSERT_TRUE(BN_rand(s_witness, 9000, BN_RAND_TOP_ONE,
                        BN_RAND_BOTTOM_ANY));
    const int witness_bits = BN_num_bits(s_witness);
    ASSERT_GT(witness_bits, 8328) << "precondition: witness exceeds old bound";

    // Compute the matching VK_i = V^(Delta * s) mod N^2 and
    // C_i0 = V^s mod N^2 (mu_i = 1 for this test).
    BN_CTX* g_ctx = BN_CTX_new();
    ASSERT_NE(g_ctx, nullptr);
    BIGNUM* N = BN_bin2bn(dkg_out.record.N.data(),
                          static_cast<int>(dkg_out.record.N.size()), nullptr);
    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, g_ctx);
    BIGNUM* V = BN_bin2bn(dkg_out.record.V.data(),
                          static_cast<int>(dkg_out.record.V.size()), nullptr);
    BIGNUM* Delta = BN_new();
    BN_dec2bn(&Delta, "20922789888000");
    BIGNUM* exp0 = BN_new();
    BN_mul(exp0, Delta, s_witness, g_ctx);
    BIGNUM* VKi = BN_new();
    BN_mod_exp(VKi, V, exp0, N2, g_ctx);
    BIGNUM* C0 = BN_new();
    BN_mod_exp(C0, V, s_witness, N2, g_ctx);

    std::vector<uint8_t> VKi_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> C0_bytes(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(VKi, VKi_bytes.data(), PAILLIER_CT_BYTES);
    BN_bn2binpad(C0, C0_bytes.data(), PAILLIER_CT_BYTES);

    dao_reshare_link_context ctx;
    ctx.genesis_block_hash = db_a.get_block_hash_from_height(0);
    ctx.stable_key_record_hash.assign(32, 0);
    ctx.share_set_id = 1;
    ctx.contributor_pubkey.assign(32, 0);
    std::memcpy(ctx.contributor_pubkey.data(), committee[0].data, 32);
    ctx.original_index = 1;
    ctx.contributor_subset = {1, 2};
    ctx.N = dkg_out.record.N;
    ctx.V = dkg_out.record.V;
    ctx.VK_i = VKi_bytes;
    ctx.C_i0 = C0_bytes;
    std::vector<uint8_t> Delta_bytes(32, 0);
    BN_bn2binpad(Delta, Delta_bytes.data(), 32);
    ctx.Delta = Delta_bytes;
    // mu_i = 1, signed encoding: 1 sign byte + 512 magnitude
    std::vector<uint8_t> mu_bytes(1 + 512, 0);
    mu_bytes[1 + 511] = 1;
    ctx.mu_i = mu_bytes;

    dao_reshare_link_proof proof;
    ASSERT_TRUE(dao_reshare_link_prove(ctx, s_witness, proof))
        << "link_prove failed on " << witness_bits << "-bit witness";

    std::vector<uint8_t> proof_bytes;
    ASSERT_TRUE(proof.serialize(proof_bytes));

    dao_reshare_link_proof proof2;
    ASSERT_TRUE(proof2.deserialize(proof_bytes));

    ASSERT_TRUE(dao_reshare_link_verify(ctx, proof2))
        << "link_verify failed on round-tripped proof";

    BN_free(s_witness);
    BN_free(N); BN_free(N2); BN_free(V); BN_free(Delta); BN_free(exp0);
    BN_free(VKi); BN_free(C0);
    BN_CTX_free(g_ctx);

    boost::filesystem::remove_all(base);
}



// ------------------------------------------------------------------
// Repeated reshares through 3 -> 4 -> 6 -> 16 members with threshold
// increases at each stage (2 -> 2 -> 3 -> 8). Exercises the crypto
// layer directly, no Blockchain instances (expert Option B). The B3d
// replay test covers the blockchain integration; this test covers the
// mathematical property that repeated reshaping does not cause
// unbounded share growth and that the original secret is preserved
// across all three operations.
//
// Bound units: DAO_RESHARE_SIGNED_BYTES = 2321 total bytes =
//   1 sign byte + 2320 magnitude bytes = 18560 magnitude bits.
// The proof-level WITNESS_BITS = 10000 also bounds the acceptable
// share magnitude (a link proof over a share larger than
// WITNESS_BITS cannot be generated within SCALAR_BYTES).
//
// Assertions:
//   - all three stages succeed
//   - every stage share magnitude < WITNESS_BITS
//   - every stage share magnitude < (DAO_RESHARE_SIGNED_BYTES - 1) * 8
//   - stage-3 magnitude is not materially larger than stage-1
//   - f(0) is preserved across all stages (secret unchanged)
// ------------------------------------------------------------------
namespace {

using namespace cryptonote::dao;

// Decode a share blob. Both DKG output (local_secret_share, documented
// as signed-encoded in dao_dkg.h) and reshare output
// (dao_reshare_serialize_signed, [sign, magnitude] of
// DAO_RESHARE_SIGNED_BYTES) carry a leading sign byte of 0 or 1.
// Fall through to plain magnitude if the first byte is neither.
BIGNUM* decode_share_signed_or_magnitude(const std::vector<uint8_t>& in)
{
    if (in.empty()) return nullptr;
    if (in[0] == 0 || in[0] == 1) {
        const bool neg = (in[0] == 1);
        BIGNUM* b = BN_bin2bn(in.data() + 1,
                               static_cast<int>(in.size() - 1), nullptr);
        if (!b) return nullptr;
        if (neg && !BN_is_zero(b)) BN_set_negative(b, 1);
        return b;
    }
    return BN_bin2bn(in.data(), static_cast<int>(in.size()), nullptr);
}

// f(0) = (sum_{i in S} mu_i * s_i) / delta, where mu_i = delta *
// lambda_i(0). S is 1-indexed against shares.
BIGNUM* compute_reconstructed_secret(const std::vector<BIGNUM*>& shares,
                                      const std::vector<uint32_t>& S,
                                      const BIGNUM* delta,
                                      BN_CTX* ctx)
{
    if (!delta || S.empty()) return nullptr;
    BIGNUM* sum = BN_new();
    if (!sum) return nullptr;
    BN_zero(sum);
    for (uint32_t i : S) {
        if (i == 0 || i > shares.size()) { BN_free(sum); return nullptr; }
        BIGNUM* mu = BN_new();
        if (!mu || !dao_dkg_lagrange_mu(S, i, mu)) {
            BN_free(mu); BN_free(sum); return nullptr;
        }
        BIGNUM* term = BN_new();
        if (!term || !BN_mul(term, mu, shares[i - 1], ctx)) {
            BN_free(term); BN_free(mu); BN_free(sum); return nullptr;
        }
        BN_add(sum, sum, term);
        BN_free(term); BN_free(mu);
    }
    BIGNUM* f0 = BN_new();
    BIGNUM* rem = BN_new();
    if (!f0 || !rem ||
        !BN_div(f0, rem, sum, delta, ctx) ||
        !BN_is_zero(rem)) {
        BN_free(f0); BN_free(rem); BN_free(sum); return nullptr;
    }
    BN_free(rem); BN_free(sum);
    return f0;
}

} // namespace

TEST(DaoV2Replay, RepeatedReshareMaxCommittee)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_represhape_%%%%-%%%%");

    // -------- Stage 0: 3-party DKG, threshold 2 --------
    std::vector<crypto::public_key> c0_pks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        c0_pks.push_back(pk);
    }
    std::sort(c0_pks.begin(), c0_pks.end(),
        [](const auto& x, const auto& y) {
            return std::memcmp(x.data, y.data, 32) < 0;
        });

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config dcfg;
    dcfg.committee_size = 3;
    dcfg.threshold = dao_dkg_expected_threshold(3);
    dcfg.member_ids = c0_pks;
    dcfg.k = 60; dcfg.target_N_bits = 128; dcfg.security_bits = 32;
    dcfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    dcfg.max_attempts = 1;
    dcfg.test_seed = 0x5645494C52544F33ULL;
    dcfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(dcfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_EQ(dkg_out.test_SK.size(), 3u);

    auto decode_decimal_sk = [](const std::vector<uint8_t>& dec)
        -> std::vector<uint8_t> {
        std::string s(dec.begin(), dec.end());
        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, s.c_str()) == 0) return {};
        bool neg = BN_is_negative(bn) != 0;
        BIGNUM* abs_bn = BN_dup(bn); BN_set_negative(abs_bn, 0);
        int nb = BN_num_bytes(abs_bn);
        std::vector<uint8_t> raw(1 + nb, 0);
        raw[0] = neg ? 1 : 0;
        BN_bn2bin(abs_bn, raw.data() + 1);
        BN_free(abs_bn); BN_free(bn);
        return raw;
    };

    std::vector<std::vector<uint8_t>> c0_share_bytes;
    c0_share_bytes.push_back(dkg_out.local_secret_share);
    c0_share_bytes.push_back(decode_decimal_sk(dkg_out.test_SK[1]));
    c0_share_bytes.push_back(decode_decimal_sk(dkg_out.test_SK[2]));

    std::vector<BIGNUM*> c0_shares;
    for (auto& b : c0_share_bytes) {
        BIGNUM* s = decode_share_signed_or_magnitude(b);
        ASSERT_NE(s, nullptr) << "could not decode DKG share";
        c0_shares.push_back(s);
    }

    // Common crypto objects.
    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));
    BIGNUM* delta = BN_dup(dao_dkg_delta());
    ASSERT_NE(delta, nullptr);
    std::vector<uint8_t> Delta_bytes(32, 0);
    BN_bn2binpad(delta, Delta_bytes.data(), 32);

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    // Stage 0 f(0): S_0 = {1, 2} (threshold 2).
    BIGNUM* f0_stage0 = compute_reconstructed_secret(
        c0_shares, {1, 2}, delta, ctx);
    ASSERT_NE(f0_stage0, nullptr)
        << "could not reconstruct f(0) from stage 0";

    // One full reshare stage.
    auto do_stage =
        [&](std::vector<crypto::public_key>& old_pks,
            std::vector<BIGNUM*>& old_shares,
            const std::vector<std::vector<uint8_t>>& old_vks_in,
            uint32_t old_threshold,
            std::vector<crypto::public_key>& new_pks,
            uint32_t new_threshold,
            uint64_t old_set_id,
            uint64_t new_set_id,
            std::vector<BIGNUM*>& new_shares_out,
            std::vector<std::vector<uint8_t>>& new_vks_out,
            int& max_bits_out) -> bool
    {
        const uint32_t t_new = new_threshold - 1;
        std::vector<uint32_t> new_indices;
        for (size_t i = 0; i < new_pks.size(); ++i)
            new_indices.push_back(static_cast<uint32_t>(i) + 1);

        // Fixed Lagrange subset: first old_threshold old positions.
        std::vector<uint32_t> S;
        for (uint32_t k = 0; k < old_threshold; ++k)
            S.push_back(static_cast<uint32_t>(k) + 1);

        std::vector<dao_reshare_contribution> contribs;
        for (uint32_t i : S) {
            dao_reshare_link_context ctx_i;
            ctx_i.genesis_block_hash = crypto::null_hash;
            ctx_i.stable_key_record_hash.assign(32, 0);
            ctx_i.share_set_id = old_set_id;
            ctx_i.contributor_pubkey.assign(32, 0);
            std::memcpy(ctx_i.contributor_pubkey.data(),
                        old_pks[i - 1].data, 32);
            ctx_i.original_index = i;
            ctx_i.contributor_subset = S;
            ctx_i.N = dkg_out.record.N;
            ctx_i.V = dkg_out.record.V;
            ctx_i.VK_i = old_vks_in[i - 1];
            ctx_i.C_i0.assign(PAILLIER_CT_BYTES, 0);
            ctx_i.Delta = Delta_bytes;

            BIGNUM* mu = BN_new();
            if (!mu || !dao_dkg_lagrange_mu(S, i, mu)) {
                BN_free(mu); return false;
            }
            dao_reshare_contribution c;
            bool ok = dao_reshare_make_contribution(
                pk, vss, dkg_out.record.V,
                old_shares[i - 1], mu, delta,
                t_new, new_indices, ctx_i, c);
            BN_free(mu);
            if (!ok) return false;
            contribs.push_back(std::move(c));
        }

        std::vector<dao_reshare_new_share> new_shares;
        for (uint32_t j = 1; j <= new_pks.size(); ++j) {
            dao_reshare_new_share ns;
            if (!dao_reshare_combine_one(
                    pk, vss, dkg_out.record.V, contribs, new_indices,
                    j - 1, /* old threshold for combine */ old_threshold,
                    delta, ns))
                return false;
            new_shares.push_back(std::move(ns));
        }

        dao_share_set_record ss;
        if (!dao_reshare_build_share_set(
                new_set_id, /* height */ 0, dkg_out.record.key_id,
                new_pks, new_shares, new_threshold, ss))
            return false;

        int mb = 0;
        for (auto& ns : new_shares) {
            if (ns.share_signed.size() != DAO_RESHARE_SIGNED_BYTES)
                return false;
            BIGNUM* b = decode_share_signed_or_magnitude(ns.share_signed);
            if (!b) return false;
            int bits = BN_num_bits(b);
            if (bits > mb) mb = bits;
            new_shares_out.push_back(b);
            new_vks_out.push_back(ns.VK_j);
        }
        max_bits_out = mb;
        return true;
    };

    // -------- Stage 1: 3 -> 4, threshold 2 -> 2 --------
    std::vector<crypto::public_key> c1_pks;
    for (int i = 0; i < 4; ++i) {
        crypto::public_key pk2; crypto::secret_key sk2;
        crypto::generate_keys(pk2, sk2);
        c1_pks.push_back(pk2);
    }
    std::sort(c1_pks.begin(), c1_pks.end(),
        [](const auto& x, const auto& y) {
            return std::memcmp(x.data, y.data, 32) < 0;
        });
    std::vector<BIGNUM*> c1_shares;
    std::vector<std::vector<uint8_t>> c1_vks;
    int c1_bits = 0;
    const std::vector<std::vector<uint8_t>> c0_vks = dkg_out.record.V_K_i;
    ASSERT_TRUE(do_stage(c0_pks, c0_shares, c0_vks, 2, c1_pks,
                         dao_dkg_expected_threshold(4),
                         100, 101, c1_shares, c1_vks, c1_bits))
        << "stage 1 (3->4) failed";
    ASSERT_EQ(c1_vks.size(), c1_pks.size());
    {
        BIGNUM* f = compute_reconstructed_secret(c1_shares, {1, 2}, delta, ctx);
        ASSERT_NE(f, nullptr) << "stage 1 f(0) unreconstructable";
        EXPECT_EQ(BN_cmp(f, f0_stage0), 0)
            << "secret changed after 3->4 reshape";
        BN_free(f);
    }

    // -------- Stage 2: 4 -> 6, threshold 2 -> 3 --------
    std::vector<crypto::public_key> c2_pks;
    for (int i = 0; i < 6; ++i) {
        crypto::public_key pk2; crypto::secret_key sk2;
        crypto::generate_keys(pk2, sk2);
        c2_pks.push_back(pk2);
    }
    std::sort(c2_pks.begin(), c2_pks.end(),
        [](const auto& x, const auto& y) {
            return std::memcmp(x.data, y.data, 32) < 0;
        });
    std::vector<BIGNUM*> c2_shares;
    std::vector<std::vector<uint8_t>> c2_vks;
    int c2_bits = 0;
    ASSERT_TRUE(do_stage(c1_pks, c1_shares, c1_vks, 2, c2_pks,
                         dao_dkg_expected_threshold(6),
                         101, 102, c2_shares, c2_vks, c2_bits))
        << "stage 2 (4->6) failed";
    ASSERT_EQ(c2_vks.size(), c2_pks.size());
    {
        BIGNUM* f = compute_reconstructed_secret(c2_shares, {1, 2, 3}, delta, ctx);
        ASSERT_NE(f, nullptr) << "stage 2 f(0) unreconstructable";
        EXPECT_EQ(BN_cmp(f, f0_stage0), 0)
            << "secret changed after 4->6 reshape";
        BN_free(f);
    }

    // -------- Stage 3: 6 -> 16, threshold 3 -> 8 --------
    std::vector<crypto::public_key> c3_pks;
    for (int i = 0; i < 16; ++i) {
        crypto::public_key pk2; crypto::secret_key sk2;
        crypto::generate_keys(pk2, sk2);
        c3_pks.push_back(pk2);
    }
    std::sort(c3_pks.begin(), c3_pks.end(),
        [](const auto& x, const auto& y) {
            return std::memcmp(x.data, y.data, 32) < 0;
        });
    std::vector<BIGNUM*> c3_shares;
    std::vector<std::vector<uint8_t>> c3_vks;
    int c3_bits = 0;
    ASSERT_TRUE(do_stage(c2_pks, c2_shares, c2_vks, 3, c3_pks,
                         dao_dkg_expected_threshold(16),
                         102, 103, c3_shares, c3_vks, c3_bits))
        << "stage 3 (6->16) failed";
    ASSERT_EQ(c3_vks.size(), c3_pks.size());
    {
        std::vector<uint32_t> S = {1, 2, 3, 4, 5, 6, 7, 8};
        BIGNUM* f = compute_reconstructed_secret(c3_shares, S, delta, ctx);
        ASSERT_NE(f, nullptr) << "stage 3 f(0) unreconstructable";
        EXPECT_EQ(BN_cmp(f, f0_stage0), 0)
            << "secret changed after all three reshares";
        BN_free(f);
    }

    // Magnitude bound assertions.
    const int kMagnitude_bits_bound =
        static_cast<int>((DAO_RESHARE_SIGNED_BYTES - 1) * 8);  // 18560
    EXPECT_LT(c1_bits, static_cast<int>(dao_reshare_link_proof::WITNESS_BITS))
        << "stage-1 magnitude (" << c1_bits << " bits) exceeds WITNESS_BITS";
    EXPECT_LT(c2_bits, static_cast<int>(dao_reshare_link_proof::WITNESS_BITS))
        << "stage-2 magnitude (" << c2_bits << " bits) exceeds WITNESS_BITS";
    EXPECT_LT(c3_bits, static_cast<int>(dao_reshare_link_proof::WITNESS_BITS))
        << "stage-3 magnitude (" << c3_bits << " bits) exceeds WITNESS_BITS";
    EXPECT_LT(c1_bits, kMagnitude_bits_bound);
    EXPECT_LT(c2_bits, kMagnitude_bits_bound);
    EXPECT_LT(c3_bits, kMagnitude_bits_bound);

    // Bounded growth: stage 3 must not be materially larger than stage 1.
    // Resharing divides out the accumulated coefficient noise at each
    // step, so magnitudes stay in the same ballpark across stages.
    EXPECT_LE(c3_bits, c1_bits + 500)
        << "share magnitudes grew across repeated reshares; "
           "s1=" << c1_bits << " s3=" << c3_bits;

    // Cleanup.
    BN_free(f0_stage0);
    for (auto* s : c0_shares) BN_free(s);
    for (auto* s : c1_shares) BN_free(s);
    for (auto* s : c2_shares) BN_free(s);
    for (auto* s : c3_shares) BN_free(s);
    BN_free(delta);
    BN_CTX_free(ctx);
    boost::filesystem::remove_all(base);
}


// ------------------------------------------------------------------
// §9 item 5: dao_reshare_combine_one must reject contributions built
// over different Lagrange interpolation subsets. Each contribution
// is individually valid; combining mismatched subsets silently
// produces an s_j that passes the internal V^{s_j*delta}==VK_j check
// but does not represent a share of the correct secret.
// ------------------------------------------------------------------
TEST(DaoV2Replay, CombineRejectsMismatchedSubsets)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_combine_mismatch_%%%%-%%%%");

    std::vector<crypto::public_key> c0_pks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk2; crypto::secret_key sk2;
        crypto::generate_keys(pk2, sk2);
        c0_pks.push_back(pk2);
    }
    std::sort(c0_pks.begin(), c0_pks.end(),
        [](const auto& x, const auto& y) {
            return std::memcmp(x.data, y.data, 32) < 0;
        });

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config dcfg;
    dcfg.committee_size = 3;
    dcfg.threshold = dao_dkg_expected_threshold(3);
    dcfg.member_ids = c0_pks;
    dcfg.k = 60; dcfg.target_N_bits = 128; dcfg.security_bits = 32;
    dcfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    dcfg.max_attempts = 1;
    dcfg.test_seed = 0x5645494C52544F33ULL;
    dcfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(dcfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_EQ(dkg_out.test_SK.size(), 3u);

    auto decode_decimal_sk = [](const std::vector<uint8_t>& dec)
        -> std::vector<uint8_t> {
        std::string s(dec.begin(), dec.end());
        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, s.c_str()) == 0) return {};
        bool neg = BN_is_negative(bn) != 0;
        BIGNUM* abs_bn = BN_dup(bn); BN_set_negative(abs_bn, 0);
        int nb = BN_num_bytes(abs_bn);
        std::vector<uint8_t> raw(1 + nb, 0);
        raw[0] = neg ? 1 : 0;
        BN_bn2bin(abs_bn, raw.data() + 1);
        BN_free(abs_bn); BN_free(bn);
        return raw;
    };

    std::vector<BIGNUM*> c0_shares;
    for (auto& b : { dkg_out.local_secret_share,
                     decode_decimal_sk(dkg_out.test_SK[1]),
                     decode_decimal_sk(dkg_out.test_SK[2]) }) {
        BIGNUM* s = decode_share_signed_or_magnitude(b);
        ASSERT_NE(s, nullptr);
        c0_shares.push_back(s);
    }

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));
    BIGNUM* delta = BN_dup(dao_dkg_delta());
    ASSERT_NE(delta, nullptr);
    std::vector<uint8_t> Delta_bytes(32, 0);
    BN_bn2binpad(delta, Delta_bytes.data(), 32);

    std::vector<crypto::public_key> new_pks;
    for (int i = 0; i < 4; ++i) {
        crypto::public_key pk2; crypto::secret_key sk2;
        crypto::generate_keys(pk2, sk2);
        new_pks.push_back(pk2);
    }
    std::vector<uint32_t> new_indices = { 1, 2, 3, 4 };
    const uint32_t t_new = 1;
    const uint32_t threshold = 2;

    auto make_contrib =
        [&](uint32_t i, const std::vector<uint32_t>& S,
            dao_reshare_contribution& c_out) -> bool
    {
        dao_reshare_link_context ctx_i;
        ctx_i.genesis_block_hash = crypto::null_hash;
        ctx_i.stable_key_record_hash.assign(32, 0);
        ctx_i.share_set_id = 100;
        ctx_i.contributor_pubkey.assign(32, 0);
        std::memcpy(ctx_i.contributor_pubkey.data(),
                    c0_pks[i - 1].data, 32);
        ctx_i.original_index = i;
        ctx_i.contributor_subset = S;
        ctx_i.N = dkg_out.record.N;
        ctx_i.V = dkg_out.record.V;
        ctx_i.VK_i = dkg_out.record.V_K_i[i - 1];
        ctx_i.C_i0.assign(PAILLIER_CT_BYTES, 0);
        ctx_i.Delta = Delta_bytes;

        BIGNUM* mu = BN_new();
        if (!mu || !cryptonote::dao::dao_dkg_lagrange_mu(S, i, mu)) {
            BN_free(mu); return false;
        }
        bool ok = dao_reshare_make_contribution(
            pk, vss, dkg_out.record.V, c0_shares[i - 1], mu, delta,
            t_new, new_indices, ctx_i, c_out);
        BN_free(mu);
        return ok;
    };

    dao_reshare_contribution c1_s12, c2_s12, c3_s23;
    ASSERT_TRUE(make_contrib(1, {1, 2}, c1_s12));
    ASSERT_TRUE(make_contrib(2, {1, 2}, c2_s12));
    ASSERT_TRUE(make_contrib(3, {2, 3}, c3_s23));

    // Control: matching subsets combine successfully.
    {
        std::vector<dao_reshare_contribution> contribs = { c1_s12, c2_s12 };
        dao_reshare_new_share ns;
        EXPECT_TRUE(dao_reshare_combine_one(
            pk, vss, dkg_out.record.V, contribs, new_indices,
            0, threshold, delta, ns))
            << "control case (matching subsets) should succeed";
        EXPECT_EQ(ns.share_signed.size(), DAO_RESHARE_SIGNED_BYTES);
        EXPECT_EQ(ns.VK_j.size(), PAILLIER_CT_BYTES);
    }

    // Negative: mismatched subsets must be rejected.
    {
        std::vector<dao_reshare_contribution> contribs = { c1_s12, c3_s23 };
        dao_reshare_new_share ns;
        EXPECT_FALSE(dao_reshare_combine_one(
            pk, vss, dkg_out.record.V, contribs, new_indices,
            0, threshold, delta, ns))
            << "combine_one accepted contributions with mismatched "
               "Lagrange subsets; a wrong result would silently pass "
               "the V^{s_j*delta}==VK_j check";
    }

    // Negative: insufficient contributions still fails.
    {
        std::vector<dao_reshare_contribution> contribs = { c1_s12 };
        dao_reshare_new_share ns;
        EXPECT_FALSE(dao_reshare_combine_one(
            pk, vss, dkg_out.record.V, contribs, new_indices,
            0, threshold, delta, ns));
    }

    for (auto* s : c0_shares) BN_free(s);
    BN_free(delta);
    boost::filesystem::remove_all(base);
}


// ------------------------------------------------------------------
// §9 item 7: all nodes derive the same reshape descriptor regardless
// of the ORDER in which reshare messages arrive at each node. Node A
// receives its mailbox FIFO, node B LIFO, node C interleaved (evens
// then odds). Message set is identical for all three; only arrival
// order differs. Each node commits its own share set record; the test
// asserts all three records are structurally identical.
//
// Structural fields asserted equal across the three nodes:
//   share_set_id, committee_members, VK_i, threshold,
//   contributor_indices, contributor_vk, base_share_set_id,
//   contributions.size()
//
// Bytes of individual contributions are NOT asserted equal: each
// node's view of a peer contribution carries its OWN decrypted share,
// so the serialized bytes legitimately differ per recipient.
// ------------------------------------------------------------------
TEST(DaoV2Replay, ReshapeDescriptorOrderIndependent)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_b3g_%%%%-%%%%");

    ReplayNode a, b, c;
    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));
    ASSERT_TRUE(c.init((base / "c").string()));

    auto& bc_a = a.core->get_blockchain_storage();
    auto& bc_b = b.core->get_blockchain_storage();
    auto& bc_c = c.core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();
    auto& db_b = bc_b.get_db();
    auto& db_c = bc_c.get_db();
    bc_a.set_dao_v2_active_for_test(true);
    bc_b.set_dao_v2_active_for_test(true);
    bc_c.set_dao_v2_active_for_test(true);

    // 3-party DKG (identical setup to B3d).
    std::vector<crypto::public_key> committee;
    std::vector<crypto::secret_key> committee_sks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk2; crypto::secret_key sk2;
        crypto::generate_keys(pk2, sk2);
        committee.push_back(pk2);
        committee_sks.push_back(sk2);
    }
    std::vector<size_t> ord = { 0, 1, 2 };
    std::sort(ord.begin(), ord.end(), [&](size_t x, size_t y) {
        return std::memcmp(committee[x].data, committee[y].data, 32) < 0;
    });
    {
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : ord) { p2.push_back(committee[i]); s2.push_back(committee_sks[i]); }
        committee = std::move(p2);
        committee_sks = std::move(s2);
    }
    crypto::public_key a_pub = committee[0];
    crypto::public_key b_pub = committee[1];
    crypto::public_key c_pub = committee[2];
    a.core->set_node_key(committee_sks[0]);
    b.core->set_node_key(committee_sks[1]);
    c.core->set_node_key(committee_sks[2]);

    crypto::public_key d_pub; crypto::secret_key d_sk;
    crypto::generate_keys(d_pub, d_sk);

    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));
    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config dcfg;
    dcfg.committee_size = 3;
    dcfg.threshold = dao_dkg_expected_threshold(3);
    dcfg.member_ids = committee;
    dcfg.k = 60; dcfg.target_N_bits = 128; dcfg.security_bits = 32;
    dcfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    dcfg.max_attempts = 1;
    dcfg.test_seed = 0x5645494C52544F33ULL;
    dcfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(dcfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_EQ(dkg_out.test_SK.size(), 3u);

    bc_a.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, dkg_out.local_secret_share);
    auto decode_decimal_sk = [](const std::vector<uint8_t>& dec)
        -> std::vector<uint8_t> {
        std::string s(dec.begin(), dec.end());
        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, s.c_str()) == 0) return {};
        bool neg = BN_is_negative(bn) != 0;
        BIGNUM* ab = BN_dup(bn); BN_set_negative(ab, 0);
        std::vector<uint8_t> r(1 + BN_num_bytes(ab), 0);
        r[0] = neg ? 1 : 0;
        BN_bn2bin(ab, r.data() + 1);
        BN_free(ab); BN_free(bn);
        return r;
    };
    bc_b.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_decimal_sk(dkg_out.test_SK[1]));
    bc_c.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_decimal_sk(dkg_out.test_SK[2]));

    // Mine to height 5.
    account_base miner; miner.generate();
    while (bc_a.get_current_blockchain_height() < 5) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc_a.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc_a](const block& bb, uint64_t hh,
                           const crypto::hash* s, unsigned int mn,
                           crypto::hash& o) -> bool {
            return get_block_longhash(&bc_a, bb, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata blob = block_to_blob(tmpl);
        ASSERT_TRUE(a.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(b.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(c.core->handle_single_incoming_block(
            blob, &tmpl, bvc, e, false));
    }

    crypto::hash g_hash = bc_a.get_block_id_by_height(0);
    const uint64_t vote_end = 3;
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        for (const auto& pk : { a_pub, b_pub, c_pub, d_pub })
            db->add_dao_v2_node_ready(pk, 0, g_hash);
    }

    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xD3, 32);
    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));
    BIGNUM* Wb = BN_new(); BN_set_word(Wb, 1000);
    BIGNUM* Sb = BN_new(); BN_set_word(Sb, 1000);
    BIGNUM* Bb = BN_new(); BN_set_word(Bb, 50000);
    BIGNUM* r1 = BN_new(); BN_set_word(r1, 3);
    BIGNUM* r2 = BN_new(); BN_set_word(r2, 5);
    BIGNUM* r3 = BN_new(); BN_set_word(r3, 7);
    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(Wb, r1, E_W));
    ASSERT_TRUE(pk.encrypt(Sb, r2, E_S));
    ASSERT_TRUE(pk.encrypt(Bb, r3, E_B));
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        proposal_record rec{};
        rec.proposal_id = prop_id;
        rec.submission_height = 0;
        rec.voting_end_height = vote_end;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(rec.tally_key_id.data, dkg_out.record.key_id.data(), 32);
        db->add_proposal_record(prop_id, rec);
        dao_proposal_aggregate agg;
        agg.aggregate_E_W = E_W;
        agg.aggregate_E_S = E_S;
        agg.aggregate_E_B = E_B;
        agg.aggregate_C_W = rct::identity();
        agg.aggregate_C_S = rct::identity();
        agg.aggregate_C_B = rct::identity();
        db->add_dao_proposal_aggregate(prop_id, agg);
        dao_supply_snapshot snap;
        snap.height = vote_end;
        snap.minted = dao_u128(100000);
        snap.circulating = dao_u128(50000);
        db->add_dao_supply_snapshot(snap);
    }

    std::vector<std::pair<crypto::public_key, std::string>> mailbox;
    std::mutex mb_mu;
    bc_a.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(a_pub, s); return true;
    });
    bc_b.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(b_pub, s); return true;
    });
    bc_c.set_dao_v2_dkg_send([&](const std::string& s) -> bool {
        std::lock_guard<std::mutex> lk(mb_mu);
        mailbox.emplace_back(c_pub, s); return true;
    });
    for (auto* bc : { &bc_a, &bc_b, &bc_c })
        bc->set_dao_v2_tally_broadcast([](const dao_v2_tally_share&) {});

    // Trigger first reshape on all three nodes.
    bc_a.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    bc_b.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);
    bc_c.maybe_start_dao_v2_reshare_for_proposal(prop_id, vote_end);

    // Drive with per-node delivery ordering:
    //   A: FIFO
    //   B: LIFO (reverse)
    //   C: interleaved (even indices then odd indices)
    // Same message set to all three nodes; only arrival order differs.
    for (int round = 0; round < 15; ++round) {
        std::vector<std::pair<crypto::public_key, std::string>> batch;
        {
            std::lock_guard<std::mutex> lk(mb_mu);
            batch.swap(mailbox);
        }
        // A: FIFO
        for (auto& m : batch)
            if (m.first != a_pub)
                bc_a.handle_dao_v2_dkg_msg(m.first, m.second);
        // B: LIFO
        for (auto it = batch.rbegin(); it != batch.rend(); ++it)
            if (it->first != b_pub)
                bc_b.handle_dao_v2_dkg_msg(it->first, it->second);
        // C: evens then odds
        for (size_t i = 0; i < batch.size(); i += 2)
            if (batch[i].first != c_pub)
                bc_c.handle_dao_v2_dkg_msg(batch[i].first, batch[i].second);
        for (size_t i = 1; i < batch.size(); i += 2)
            if (batch[i].first != c_pub)
                bc_c.handle_dao_v2_dkg_msg(batch[i].first, batch[i].second);
        bc_a.maybe_commit_dao_v2_reshare();
        bc_b.maybe_commit_dao_v2_reshare();
        bc_c.maybe_commit_dao_v2_reshare();
    }

    auto find_latest = [](BlockchainDB& db,
                          const std::vector<uint8_t>& kid) -> uint64_t {
        uint64_t sid = 0;
        db.for_all_dao_share_sets(
            [&](uint64_t id, const dao_share_set_record& r) -> bool {
                if (r.key_id == kid && !r.contributions.empty() && id > sid)
                    sid = id;
                return true;
            });
        return sid;
    };

    uint64_t sid_a = find_latest(db_a, dkg_out.record.key_id);
    uint64_t sid_b = find_latest(db_b, dkg_out.record.key_id);
    uint64_t sid_c = find_latest(db_c, dkg_out.record.key_id);
    ASSERT_NE(sid_a, 0u) << "node A did not commit a reshare";
    ASSERT_NE(sid_b, 0u) << "node B did not commit a reshare";
    ASSERT_NE(sid_c, 0u) << "node C did not commit a reshare";

    EXPECT_EQ(sid_a, sid_b) << "A and B disagree on reshare share_set_id";
    EXPECT_EQ(sid_b, sid_c) << "B and C disagree on reshare share_set_id";

    dao_share_set_record ssa, ssb, ssc;
    ASSERT_TRUE(db_a.get_dao_share_set(sid_a, ssa));
    ASSERT_TRUE(db_b.get_dao_share_set(sid_b, ssb));
    ASSERT_TRUE(db_c.get_dao_share_set(sid_c, ssc));

    EXPECT_EQ(ssa.committee_members, ssb.committee_members);
    EXPECT_EQ(ssb.committee_members, ssc.committee_members);
    EXPECT_EQ(ssa.VK_i, ssb.VK_i);
    EXPECT_EQ(ssb.VK_i, ssc.VK_i);
    EXPECT_EQ(ssa.threshold, ssb.threshold);
    EXPECT_EQ(ssb.threshold, ssc.threshold);
    EXPECT_EQ(ssa.contributor_indices, ssb.contributor_indices);
    EXPECT_EQ(ssb.contributor_indices, ssc.contributor_indices);
    EXPECT_EQ(ssa.contributor_vk, ssb.contributor_vk);
    EXPECT_EQ(ssb.contributor_vk, ssc.contributor_vk);
    EXPECT_EQ(ssa.base_share_set_id, ssb.base_share_set_id);
    EXPECT_EQ(ssb.base_share_set_id, ssc.base_share_set_id);
    EXPECT_EQ(ssa.contributions.size(), ssb.contributions.size());
    EXPECT_EQ(ssb.contributions.size(), ssc.contributions.size());
    EXPECT_FALSE(ssa.contributions.empty());

    BN_free(Wb); BN_free(Sb); BN_free(Bb);
    BN_free(r1); BN_free(r2); BN_free(r3);
    boost::filesystem::remove_all(base);
}


// ------------------------------------------------------------------
// Reshare commit atomicity and send-callback independence.
// ------------------------------------------------------------------
TEST(DaoV2Replay, ReshareCommitAtomicBothRecordsWritten)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    auto decode_decimal_sk = [](const std::vector<uint8_t>& dec)
        -> std::vector<uint8_t> {
        std::string s(dec.begin(), dec.end());
        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, s.c_str()) == 0) return {};
        bool neg = BN_is_negative(bn) != 0;
        BIGNUM* ab = BN_dup(bn); BN_set_negative(ab, 0);
        std::vector<uint8_t> r(1 + BN_num_bytes(ab), 0);
        r[0] = neg ? 1 : 0;
        BN_bn2bin(ab, r.data() + 1);
        BN_free(ab); BN_free(bn);
        return r;
    };

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_commit_atomic_%%%%-%%%%");

    ReplayNode a, b, c;
    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));
    ASSERT_TRUE(c.init((base / "c").string()));
    auto& bc_a = a.core->get_blockchain_storage();
    auto& bc_b = b.core->get_blockchain_storage();
    auto& bc_c = c.core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();
    auto& db_b = bc_b.get_db();
    auto& db_c = bc_c.get_db();
    bc_a.set_dao_v2_active_for_test(true);
    bc_b.set_dao_v2_active_for_test(true);
    bc_c.set_dao_v2_active_for_test(true);

    std::vector<crypto::public_key> c0;
    std::vector<crypto::secret_key> c0_sk;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key p; crypto::secret_key s;
        crypto::generate_keys(p, s);
        c0.push_back(p); c0_sk.push_back(s);
    }
    std::vector<size_t> ord = { 0, 1, 2 };
    std::sort(ord.begin(), ord.end(), [&](size_t x, size_t y) {
        return std::memcmp(c0[x].data, c0[y].data, 32) < 0;
    });
    {
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : ord) { p2.push_back(c0[i]); s2.push_back(c0_sk[i]); }
        c0 = std::move(p2);
        c0_sk = std::move(s2);
    }
    a.core->set_node_key(c0_sk[0]);
    b.core->set_node_key(c0_sk[1]);
    c.core->set_node_key(c0_sk[2]);

    // A 4th ready-only pubkey forces the reshare trigger: with only
    // the base committee in the ready set, cur_set == ready_set and
    // the trigger short-circuits. This key does not run a node; the
    // reshare completes on the three running nodes and this key ends
    // up in the new committee without a persisted local share.
    crypto::public_key d_pub; crypto::secret_key d_sk;
    crypto::generate_keys(d_pub, d_sk);

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory fac =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config dcfg;
    dcfg.committee_size = 3;
    dcfg.threshold = dao_dkg_expected_threshold(3);
    dcfg.member_ids = c0;
    dcfg.k = 60; dcfg.target_N_bits = 128; dcfg.security_bits = 32;
    dcfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    dcfg.max_attempts = 1;
    dcfg.test_seed = 0x5645494C52544F33ULL;
    dcfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(dcfg, fac, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_EQ(dkg_out.test_SK.size(), 3u);

    bc_a.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, dkg_out.local_secret_share);
    bc_b.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_decimal_sk(dkg_out.test_SK[1]));
    bc_c.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_decimal_sk(dkg_out.test_SK[2]));

    account_base miner; miner.generate();
    while (bc_a.get_current_blockchain_height() < 2) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc_a.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc_a](const block& bb, uint64_t hh,
                           const crypto::hash* s, unsigned int mn,
                           crypto::hash& o) -> bool {
            return get_block_longhash(&bc_a, bb, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata blob = block_to_blob(tmpl);
        ASSERT_TRUE(a.core->handle_single_incoming_block(blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(b.core->handle_single_incoming_block(blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(c.core->handle_single_incoming_block(blob, &tmpl, bvc, e, false));
    }
    crypto::hash gh = bc_a.get_block_id_by_height(0);
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        for (const auto& pk : c0) db->add_dao_v2_node_ready(pk, 0, gh);
        db->add_dao_v2_node_ready(d_pub, 0, gh);
    }
    crypto::hash pid{};
    std::memset(pid.data, 0xA1, 32);
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        proposal_record pr{};
        pr.proposal_id = pid;
        pr.voting_end_height = 1;
        pr.status = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(pr.tally_key_id.data, dkg_out.record.key_id.data(), 32);
        db->add_proposal_record(pid, pr);
    }

    std::vector<std::pair<crypto::public_key, std::string>> mailbox;
    std::mutex mu;
    bc_a.set_dao_v2_dkg_send([&](const std::string& s)->bool{
        std::lock_guard<std::mutex> lk(mu);
        mailbox.emplace_back(c0[0], s); return true; });
    bc_b.set_dao_v2_dkg_send([&](const std::string& s)->bool{
        std::lock_guard<std::mutex> lk(mu);
        mailbox.emplace_back(c0[1], s); return true; });
    bc_c.set_dao_v2_dkg_send([&](const std::string& s)->bool{
        std::lock_guard<std::mutex> lk(mu);
        mailbox.emplace_back(c0[2], s); return true; });
    for (auto* bc : { &bc_a, &bc_b, &bc_c })
        bc->set_dao_v2_tally_broadcast([](const dao_v2_tally_share&){});

    bc_a.maybe_start_dao_v2_reshare_for_proposal(pid, 1);
    bc_b.maybe_start_dao_v2_reshare_for_proposal(pid, 1);
    bc_c.maybe_start_dao_v2_reshare_for_proposal(pid, 1);

    for (int r = 0; r < 20; ++r) {
        std::vector<std::pair<crypto::public_key, std::string>> batch;
        { std::lock_guard<std::mutex> lk(mu); batch.swap(mailbox); }
        for (auto& [snd, pl] : batch) {
            if (std::memcmp(snd.data, c0[0].data, 32) != 0)
                bc_a.handle_dao_v2_dkg_msg(snd, pl);
            if (std::memcmp(snd.data, c0[1].data, 32) != 0)
                bc_b.handle_dao_v2_dkg_msg(snd, pl);
            if (std::memcmp(snd.data, c0[2].data, 32) != 0)
                bc_c.handle_dao_v2_dkg_msg(snd, pl);
        }
        bc_a.maybe_commit_dao_v2_reshare();
        bc_b.maybe_commit_dao_v2_reshare();
        bc_c.maybe_commit_dao_v2_reshare();
    }

    auto find_latest = [](BlockchainDB& db,
                          const std::vector<uint8_t>& kid) -> uint64_t {
        uint64_t sid = 0;
        db.for_all_dao_share_sets(
            [&](uint64_t id, const dao_share_set_record& r) -> bool {
                if (r.key_id == kid && !r.contributions.empty() && id > sid)
                    sid = id;
                return true;
            });
        return sid;
    };

    uint64_t sid_a = find_latest(db_a, dkg_out.record.key_id);
    uint64_t sid_b = find_latest(db_b, dkg_out.record.key_id);
    uint64_t sid_c = find_latest(db_c, dkg_out.record.key_id);
    ASSERT_NE(sid_a, 0u) << "no reshare committed on A";
    ASSERT_NE(sid_b, 0u) << "no reshare committed on B";
    ASSERT_NE(sid_c, 0u) << "no reshare committed on C";
    EXPECT_EQ(sid_a, sid_b);
    EXPECT_EQ(sid_b, sid_c);

    dao_share_set_record ss;
    ASSERT_TRUE(db_a.get_dao_share_set(sid_a, ss));
    ASSERT_GT(ss.committee_members.size(), 0u);

    struct Triple { BlockchainDB* db; crypto::public_key pk; };
    for (const auto& t : { Triple{&db_a, c0[0]},
                            Triple{&db_b, c0[1]},
                            Triple{&db_c, c0[2]} }) {
        uint32_t pos = 0;
        for (size_t i = 0; i < ss.committee_members.size(); ++i) {
            if (ss.committee_members[i].size() != 32) continue;
            if (std::memcmp(ss.committee_members[i].data(),
                            t.pk.data, 32) == 0) {
                pos = static_cast<uint32_t>(i) + 1;
                break;
            }
        }
        ASSERT_NE(pos, 0u);
        std::vector<uint8_t> packed;
        ASSERT_TRUE(t.db->get_dao_local_share(
            static_cast<uint32_t>(sid_a), pos, packed))
            << "missing local share for pos " << pos;
        EXPECT_FALSE(packed.empty());
    }

    boost::filesystem::remove_all(base);
}

TEST(DaoV2Replay, ReshareCommitWorksWithoutSendCallback)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_commit_nocb_%%%%-%%%%");

    ReplayNode a;
    ASSERT_TRUE(a.init((base / "a").string()));
    auto& bc_a = a.core->get_blockchain_storage();
    bc_a.set_dao_v2_active_for_test(true);

    bc_a.set_dao_v2_dkg_send({});
    EXPECT_TRUE(bc_a.maybe_commit_dao_v2_reshare());
    EXPECT_FALSE(bc_a.has_dao_v2_reshare_runner_for_test());

    boost::filesystem::remove_all(base);
}

TEST(DaoV2Replay, ReshareCommitPreservesRunnerWhenNotFinished)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    auto decode_decimal_sk = [](const std::vector<uint8_t>& dec)
        -> std::vector<uint8_t> {
        std::string s(dec.begin(), dec.end());
        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, s.c_str()) == 0) return {};
        bool neg = BN_is_negative(bn) != 0;
        BIGNUM* ab = BN_dup(bn); BN_set_negative(ab, 0);
        std::vector<uint8_t> r(1 + BN_num_bytes(ab), 0);
        r[0] = neg ? 1 : 0;
        BN_bn2bin(ab, r.data() + 1);
        BN_free(ab); BN_free(bn);
        return r;
    };

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_commit_preserve_%%%%-%%%%");

    ReplayNode a, b, c;
    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));
    ASSERT_TRUE(c.init((base / "c").string()));
    auto& bc_a = a.core->get_blockchain_storage();
    auto& bc_b = b.core->get_blockchain_storage();
    auto& bc_c = c.core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();
    auto& db_b = bc_b.get_db();
    auto& db_c = bc_c.get_db();
    bc_a.set_dao_v2_active_for_test(true);
    bc_b.set_dao_v2_active_for_test(true);
    bc_c.set_dao_v2_active_for_test(true);

    std::vector<crypto::public_key> c0;
    std::vector<crypto::secret_key> c0_sk;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key p; crypto::secret_key s;
        crypto::generate_keys(p, s);
        c0.push_back(p); c0_sk.push_back(s);
    }
    std::vector<size_t> ord = { 0, 1, 2 };
    std::sort(ord.begin(), ord.end(), [&](size_t x, size_t y) {
        return std::memcmp(c0[x].data, c0[y].data, 32) < 0;
    });
    {
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : ord) { p2.push_back(c0[i]); s2.push_back(c0_sk[i]); }
        c0 = std::move(p2);
        c0_sk = std::move(s2);
    }
    a.core->set_node_key(c0_sk[0]);
    b.core->set_node_key(c0_sk[1]);
    c.core->set_node_key(c0_sk[2]);

    crypto::public_key d_pub; crypto::secret_key d_sk;
    crypto::generate_keys(d_pub, d_sk);

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory fac =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };
    dkg_config dcfg;
    dcfg.committee_size = 3;
    dcfg.threshold = dao_dkg_expected_threshold(3);
    dcfg.member_ids = c0;
    dcfg.k = 60; dcfg.target_N_bits = 128; dcfg.security_bits = 32;
    dcfg.qproof_rounds = DAO_DKG_QPROOF_ROUNDS_TEST;
    dcfg.max_attempts = 1;
    dcfg.test_seed = 0x5645494C52544F33ULL;
    dcfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(dcfg, fac, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_EQ(dkg_out.test_SK.size(), 3u);

    bc_a.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, dkg_out.local_secret_share);
    bc_b.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_decimal_sk(dkg_out.test_SK[1]));
    bc_c.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, decode_decimal_sk(dkg_out.test_SK[2]));

    account_base miner; miner.generate();
    while (bc_a.get_current_blockchain_height() < 2) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc_a.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc_a](const block& bb, uint64_t hh,
                           const crypto::hash* s, unsigned int mn,
                           crypto::hash& o) -> bool {
            return get_block_longhash(&bc_a, bb, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata blob = block_to_blob(tmpl);
        ASSERT_TRUE(a.core->handle_single_incoming_block(blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(b.core->handle_single_incoming_block(blob, &tmpl, bvc, e, false));
        ASSERT_TRUE(c.core->handle_single_incoming_block(blob, &tmpl, bvc, e, false));
    }
    crypto::hash gh = bc_a.get_block_id_by_height(0);
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        for (const auto& pk : c0) db->add_dao_v2_node_ready(pk, 0, gh);
        db->add_dao_v2_node_ready(d_pub, 0, gh);
    }
    crypto::hash pid{};
    std::memset(pid.data, 0xA2, 32);
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        proposal_record pr{};
        pr.proposal_id = pid;
        pr.voting_end_height = 1;
        pr.status = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(pr.tally_key_id.data, dkg_out.record.key_id.data(), 32);
        db->add_proposal_record(pid, pr);
    }

    bc_a.set_dao_v2_dkg_send([](const std::string&)->bool{ return true; });
    bc_b.set_dao_v2_dkg_send([](const std::string&)->bool{ return true; });
    bc_c.set_dao_v2_dkg_send([](const std::string&)->bool{ return true; });
    for (auto* bc : { &bc_a, &bc_b, &bc_c })
        bc->set_dao_v2_tally_broadcast([](const dao_v2_tally_share&){});

    // Trigger only on A; do not drive. Runner starts but never
    // finishes. commit must be a no-op that preserves the runner.
    bc_a.maybe_start_dao_v2_reshare_for_proposal(pid, 1);
    ASSERT_TRUE(bc_a.has_dao_v2_reshare_runner_for_test());
    EXPECT_TRUE(bc_a.maybe_commit_dao_v2_reshare());
    ASSERT_TRUE(bc_a.has_dao_v2_reshare_runner_for_test())
        << "runner was reset despite not being finished";

    boost::filesystem::remove_all(base);
}


TEST(DaoV2Replay, ProposalDkgEndToEndActivation)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_dkg_e2e_%%%%-%%%%");

    struct PathCleanup {
        boost::filesystem::path p;
        ~PathCleanup() { try { boost::filesystem::remove_all(p); } catch (...) {} }
    };
    PathCleanup cleanup_guard{base};

    ReplayNode a, b, c;
    ASSERT_TRUE(a.init((base / "a").string()));
    ASSERT_TRUE(b.init((base / "b").string()));
    ASSERT_TRUE(c.init((base / "c").string()));
    auto& bc_a = a.core->get_blockchain_storage();
    auto& bc_b = b.core->get_blockchain_storage();
    auto& bc_c = c.core->get_blockchain_storage();
    auto& db_a = bc_a.get_db();
    auto& db_b = bc_b.get_db();
    auto& db_c = bc_c.get_db();
    bc_a.set_dao_v2_active_for_test(true);
    bc_b.set_dao_v2_active_for_test(true);
    bc_c.set_dao_v2_active_for_test(true);

    std::vector<crypto::public_key> pk_set;
    std::vector<crypto::secret_key> sk_set;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        pk_set.push_back(pk); sk_set.push_back(sk);
    }
    std::vector<size_t> ord = { 0, 1, 2 };
    std::sort(ord.begin(), ord.end(), [&](size_t x, size_t y) {
        return std::memcmp(pk_set[x].data, pk_set[y].data, 32) < 0;
    });
    {
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : ord) { p2.push_back(pk_set[i]); s2.push_back(sk_set[i]); }
        pk_set = std::move(p2); sk_set = std::move(s2);
    }
    a.core->set_node_key(sk_set[0]);
    b.core->set_node_key(sk_set[1]);
    c.core->set_node_key(sk_set[2]);

    account_base miner; miner.generate();
    while (bc_a.get_current_blockchain_height() < 3) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc_a.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc_a](const block& bl, uint64_t hh,
                           const crypto::hash* s, unsigned int mn,
                           crypto::hash& o) -> bool {
            return get_block_longhash(&bc_a, bl, o, hh, s, static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(gbh, tmpl, diff, h, nullptr));
        blobdata bb = block_to_blob(tmpl);
        block_verification_context bvc_a{}; pool_supplement ea{};
        block_verification_context bvc_b{}; pool_supplement eb{};
        block_verification_context bvc_c{}; pool_supplement ec{};
        ASSERT_TRUE(a.core->handle_single_incoming_block(bb, &tmpl, bvc_a, ea, false));
        ASSERT_TRUE(b.core->handle_single_incoming_block(bb, &tmpl, bvc_b, eb, false));
        ASSERT_TRUE(c.core->handle_single_incoming_block(bb, &tmpl, bvc_c, ec, false));
        ASSERT_FALSE(bvc_a.m_verifivation_failed);
        ASSERT_FALSE(bvc_b.m_verifivation_failed);
        ASSERT_FALSE(bvc_c.m_verifivation_failed);
        ASSERT_TRUE(bvc_a.m_added_to_main_chain);
        ASSERT_TRUE(bvc_b.m_added_to_main_chain);
        ASSERT_TRUE(bvc_c.m_added_to_main_chain);
    }
    ASSERT_EQ(bc_a.get_current_blockchain_height(), bc_b.get_current_blockchain_height());
    ASSERT_EQ(bc_a.get_current_blockchain_height(), bc_c.get_current_blockchain_height());
    for (uint64_t hh = 0; hh < bc_a.get_current_blockchain_height(); ++hh) {
        ASSERT_EQ(bc_a.get_block_id_by_height(hh), bc_b.get_block_id_by_height(hh));
        ASSERT_EQ(bc_a.get_block_id_by_height(hh), bc_c.get_block_id_by_height(hh));
    }
    crypto::hash can_hash_1 = bc_a.get_block_id_by_height(1);

    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        for (const auto& pk : pk_set) db->add_dao_v2_node_ready(pk, 1, can_hash_1);
    }

    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xE2, 32);
    const uint64_t sub_h = bc_a.get_current_blockchain_height();
    for (auto* db : { &db_a, &db_b, &db_c }) {
        db_wtxn_guard g(db);
        proposal_record rec{};
        rec.proposal_id = prop_id;
        rec.submission_height = sub_h;
        rec.voting_end_height = sub_h + 720;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        std::memset(rec.tally_key_id.data, 0, 32);
        db->add_proposal_record(prop_id, rec);
    }

    struct DkgMailboxState {
        std::mutex mutex;
        std::vector<std::pair<crypto::public_key, std::string>> messages;
    };
    auto mailbox = std::make_shared<DkgMailboxState>();
    auto make_send = [mailbox](crypto::public_key sender) {
        return [mailbox, sender](const std::string& s) -> bool {
            std::lock_guard<std::mutex> lk(mailbox->mutex);
            mailbox->messages.emplace_back(sender, s);
            return true;
        };
    };
    bc_a.set_dao_v2_dkg_send(make_send(pk_set[0]));
    bc_b.set_dao_v2_dkg_send(make_send(pk_set[1]));
    bc_c.set_dao_v2_dkg_send(make_send(pk_set[2]));
    for (auto* bc : { &bc_a, &bc_b, &bc_c })
        bc->set_dao_v2_tally_broadcast([](const dao_v2_tally_share&){});

    bc_a.set_dao_v2_test_dkg_seed(dao::DAO_DKG_TEST_SEED_3);
    bc_b.set_dao_v2_test_dkg_seed(dao::DAO_DKG_TEST_SEED_3);
    bc_c.set_dao_v2_test_dkg_seed(dao::DAO_DKG_TEST_SEED_3);
    bc_a.set_dao_v2_test_dkg_phase_timeout_seconds(30);
    bc_b.set_dao_v2_test_dkg_phase_timeout_seconds(30);
    bc_c.set_dao_v2_test_dkg_phase_timeout_seconds(30);

    auto st_a = bc_a.start_dao_v2_dkg_for_proposal(prop_id);
    auto st_b = bc_b.start_dao_v2_dkg_for_proposal(prop_id);
    auto st_c = bc_c.start_dao_v2_dkg_for_proposal(prop_id);
    EXPECT_EQ(st_a, dao::dao_dkg_start_status::started)
        << "node A start status=" << (int)st_a;
    EXPECT_EQ(st_b, dao::dao_dkg_start_status::started)
        << "node B start status=" << (int)st_b;
    EXPECT_EQ(st_c, dao::dao_dkg_start_status::started)
        << "node C start status=" << (int)st_c;
    if (st_a != dao::dao_dkg_start_status::started ||
        st_b != dao::dao_dkg_start_status::started ||
        st_c != dao::dao_dkg_start_status::started) {
        return;
    }

    auto mine_one = [&]() -> bool {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        if (!bc_a.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh))
            return false;
        auto gbh = [&bc_a](const block& bl, uint64_t hh,
                           const crypto::hash* s, unsigned int mn,
                           crypto::hash& o) -> bool {
            return get_block_longhash(&bc_a, bl, o, hh, s, static_cast<int>(mn));
        };
        if (!miner::find_nonce_for_given_block(gbh, tmpl, diff, h, nullptr))
            return false;

        const blobdata bb = block_to_blob(tmpl);

        // A block contains transaction hashes, not full bodies. B and C
        // are separate nodes with separate mempools — they do not
        // automatically have A's activation tx. Build independent
        // supplements from A's pool BEFORE A mines.
        auto build_supplement = [&](pool_supplement& out) -> bool {
            for (const crypto::hash& txid : tmpl.tx_hashes) {
                blobdata tx_blob;
                if (!a.core->get_pool_transaction(
                        txid, tx_blob, relay_category::all)) {
                    std::cerr << "Missing source tx in A pool: "
                              << txid << std::endl;
                    return false;
                }
                transaction tx;
                crypto::hash parsed_id{};
                if (!parse_and_validate_tx_from_blob(
                        tx_blob, tx, parsed_id) ||
                    parsed_id != txid) {
                    std::cerr << "Invalid tx supplement: "
                              << txid << std::endl;
                    return false;
                }
                out.txs_by_txid.emplace(
                    txid, std::make_pair(std::move(tx),
                                          std::move(tx_blob)));
            }
            return true;
        };

        pool_supplement e_b{}, e_c{};
        if (!build_supplement(e_b) || !build_supplement(e_c))
            return false;

        const uint64_t new_h = bc_a.get_current_blockchain_height();
        const crypto::hash expected_block_id = get_block_hash(tmpl);

        block_verification_context bvc_a{};
        pool_supplement e_a{};
        if (!a.core->handle_single_incoming_block(
                bb, &tmpl, bvc_a, e_a, false) ||
            bvc_a.m_verifivation_failed ||
            !bvc_a.m_added_to_main_chain) {
            std::cerr << "A failed block: vf=" << bvc_a.m_verifivation_failed
                      << " miss=" << bvc_a.m_missing_txs << std::endl;
            return false;
        }

        block_verification_context bvc_b{};
        if (!b.core->handle_single_incoming_block(
                bb, &tmpl, bvc_b, e_b, false) ||
            bvc_b.m_verifivation_failed ||
            bvc_b.m_missing_txs ||
            !bvc_b.m_added_to_main_chain) {
            std::cerr << "B failed block: vf=" << bvc_b.m_verifivation_failed
                      << " miss=" << bvc_b.m_missing_txs << std::endl;
            return false;
        }

        block_verification_context bvc_c{};
        if (!c.core->handle_single_incoming_block(
                bb, &tmpl, bvc_c, e_c, false) ||
            bvc_c.m_verifivation_failed ||
            bvc_c.m_missing_txs ||
            !bvc_c.m_added_to_main_chain) {
            std::cerr << "C failed block: vf=" << bvc_c.m_verifivation_failed
                      << " miss=" << bvc_c.m_missing_txs << std::endl;
            return false;
        }

        if (bc_a.get_block_id_by_height(new_h) != expected_block_id ||
            bc_b.get_block_id_by_height(new_h) != expected_block_id ||
            bc_c.get_block_id_by_height(new_h) != expected_block_id) {
            std::cerr << "Nodes disagree on block at h=" << new_h << std::endl;
            return false;
        }
        return true;
    };

    auto pump_mailbox = [&]() {
        std::vector<std::pair<crypto::public_key, std::string>> batch;
        {
            std::lock_guard<std::mutex> lk(mailbox->mutex);
            batch.swap(mailbox->messages);
        }
        for (auto& [snd, pl] : batch) {
            if (std::memcmp(snd.data, pk_set[0].data, 32) != 0)
                bc_a.handle_dao_v2_dkg_msg(snd, pl);
            if (std::memcmp(snd.data, pk_set[1].data, 32) != 0)
                bc_b.handle_dao_v2_dkg_msg(snd, pl);
            if (std::memcmp(snd.data, pk_set[2].data, 32) != 0)
                bc_c.handle_dao_v2_dkg_msg(snd, pl);
        }
    };

    const auto overall_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(180);

    // Stage 1: pump DKG traffic until all three runners finish.
    bool stage1_ok = false;
    while (std::chrono::steady_clock::now() < overall_deadline) {
        pump_mailbox();
        Blockchain::dkg_runner_state_for_test sa, sb, sc;
        dao::dkg_result ra_out{}, rb_out{}, rc_out{};
        bc_a.get_dao_v2_dkg_runner_state_for_test(prop_id, sa, ra_out);
        bc_b.get_dao_v2_dkg_runner_state_for_test(prop_id, sb, rb_out);
        bc_c.get_dao_v2_dkg_runner_state_for_test(prop_id, sc, rc_out);

        auto report_fail = [](const char* who, const dao::dkg_result& r) {
            return std::string(who) + " runner finished unsuccessfully:"
                + " attempts=" + std::to_string(r.candidate_attempts)
                + " accepted=" + std::to_string(r.candidate_accepted)
                + " biprimality_failures=" + std::to_string(r.biprimality_failures)
                + " trial_div_failures=" + std::to_string(r.trial_division_failures)
                + " beta_retries=" + std::to_string(r.beta_phase_retries);
        };
        if (sa == Blockchain::dkg_runner_state_for_test::finished_fail)
            FAIL() << report_fail("A", ra_out);
        if (sb == Blockchain::dkg_runner_state_for_test::finished_fail)
            FAIL() << report_fail("B", rb_out);
        if (sc == Blockchain::dkg_runner_state_for_test::finished_fail)
            FAIL() << report_fail("C", rc_out);

        if (sa == Blockchain::dkg_runner_state_for_test::finished_ok &&
            sb == Blockchain::dkg_runner_state_for_test::finished_ok &&
            sc == Blockchain::dkg_runner_state_for_test::finished_ok) {
            stage1_ok = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!stage1_ok) {
        Blockchain::dkg_runner_state_for_test sa, sb, sc;
        dao::dkg_result ra_out{}, rb_out{}, rc_out{};
        bc_a.get_dao_v2_dkg_runner_state_for_test(prop_id, sa, ra_out);
        bc_b.get_dao_v2_dkg_runner_state_for_test(prop_id, sb, rb_out);
        bc_c.get_dao_v2_dkg_runner_state_for_test(prop_id, sc, rc_out);
        FAIL() << "Stage 1 deadline (180s) hit. Runner states: A="
               << (int)sa << " B=" << (int)sb << " C=" << (int)sc;
    }

    // Stage 2: pump result processing + attestations until the
    // activation tx appears in A's mempool. No mining yet.
    bool stage2_ok = false;
    while (std::chrono::steady_clock::now() < overall_deadline) {
        pump_mailbox();
        bc_a.maybe_process_dao_v2_dkg_results();
        bc_b.maybe_process_dao_v2_dkg_results();
        bc_c.maybe_process_dao_v2_dkg_results();
        if (a.core->get_pool_transactions_count(false) > 0) {
            stage2_ok = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!stage2_ok) {
        FAIL() << "Stage 2 deadline (180s) hit. Activation tx did not "
                  "appear in A's mempool.";
    }

    // Give any activation tx already in A's mempool a chance to be mined.
    for (int extra = 0; extra < 5; ++extra) {
        ASSERT_TRUE(mine_one());
        bc_a.maybe_process_dao_v2_dkg_results();
        bc_b.maybe_process_dao_v2_dkg_results();
        bc_c.maybe_process_dao_v2_dkg_results();
    }

    proposal_record rec_a{}, rec_b{}, rec_c{};
    ASSERT_TRUE(db_a.get_proposal_record(prop_id, rec_a));
    ASSERT_TRUE(db_b.get_proposal_record(prop_id, rec_b));
    ASSERT_TRUE(db_c.get_proposal_record(prop_id, rec_c));

    EXPECT_NE(rec_a.tally_key_id, crypto::null_hash)
        << "A: tally_key_id never set (proposal DKG activation did not complete)";
    EXPECT_EQ(rec_a.tally_key_id, rec_b.tally_key_id)
        << "A and B disagree on proposal key_id";
    EXPECT_EQ(rec_b.tally_key_id, rec_c.tally_key_id)
        << "B and C disagree on proposal key_id";
}
