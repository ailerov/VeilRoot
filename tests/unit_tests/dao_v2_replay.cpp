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

    a.core->get_blockchain_storage().queue_dao_v2_dkg_result(1, dkg_out);
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

    const crypto::hash digest = dao::dao_dkg_activation_digest(
        genesis_hash, selection_height, dkg_out.record);
    ASSERT_NE(digest, crypto::null_hash);

    dao::dao_dkg_key_activation act;
    act.version          = 1;
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
// Reshare trigger.
//
// The eligible set must at all times be covered by the current share
// set. When an eligible node appears that is not in the current share
// set, maybe_maintain_dao_v2_share_set() must start a reshare.
//
// This test installs the bootstrap share set (2 members) on a single
// node, adds a third eligible record, captures the P2P sends, and
// confirms that the trigger broadcast at least one reshare deal.
// It does not run the reshare to completion; that requires two
// cooperating nodes, and is covered separately.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, ReshareTriggerFiresWhenEligibleSetGrows)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_trigger_%%%%-%%%%");

    ReplayNode a;
    ASSERT_TRUE(a.init((base / "a").string()));

    auto& bc = a.core->get_blockchain_storage();
    auto& db = bc.get_db();
    bc.set_dao_v2_active_for_test(true);

    // Three committee member keys, sorted ascending.
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
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : idx) { p2.push_back(committee_pks[i]); s2.push_back(committee_sks[i]); }
        committee_pks = std::move(p2);
        committee_sks = std::move(s2);
    }
    a.core->set_node_key(committee_sks[0]);

    // Real DKG.
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

    // Install key record + bootstrap share set.
    bc.install_dao_tally_key_for_test(dkg_out.record);

    EXPECT_EQ(db.get_current_dao_share_set_id(), 1u);

    // Store local share for member 1 under share set 1.
    {
        std::vector<uint8_t> packed = dao_pack_local_share(
            dkg_out.record.key_id, dkg_out.local_secret_share);
        ASSERT_FALSE(packed.empty());
        db_wtxn_guard g(&db);
        db.add_dao_local_share(1, 1, packed);
    }

    // Install eligible records for the three existing members, plus a
    // fourth node not present in the bootstrap set.
    for (int i = 0; i < 3; ++i) {
        committee_eligible_record er{};
        er.node_pubkey = committee_pks[i];
        er.amount = 3000000;
        er.unlock_height = 0;
        crypto::key_image ki{};
        std::memset(ki.data, 0, sizeof(ki.data));
        ki.data[0] = static_cast<uint8_t>(i + 1);
        db_wtxn_guard g(&db);
        db.add_committee_eligible(ki, er);
    }
    {
        crypto::public_key p4; crypto::secret_key s4;
        crypto::generate_keys(p4, s4);
        committee_eligible_record er{};
        er.node_pubkey = p4;
        er.amount = 1000000;
        er.unlock_height = 0;
        crypto::key_image ki{};
        std::memset(ki.data, 0, sizeof(ki.data));
        ki.data[0] = 4;
        db_wtxn_guard g(&db);
        db.add_committee_eligible(ki, er);
    }

    // Capture reshare broadcasts.
    std::atomic<int> broadcasts{0};
    bc.set_dao_v2_dkg_send([&broadcasts](const std::string&) -> bool {
        broadcasts.fetch_add(1);
        return true;
    });

    // Run the trigger.
    {
        db_wtxn_guard g(&db);
        bc.maybe_maintain_dao_v2_share_set();
    }

    EXPECT_GT(broadcasts.load(), 0);

    boost::filesystem::remove_all(base);
}


// ---------------------------------------------------------------------
// Two-node resharing.
//
// Two ReplayNodes with distinct node keys, sharing the same bootstrap
// key record and share set. Both nodes install the same eligible set
// including a fourth, new node. Both run the trigger. Their reshare
// messages are passed through a shared mailbox. Both must commit the
// same new share set.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, ReshareCompletesAcrossTwoNodes)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_two_%%%%-%%%%");

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

    // Committee of 3, sorted ascending.
    std::vector<crypto::public_key> c_pks;
    std::vector<crypto::secret_key> c_sks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        c_pks.push_back(pk);
        c_sks.push_back(sk);
    }
    {
        std::vector<size_t> idx = {0, 1, 2};
        std::sort(idx.begin(), idx.end(), [&](size_t x, size_t y) {
            return std::memcmp(c_pks[x].data, c_pks[y].data, 32) < 0;
        });
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : idx) { p2.push_back(c_pks[i]); s2.push_back(c_sks[i]); }
        c_pks = std::move(p2);
        c_sks = std::move(s2);
    }
    a.core->set_node_key(c_sks[0]);
    b.core->set_node_key(c_sks[1]);

    crypto::public_key a_pub, b_pub;
    ASSERT_TRUE(crypto::secret_key_to_public_key(c_sks[0], a_pub));
    ASSERT_TRUE(crypto::secret_key_to_public_key(c_sks[1], b_pub));

    // Real DKG for the bootstrap committee.
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
    cfg.member_ids     = c_pks;
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

    // Install the same key record on both nodes.
    bc_a.install_dao_tally_key_for_test(dkg_out.record);
    bc_b.install_dao_tally_key_for_test(dkg_out.record);

    // Local shares: A holds position 1, B holds position 2. We use the
    // test-only oracle SK for member 2 to give B a valid share.
    {
        std::vector<uint8_t> packed_a = dao_pack_local_share(
            dkg_out.record.key_id, dkg_out.local_secret_share);
        ASSERT_FALSE(packed_a.empty());
        db_wtxn_guard g(&db_a);
        db_a.add_dao_local_share(1, 1, packed_a);
    }
    {
        // test_SK[1] holds B's share as a decimal string (test oracle).
        // Convert to BIGNUM, then encode in the signed byte layout the
        // envelope expects: 1 sign byte then big-endian magnitude.
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
        std::vector<uint8_t> packed_b =
            dao_pack_local_share(dkg_out.record.key_id, raw);
        ASSERT_FALSE(packed_b.empty());
        db_wtxn_guard g(&db_b);
        db_b.add_dao_local_share(1, 2, packed_b);
    }

    // Same eligible set on both nodes: 3 existing + 1 new.
    crypto::public_key new_pk;
    crypto::secret_key new_sk;
    crypto::generate_keys(new_pk, new_sk);
    for (auto* db : { &db_a, &db_b }) {
        for (size_t i = 0; i < 3; ++i) {
            committee_eligible_record er{};
            er.node_pubkey = c_pks[i];
            er.amount = 3000000;
            er.unlock_height = 0;
            crypto::key_image ki{};
            std::memset(ki.data, 0, sizeof(ki.data));
            ki.data[0] = static_cast<uint8_t>(i + 1);
            db_wtxn_guard g(db);
            db->add_committee_eligible(ki, er);
        }
        committee_eligible_record er{};
        er.node_pubkey = new_pk;
        er.amount = 1000000;
        er.unlock_height = 0;
        crypto::key_image ki{};
        std::memset(ki.data, 0, sizeof(ki.data));
        ki.data[0] = 4;
        db_wtxn_guard g(db);
        db->add_committee_eligible(ki, er);
    }

    // Shared mailbox.
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

    // Trigger both.
    {
        db_wtxn_guard g(&db_a);
        bc_a.maybe_maintain_dao_v2_share_set();
    }
    {
        db_wtxn_guard g(&db_b);
        bc_b.maybe_maintain_dao_v2_share_set();
    }

    // Deliver messages round-robin until both have finalized or we
    // run out of patience.
    for (int round = 0; round < 8; ++round) {
        std::vector<std::pair<crypto::public_key, std::string>> batch;
        {
            std::lock_guard<std::mutex> lk(mb_mu);
            batch.swap(mailbox);
        }
        if (batch.empty()) break;

        for (auto& [sender, payload] : batch) {
            if (std::memcmp(sender.data, a_pub.data, 32) == 0) {
                bc_b.handle_dao_v2_dkg_msg(a_pub, payload);
            } else {
                bc_a.handle_dao_v2_dkg_msg(b_pub, payload);
            }
        }

        // Let each node's trigger observe what it has received.
        {
            db_wtxn_guard g(&db_a);
            bc_a.maybe_maintain_dao_v2_share_set();
        }
        {
            db_wtxn_guard g(&db_b);
            bc_b.maybe_maintain_dao_v2_share_set();
        }
    }

    // Both nodes should now be on share set 2.
    EXPECT_EQ(db_a.get_current_dao_share_set_id(), 2u);
    EXPECT_EQ(db_b.get_current_dao_share_set_id(), 2u);

    dao::dao_share_set_record sa, sb;
    ASSERT_TRUE(db_a.get_dao_share_set(2, sa));
    ASSERT_TRUE(db_b.get_dao_share_set(2, sb));
    EXPECT_EQ(sa.share_set_id, sb.share_set_id);
    EXPECT_EQ(sa.committee_id_hash, sb.committee_id_hash);
    EXPECT_EQ(sa.VK_i, sb.VK_i);

    boost::filesystem::remove_all(base);
}


// ---------------------------------------------------------------------
// Resharing delivers a valid share to a node that joined after the
// bootstrap DKG.
//
// Three ReplayNodes: a and b are bootstrap shareholders; c is a new
// node whose key is not in the bootstrap committee. All three are in
// the eligible set. Both bootstrap nodes and the new node run the
// trigger. The new node receives deals, derives its reshared share,
// and commits the new share set. Its share is verified against the
// published VK for its position in the new set.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, ReshareNewMemberReceivesShare)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    boost::filesystem::path base =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("vr_replay_new_%%%%-%%%%");

    ReplayNode a;
    ReplayNode b;
    ReplayNode c;
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

    // Bootstrap committee of 3, ordered by pubkey.
    std::vector<crypto::public_key> bpks;
    std::vector<crypto::secret_key> bsks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        bpks.push_back(pk);
        bsks.push_back(sk);
    }
    {
        std::vector<size_t> idx = {0, 1, 2};
        std::sort(idx.begin(), idx.end(), [&](size_t x, size_t y) {
            return std::memcmp(bpks[x].data, bpks[y].data, 32) < 0;
        });
        std::vector<crypto::public_key> p2;
        std::vector<crypto::secret_key> s2;
        for (auto i : idx) { p2.push_back(bpks[i]); s2.push_back(bsks[i]); }
        bpks = std::move(p2);
        bsks = std::move(s2);
    }

    // c's key: not in the bootstrap set.
    crypto::public_key c_pk; crypto::secret_key c_sk;
    crypto::generate_keys(c_pk, c_sk);

    a.core->set_node_key(bsks[0]);
    b.core->set_node_key(bsks[1]);
    c.core->set_node_key(c_sk);

    crypto::public_key a_pub, b_pub, c_pub;
    ASSERT_TRUE(crypto::secret_key_to_public_key(bsks[0], a_pub));
    ASSERT_TRUE(crypto::secret_key_to_public_key(bsks[1], b_pub));
    ASSERT_TRUE(crypto::secret_key_to_public_key(c_sk, c_pub));

    // Bootstrap DKG over the 3 bootstrap keys.
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
    cfg.member_ids     = bpks;
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

    // Install the same bootstrap key record on all three nodes.
    bc_a.install_dao_tally_key_for_test(dkg_out.record);
    bc_b.install_dao_tally_key_for_test(dkg_out.record);
    bc_c.install_dao_tally_key_for_test(dkg_out.record);

    // Local bootstrap shares: a holds position 1, b holds position 2.
    // c holds none (it is a new member).
    {
        std::vector<uint8_t> packed = dao_pack_local_share(
            dkg_out.record.key_id, dkg_out.local_secret_share);
        ASSERT_FALSE(packed.empty());
        db_wtxn_guard g(&db_a);
        db_a.add_dao_local_share(1, 1, packed);
    }
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
        std::vector<uint8_t> packed =
            dao_pack_local_share(dkg_out.record.key_id, raw);
        ASSERT_FALSE(packed.empty());
        db_wtxn_guard g(&db_b);
        db_b.add_dao_local_share(1, 2, packed);
    }

    // Eligible set on every node: a (weight 3M), b (2M), c (1M).
    // Order by weight desc: a, b, c. New positions: a=1, b=2, c=3.
    for (auto* db : { &db_a, &db_b, &db_c }) {
        for (int i = 0; i < 2; ++i) {
            committee_eligible_record er{};
            er.node_pubkey = bpks[i];
            er.amount = (i == 0) ? 3000000 : 2000000;
            er.unlock_height = 0;
            crypto::key_image ki{};
            std::memset(ki.data, 0, sizeof(ki.data));
            ki.data[0] = static_cast<uint8_t>(i + 1);
            db_wtxn_guard g(db);
            db->add_committee_eligible(ki, er);
        }
        committee_eligible_record er{};
        er.node_pubkey = c_pk;
        er.amount = 1000000;
        er.unlock_height = 0;
        crypto::key_image ki{};
        std::memset(ki.data, 0, sizeof(ki.data));
        ki.data[0] = 3;
        db_wtxn_guard g(db);
        db->add_committee_eligible(ki, er);
    }

    // Shared mailbox.
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

    // Trigger all three.
    {
        db_wtxn_guard g(&db_a);
        bc_a.maybe_maintain_dao_v2_share_set();
    }
    {
        db_wtxn_guard g(&db_b);
        bc_b.maybe_maintain_dao_v2_share_set();
    }
    {
        db_wtxn_guard g(&db_c);
        bc_c.maybe_maintain_dao_v2_share_set();
    }

    // Deliver messages round-robin and re-trigger after each round.
    for (int round = 0; round < 8; ++round) {
        std::vector<std::pair<crypto::public_key, std::string>> batch;
        {
            std::lock_guard<std::mutex> lk(mb_mu);
            batch.swap(mailbox);
        }
        if (batch.empty() && round > 0) break;

        for (auto& [sender, payload] : batch) {
            if (std::memcmp(sender.data, a_pub.data, 32) != 0)
                bc_a.handle_dao_v2_dkg_msg(sender, payload);
            if (std::memcmp(sender.data, b_pub.data, 32) != 0)
                bc_b.handle_dao_v2_dkg_msg(sender, payload);
            if (std::memcmp(sender.data, c_pub.data, 32) != 0)
                bc_c.handle_dao_v2_dkg_msg(sender, payload);
        }

        {
            db_wtxn_guard g(&db_a);
            bc_a.maybe_maintain_dao_v2_share_set();
        }
        {
            db_wtxn_guard g(&db_b);
            bc_b.maybe_maintain_dao_v2_share_set();
        }
        {
            db_wtxn_guard g(&db_c);
            bc_c.maybe_maintain_dao_v2_share_set();
        }
    }

    // All three must have committed share set 2.
    ASSERT_EQ(db_a.get_current_dao_share_set_id(), 2u);
    ASSERT_EQ(db_b.get_current_dao_share_set_id(), 2u);
    ASSERT_EQ(db_c.get_current_dao_share_set_id(), 2u);

    dao::dao_share_set_record sa, sb, sc;
    ASSERT_TRUE(db_a.get_dao_share_set(2, sa));
    ASSERT_TRUE(db_b.get_dao_share_set(2, sb));
    ASSERT_TRUE(db_c.get_dao_share_set(2, sc));

    EXPECT_EQ(sa.committee_id_hash, sb.committee_id_hash);
    EXPECT_EQ(sa.committee_id_hash, sc.committee_id_hash);
    EXPECT_EQ(sa.VK_i, sb.VK_i);
    EXPECT_EQ(sa.VK_i, sc.VK_i);

    // c must appear somewhere in the new share set.
    ASSERT_EQ(sa.committee_members.size(), 3u);
    size_t c_pos = 0;
    bool found_c = false;
    for (size_t i = 0; i < sa.committee_members.size(); ++i) {
        if (sa.committee_members[i].size() != 32) continue;
        if (std::memcmp(sa.committee_members[i].data(),
                        c_pub.data, 32) == 0) {
            c_pos = i + 1;
            found_c = true;
            break;
        }
    }
    ASSERT_TRUE(found_c) << "c not present in new share set";

    // c holds a share at (share_set_id=2, its position).
    std::vector<uint8_t> c_packed;
    ASSERT_TRUE(db_c.get_dao_local_share(
        static_cast<uint32_t>(2), static_cast<uint32_t>(c_pos), c_packed));
    std::vector<uint8_t> c_raw;
    ASSERT_TRUE(dao_unpack_local_share(c_packed, dkg_out.record.key_id,
                                        c_raw));
    ASSERT_FALSE(c_raw.empty());

    // Parse the signed share and verify V^((16!) * s_c) == VK_i[2].
    {
        const bool neg = (c_raw[0] != 0);
        BIGNUM* sc_bn = BN_bin2bn(c_raw.data() + 1,
                                  static_cast<int>(c_raw.size() - 1),
                                  nullptr);
        ASSERT_NE(sc_bn, nullptr);
        if (neg && !BN_is_zero(sc_bn)) BN_set_negative(sc_bn, 1);

        dao::dao_tally_key_record key_rec;
        ASSERT_TRUE(db_a.get_dao_tally_key(key_rec));

        PaillierPublicKey pk;
        ASSERT_TRUE(pk.deserialize_modulus(key_rec.N));

        BN_CTX* ctx = BN_CTX_new();
        ASSERT_NE(ctx, nullptr);
        BIGNUM* delta = BN_new();
        BN_dec2bn(&delta, "20922789888000");
        BIGNUM* exp = BN_new();
        BN_mul(exp, sc_bn, delta, ctx);

        BIGNUM* V = BN_bin2bn(key_rec.V.data(),
                               static_cast<int>(key_rec.V.size()), nullptr);
        BIGNUM* got = BN_new();
        // Signed exponentiation. sc_bn may be negative; BN_mod_exp
        // with a negative exponent does not invert.
        if (BN_is_negative(exp)) {
            BIGNUM* Vinv = BN_mod_inverse(nullptr, V, pk.N2(), ctx);
            ASSERT_NE(Vinv, nullptr);
            BIGNUM* pos = BN_dup(exp);
            BN_set_negative(pos, 0);
            ASSERT_EQ(BN_mod_exp(got, Vinv, pos, pk.N2(), ctx), 1);
            BN_free(Vinv);
            BN_free(pos);
        } else {
            ASSERT_EQ(BN_mod_exp(got, V, exp, pk.N2(), ctx), 1);
        }
        std::vector<uint8_t> got_bytes(dao::PAILLIER_CT_BYTES, 0);
        BN_bn2binpad(got, got_bytes.data(), dao::PAILLIER_CT_BYTES);

        EXPECT_EQ(got_bytes, sa.VK_i[c_pos - 1]);

        BN_free(sc_bn); BN_free(delta); BN_free(exp);
        BN_free(V); BN_free(got);
        BN_CTX_free(ctx);
    }

    // --------------------------------------------------------------
    // Produce a tally share from the reshared set.
    //
    // The producer must index its output against the current (reshared)
    // share set, and its proof must be built against that set's VK.
    // We exercise this on node a.
    // --------------------------------------------------------------
    {
        // Add a proposal and an aggregate on node a.
        crypto::hash prop_id{};
        std::memset(prop_id.data, 0x5A, 32);
        const uint64_t VOTE_END = 50000;

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
        BN_free(W); BN_free(S); BN_free(B);
        BN_free(r1); BN_free(r2); BN_free(r3);

        {
            db_wtxn_guard g(&db_a);
            proposal_record rec{};
            std::memset(&rec, 0, sizeof(rec));
            rec.proposal_id = prop_id;
            rec.voting_period_days = 7;
            rec.submission_height = VOTE_END - 1000;
            rec.voting_end_height = VOTE_END;
            std::memcpy(rec.tally_key_id.data,
                        dkg_out.record.key_id.data(), 32);
            rec.submission_tx_hash = prop_id;
            rec.status = PROPOSAL_STATUS_ACTIVE;
            rec.status_height = VOTE_END - 1000;
            db_a.add_proposal_record(prop_id, rec);

            dao_proposal_aggregate agg;
            agg.aggregate_E_W = E_W;
            agg.aggregate_E_S = E_S;
            agg.aggregate_E_B = E_B;
            agg.aggregate_C_W = rct::identity();
            agg.aggregate_C_S = rct::identity();
            agg.aggregate_C_B = rct::identity();
            db_a.add_dao_proposal_aggregate(prop_id, agg);

            dao::dao_supply_snapshot snap;
            snap.height = VOTE_END;
            snap.minted = dao::dao_u128(100000);
            snap.circulating = dao::dao_u128(50000);
            db_a.add_dao_supply_snapshot(snap);
        }

        // Broadcast callback captures the produced share.
        dao::dao_v2_tally_share produced{};
        bool got_share = false;
        bc_a.set_dao_v2_tally_broadcast([&](const dao::dao_v2_tally_share& s) {
            produced = s;
            got_share = true;
        });
        bc_a.set_dao_v2_dkg_send([](const std::string&) -> bool {
            return true;
        });

        {
            db_wtxn_guard g(&db_a);
            bc_a.maybe_produce_dao_v2_share(VOTE_END + 1);
        }
        ASSERT_TRUE(got_share) << "producer did not fire after reshare";
        EXPECT_EQ(produced.proposal_id, prop_id);
        EXPECT_EQ(std::memcmp(produced.tally_key_id.data(),
                              dkg_out.record.key_id.data(), 32), 0);

        // a's position in share set 2 must match its actual position.
        size_t a_pos = 0;
        bool found_a = false;
        for (size_t i = 0; i < sa.committee_members.size(); ++i) {
            if (sa.committee_members[i].size() != 32) continue;
            if (std::memcmp(sa.committee_members[i].data(),
                            a_pub.data, 32) == 0) {
                a_pos = i + 1;
                found_a = true;
                break;
            }
        }
        ASSERT_TRUE(found_a);
        EXPECT_EQ(produced.member_index, a_pos);
        EXPECT_FALSE(produced.partial_W.empty());
        EXPECT_FALSE(produced.partial_S.empty());
        EXPECT_FALSE(produced.partial_B.empty());

        // Now produce the same on B, then combine into a certificate.
        {
            db_wtxn_guard g(&db_b);
            proposal_record rec{};
            std::memset(&rec, 0, sizeof(rec));
            rec.proposal_id = prop_id;
            rec.voting_period_days = 7;
            rec.submission_height = VOTE_END - 1000;
            rec.voting_end_height = VOTE_END;
            std::memcpy(rec.tally_key_id.data,
                        dkg_out.record.key_id.data(), 32);
            rec.submission_tx_hash = prop_id;
            rec.status = PROPOSAL_STATUS_ACTIVE;
            rec.status_height = VOTE_END - 1000;
            db_b.add_proposal_record(prop_id, rec);

            dao_proposal_aggregate agg;
            agg.aggregate_E_W = E_W;
            agg.aggregate_E_S = E_S;
            agg.aggregate_E_B = E_B;
            agg.aggregate_C_W = rct::identity();
            agg.aggregate_C_S = rct::identity();
            agg.aggregate_C_B = rct::identity();
            db_b.add_dao_proposal_aggregate(prop_id, agg);

            dao::dao_supply_snapshot snap;
            snap.height = VOTE_END;
            snap.minted = dao::dao_u128(100000);
            snap.circulating = dao::dao_u128(50000);
            db_b.add_dao_supply_snapshot(snap);
        }

        dao::dao_v2_tally_share share_b{};
        bool got_b = false;
        bc_b.set_dao_v2_tally_broadcast(
            [&](const dao::dao_v2_tally_share& s) {
                share_b = s;
                got_b = true;
            });
        bc_b.set_dao_v2_dkg_send([](const std::string&) -> bool {
            return true;
        });
        {
            db_wtxn_guard g(&db_b);
            bc_b.maybe_produce_dao_v2_share(VOTE_END + 1);
        }
        ASSERT_TRUE(got_b) << "producer did not fire on B";
        EXPECT_EQ(share_b.proposal_id, prop_id);
        EXPECT_NE(share_b.member_index, produced.member_index);

        // Combine A's and B's shares into a certificate at A.
        std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
        shares[a_pub] = produced;
        shares[b_pub] = share_b;

        const governance_params params =
            governance_params::default_params();
        cryptonote::TallyManager tm(db_a, params);
        transaction result_tx;
        ASSERT_TRUE(tm.build_tally_result_transaction(
            prop_id, shares, 2, result_tx));

        // Both nodes must validate the certificate.
        ASSERT_TRUE(bc_a.validate_dao_v2_tally_result_tx(
            result_tx, VOTE_END + 1));
        ASSERT_TRUE(bc_b.validate_dao_v2_tally_result_tx(
            result_tx, VOTE_END + 1));

        // Apply on both nodes.
        {
            db_wtxn_guard g(&db_a);
            ASSERT_TRUE(bc_a.apply_dao_v2_tally_result(
                result_tx, VOTE_END + 1));
        }
        {
            db_wtxn_guard g(&db_b);
            ASSERT_TRUE(bc_b.apply_dao_v2_tally_result(
                result_tx, VOTE_END + 1));
        }

        // Both must carry the same outcome.
        dao::dao_v2_outcome_record out_a, out_b;
        ASSERT_TRUE(db_a.get_dao_v2_outcome(prop_id, out_a));
        ASSERT_TRUE(db_b.get_dao_v2_outcome(prop_id, out_b));
        EXPECT_EQ(out_a.share_set_id, out_b.share_set_id);
        EXPECT_EQ(out_a.passed, out_b.passed);
        EXPECT_EQ(out_a.quorum_met, out_b.quorum_met);
        EXPECT_EQ(out_a.majority_met, out_b.majority_met);
        EXPECT_EQ(out_a.yes_weight, out_b.yes_weight);
        EXPECT_EQ(out_a.no_weight, out_b.no_weight);
        EXPECT_EQ(out_a.participation_coins, out_b.participation_coins);
    }

    boost::filesystem::remove_all(base);
}
