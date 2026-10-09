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
// and the active epoch from chain state alone. It then replays the
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
    block& out)
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
// expectation is "key record missing for epoch 1" — the DKG public key
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
    cfg.epoch          = 1;
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
    EXPECT_FALSE(adb.get_dao_tally_key(1, key_rec_a));
    EXPECT_FALSE(bdb.get_dao_tally_key(1, key_rec_b));

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

    // Both nodes now reconstruct the key record and the active epoch
    // by replaying the activation block alone.
    ASSERT_TRUE(adb.get_dao_tally_key(1, key_rec_a));
    ASSERT_TRUE(bdb.get_dao_tally_key(1, key_rec_b));
    EXPECT_EQ(key_rec_a.key_id, key_rec_b.key_id);
    EXPECT_EQ(key_rec_a.committee_size, key_rec_b.committee_size);
    EXPECT_EQ(key_rec_a.threshold, key_rec_b.threshold);
    {
        uint32_t e_a = 0, e_b = 0;
        EXPECT_TRUE(adb.get_current_dao_tally_key_epoch(e_a));
        EXPECT_TRUE(bdb.get_current_dao_tally_key_epoch(e_b));
        EXPECT_EQ(e_a, 1u);
        EXPECT_EQ(e_b, 1u);
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
        rec.tally_key_epoch = 1;
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
    second_share.tally_key_epoch = 1;
    second_share.share_epoch = 1;
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
