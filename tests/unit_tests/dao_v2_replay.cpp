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
#include "governance/dao_tally_share.h"
#include "governance/dao_tally.h"
#include "governance/dao_supply.h"
#include "v2_vote_builder.h"
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
            return false;
        }

        try {
            const block prev = db.get_block_from_height(height - 1);
            last_ts = prev.timestamp;
        } catch (const std::exception& e) {
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
        return false;
    }

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
        return false;
    }

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
// real derived spend secret, real CL ciphertexts, real CLSAGs, real
// transcript, real block-apply through GovernanceManager.
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

    // CL test key. No DKG needed: the fixture installs a ready CL key
    // record directly so that vote verification finds the context.
    v2test::CLTestKey cl_key;
    if (!v2test::make_cl_test_key(cl_key, 0x5A5AUL)) return false;

    // A node key is still required by the block-apply path.
    crypto::public_key node_pk; crypto::secret_key node_sk;
    crypto::generate_keys(node_pk, node_sk);
    fx.node->core->set_node_key(node_sk);

    {
        dao::dao_tally_key_record rec{};
        rec.version        = 1;
        rec.committee_size = 3;
        rec.threshold      = 2;
        rec.t              = 1;
        rec.committee_id_hash.assign(32, 0);
        rec.committee_members.assign(3, std::vector<uint8_t>(32, 0));
        rec.cl_modulus = cl_key.context_wire;
        rec.activation_height = 1;
        rec.dkg_transcript_hash.assign(32, 0);
        rec.key_id.assign(32, 0);
        std::memset(rec.key_id.data(), 0x5A, 32);
        fx.key_rec = rec;

        dao::dao_share_set_record ss{};
        ss.version           = 3;
        ss.share_set_id      = static_cast<uint64_t>(
                                   dao::share_set_id_for_key_id(rec.key_id));
        ss.height            = rec.activation_height;
        ss.threshold         = rec.threshold;
        ss.key_id            = rec.key_id;
        ss.committee_members = rec.committee_members;
        ss.committee_id_hash.assign(32, 0);
        ss.cl_gammas_serialized.assign(8, 0);
        ss.qualified_ids     = {0, 1, 2};

        bc_a.install_dao_tally_key_for_proposal_for_test(rec, ss, {});
    }

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
        uint64_t           amount_output_index;
        crypto::public_key pubkey;
        rct::key           commitment;
        uint64_t           height;
        uint64_t           amount;
        crypto::secret_key output_secret;
    };
    std::vector<OwnedOutput> owned;
    {
        const uint64_t amount_zero_output_count = db_a.get_num_outputs(0);
        for (uint64_t amount_index = 0;
             amount_index < amount_zero_output_count; ++amount_index) {
            output_data_t od;
            try { od = db_a.get_output_key(0, amount_index, true); }
            catch (...) { continue; }
            tx_out_index toi;
            try { toi = db_a.get_output_tx_and_index(0, amount_index); }
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
            oo.amount_output_index = amount_index;
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
                  return x.amount_output_index < y.amount_output_index; });

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
        // V2 key offsets are indices in the RingCT amount=0 bucket.
        rm.global_index = owned[i].amount_output_index;
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
            cl_key.context_wire, /*direction=YES*/ 0,
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
// Real coinbase outputs, real derived spend secret, real CL
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
    // The normal miner template must select the zero-fee, zero-input V2
    // vote from the pool. The manual block below is a consensus replay test
    // and does not exercise tx-pool template selection.
    {
        block mining_template{};
        difficulty_type template_difficulty = 0;
        uint64_t template_height = 0;
        uint64_t template_reward = 0;
        uint64_t template_seed_height = 0;
        crypto::hash template_seed_hash = crypto::null_hash;
        const blobdata extra_nonce;
        ASSERT_TRUE(fx.node->core->get_block_template(
            mining_template,
            fx.miner_acc.get_keys().m_account_address,
            template_difficulty, template_height, template_reward,
            extra_nonce, template_seed_height, template_seed_hash));
        EXPECT_EQ(template_height, fx.chain_height);
        
        EXPECT_NE(std::find(mining_template.tx_hashes.begin(),
                            mining_template.tx_hashes.end(),
                            get_transaction_hash(fx.vote_tx)),
                  mining_template.tx_hashes.end());

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
// VoteProofVerifier step 21 rejects a non-canonical CL ciphertext,
// so a single bit flip in E_W is sufficient.
// ---------------------------------------------------------------------
TEST(DaoV2Replay, InvalidV2VoteProofRejectedByMempool)
{
    using namespace cryptonote;

    V2VoteFixture fx;
    ASSERT_TRUE(build_v2_vote_fixture(fx, "votebad"));

    // Tamper one byte of E_W.
    vote_proof_v2 bad = fx.proof;
    bad.E_W[0] ^= 0xFF;

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
        fx.tally_key_id, fx.key_rec.cl_modulus, /*direction=YES*/ 0,
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

        // Override execution_delay to 0 so the delay gate is neutral.
        // This test proves duplicate-in-block rejection, not delay
        // rejection; both tx must reach the duplicate check.
        parameter_record dp{};
        dp.parameter         = governance_parameter::execution_delay;
        dp.value             = 0;
        dp.activation_height = 0;
        dp.proposal_height   = 0;
        dp.proposal_id       = crypto::null_hash;
        db.add_parameter_record(dp);
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
