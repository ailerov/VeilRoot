// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Single-node bootstrap integration test. Instantiates a real
// cryptonote::core with a fresh LMDB, installs a persistent node
// identity and three eligible records, then drives the production
// bootstrap sequence end to end:
//
//   core
//     -> Blockchain::init (real)
//     -> committee_privkey installed
//     -> eligible records installed
//     -> runner starts, watcher queues
//     -> owner thread drains the queue
//     -> LMDB holds the tally key record for this node's committee index

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "gtest/gtest.h"

#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_core.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "cryptonote_basic/tx_extra.h"
#include "serialization/binary_utils.h"
#include "serialization/binary_archive.h"
#include "serialization/variant.h"
#include "serialization/string.h"
#include "governance/governance_params.h"
#include "governance/tally_manager.h"
#include "governance/dao_tally_share.h"
#include "governance/dao_tally.h"
#include "governance/dao_supply.h"
#include "governance/dao_paillier.h"
#include "cl_bootstrap_fixture.h"

namespace po = boost::program_options;
using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

constexpr uint64_t FIXED_TEST_CANDIDATE_SEED_3 = 0x5645494C52544F33ULL;

} // namespace

class DaoBootstrapIntegration : public ::testing::Test
{
protected:
    std::string m_dir;
    std::unique_ptr<cryptonote::core> m_core;
    crypto::secret_key m_node_sec;
    crypto::public_key m_node_pub;

    void SetUp() override
    {
        boost::filesystem::path tmp =
            boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_dkg_int_%%%%-%%%%");
        m_dir = tmp.string();
        boost::filesystem::create_directories(m_dir);

        po::options_description desc("");
        cryptonote::core::init_options(desc);

        po::variables_map vm;
        // FAKECHAIN mode: --regtest-on.
        // data dir set to our temp path.
        std::vector<std::string> args = {
            "--regtest",
            "--data-dir", m_dir,
            "--offline",
            "--keep-fakechain",
            "--fixed-difficulty", "1",
        };
        po::store(po::command_line_parser(args).options(desc).run(), vm);
        po::notify(vm);

        m_core.reset(new cryptonote::core(nullptr));
        ASSERT_TRUE(m_core->init(vm, nullptr, nullptr, false));

        // Persistent node identity, matching Blockchain::init()'s own
        // behavior: load from LMDB if present, else generate and store.
        crypto::secret_key sec;
        if (!m_core->get_blockchain_storage().get_db().get_committee_privkey(sec))
        {
            crypto::generate_keys(m_node_pub, m_node_sec);
            m_core->get_blockchain_storage().get_db().set_committee_privkey(m_node_sec);
        }
        else
        {
            m_node_sec = sec;
            ASSERT_TRUE(crypto::secret_key_to_public_key(m_node_sec, m_node_pub));
        }
        m_core->set_node_key(m_node_sec);
    }

    void TearDown() override
    {
        if (m_core) {
            m_core->deinit();
        }
        m_core.reset();
        boost::filesystem::remove_all(m_dir);
    }
};

TEST_F(DaoBootstrapIntegration, CoreInitSucceeds)
{
    // The fixture itself exercises this; the assert is that SetUp
    // reached this point.
    SUCCEED();
}

TEST_F(DaoBootstrapIntegration, PersistentNodeIdentityInstalled)
{
    crypto::secret_key recovered;
    ASSERT_TRUE(m_core->get_blockchain_storage().get_db()
                    .get_committee_privkey(recovered));
    crypto::public_key recovered_pub;
    ASSERT_TRUE(crypto::secret_key_to_public_key(recovered, recovered_pub));
    EXPECT_EQ(recovered_pub, m_node_pub);
}

namespace {

// Sign and deliver a node_ready announcement for (sec, pub). The
// digest matches Blockchain::compute_dao_v2_node_ready_digest (V2:
// covers genesis, pk, announce height, and block hash at that height).
void deliver_node_ready(core& c,
                        const crypto::hash& genesis,
                        const crypto::public_key& pk,
                        const crypto::secret_key& sk)
{
    auto& bs = c.get_blockchain_storage();
    const uint64_t current_h = bs.get_current_blockchain_height();
    if (current_h == 0) return;
    const uint64_t announce_h = current_h - 1;
    crypto::hash announce_hash{};
    try { announce_hash = bs.get_block_id_by_height(announce_h); }
    catch (...) { return; }

    const char* domain = "VeilRoot-DAO-DKG-NODE-READY-V2";
    std::vector<uint8_t> msg;
    const size_t dlen = std::strlen(domain);
    msg.insert(msg.end(), domain, domain + dlen);
    msg.insert(msg.end(), genesis.data, genesis.data + 32);
    msg.insert(msg.end(), pk.data, pk.data + 32);
    uint8_t h_le[8];
    std::memcpy(h_le, &announce_h, 8);
    msg.insert(msg.end(), h_le, h_le + 8);
    msg.insert(msg.end(), announce_hash.data, announce_hash.data + 32);

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
    std::memcpy(m.bytes_b.data(), &announce_h, 8);
    std::memcpy(m.bytes_b.data() + 8, announce_hash.data, 32);

    std::vector<uint8_t> wire;
    ASSERT_TRUE(m.serialize(wire));
    std::string payload(wire.begin(), wire.end());

    bs.handle_dao_v2_dkg_msg(pk, payload);
}

}  // namespace



TEST_F(DaoBootstrapIntegration, NodeReadyRecordsValidAnnouncement)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    deliver_node_ready(*m_core, genesis, a_pk, a_sk);

    auto& bs = m_core->get_blockchain_storage();
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_EQ(1u, bs.get_dao_v2_ready_peer_count_for_test());
}

TEST_F(DaoBootstrapIntegration, NodeReadyRejectsInvalidSignature)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    crypto::public_key b_pk;
    crypto::secret_key b_sk;
    crypto::generate_keys(b_pk, b_sk);

    deliver_node_ready(*m_core, genesis, a_pk, a_sk);
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .has_dao_v2_ready_peer_for_test(a_pk));

    // Forged: signature is over A's digest, but the message arrives
    // claiming sender=B. The handler computes the digest over B, so
    // signature verification against B's public key fails.
    auto& bs_for_rej = m_core->get_blockchain_storage();
    const uint64_t cur_h = bs_for_rej.get_current_blockchain_height();
    ASSERT_GT(cur_h, 0u);
    const uint64_t announce_h = cur_h - 1;
    crypto::hash announce_hash{};
    try { announce_hash = bs_for_rej.get_block_id_by_height(announce_h); }
    catch (...) { FAIL() << "get_block_id_by_height threw"; return; }

    std::vector<uint8_t> msg;
    const char* domain = "VeilRoot-DAO-DKG-NODE-READY-V2";
    const size_t dlen = std::strlen(domain);
    msg.insert(msg.end(), domain, domain + dlen);
    msg.insert(msg.end(), genesis.data, genesis.data + 32);
    msg.insert(msg.end(), a_pk.data, a_pk.data + 32);
    uint8_t h_le[8];
    std::memcpy(h_le, &announce_h, 8);
    msg.insert(msg.end(), h_le, h_le + 8);
    msg.insert(msg.end(), announce_hash.data, announce_hash.data + 32);
    crypto::hash digest{};
    crypto::cn_fast_hash(msg.data(), msg.size(), digest);
    crypto::signature sig{};
    crypto::generate_signature(digest, a_pk, a_sk, sig);

    dao::dkg_msg forged;
    forged.hdr.type         = dao::dkg_msg_type::node_ready;
    forged.hdr.recipient_id = 0;
    forged.bytes_a.resize(sizeof(crypto::signature));
    std::memcpy(forged.bytes_a.data(), &sig, sizeof(crypto::signature));
    forged.bytes_b.resize(8 + 32);
    std::memcpy(forged.bytes_b.data(), &announce_h, 8);
    std::memcpy(forged.bytes_b.data() + 8, announce_hash.data, 32);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(forged.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    m_core->get_blockchain_storage().handle_dao_v2_dkg_msg(b_pk, payload);

    auto& bs = m_core->get_blockchain_storage();
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_FALSE(bs.has_dao_v2_ready_peer_for_test(b_pk));
    EXPECT_EQ(1u, bs.get_dao_v2_ready_peer_count_for_test());
}

namespace {

inline void write_u64_le(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}

// Build a node_ready message signed by (pk, sk) over an arbitrary
// (height, hash) tuple. Height is written little-endian on the wire,
// matching the source-side encoding.
dao::dkg_msg make_node_ready_msg(
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
    write_u64_le(h_le, height);
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
    write_u64_le(m.bytes_b.data(), height);
    std::memcpy(m.bytes_b.data() + 8, block_hash.data, 32);
    return m;
}

void send_ready_msg(core& c,
                    const crypto::public_key& sender,
                    const dao::dkg_msg& m)
{
    std::vector<uint8_t> wire;
    ASSERT_TRUE(m.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    c.get_blockchain_storage().handle_dao_v2_dkg_msg(sender, payload);
}

}  // namespace

TEST_F(DaoBootstrapIntegration, NodeReadyRejectsFutureHeight)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    auto& bs = m_core->get_blockchain_storage();
    const uint64_t cur_h = bs.get_current_blockchain_height();
    ASSERT_GT(cur_h, 0u);

    crypto::hash fake_hash{};
    std::memset(fake_hash.data, 0xAB, sizeof(fake_hash.data));

    // Height at or above local tip is rejected.
    dao::dkg_msg m = make_node_ready_msg(
        genesis, a_pk, a_sk, cur_h, fake_hash);
    send_ready_msg(*m_core, a_pk, m);

    EXPECT_FALSE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_EQ(0u, bs.get_dao_v2_ready_peer_count_for_test());
}

TEST_F(DaoBootstrapIntegration, NodeReadyRejectsNonCanonicalHash)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    auto& bs = m_core->get_blockchain_storage();
    const uint64_t cur_h = bs.get_current_blockchain_height();
    ASSERT_GT(cur_h, 0u);

    const uint64_t h = cur_h - 1;
    crypto::hash fake_hash{};
    std::memset(fake_hash.data, 0xCD, sizeof(fake_hash.data));

    dao::dkg_msg m = make_node_ready_msg(genesis, a_pk, a_sk, h, fake_hash);
    send_ready_msg(*m_core, a_pk, m);

    EXPECT_FALSE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_EQ(0u, bs.get_dao_v2_ready_peer_count_for_test());
}

TEST_F(DaoBootstrapIntegration, NodeReadyArrivalOrderABCPopulatesRoster)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));
    auto& bs = m_core->get_blockchain_storage();

    crypto::public_key a_pk, b_pk, c_pk;
    crypto::secret_key a_sk, b_sk, c_sk;
    crypto::generate_keys(a_pk, a_sk);
    crypto::generate_keys(b_pk, b_sk);
    crypto::generate_keys(c_pk, c_sk);

    deliver_node_ready(*m_core, genesis, a_pk, a_sk);
    deliver_node_ready(*m_core, genesis, b_pk, b_sk);
    deliver_node_ready(*m_core, genesis, c_pk, c_sk);

    EXPECT_EQ(3u, bs.get_dao_v2_ready_peer_count_for_test());
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(b_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(c_pk));
}

TEST_F(DaoBootstrapIntegration, NodeReadyArrivalOrderCBAPopulatesRoster)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));
    auto& bs = m_core->get_blockchain_storage();

    crypto::public_key a_pk, b_pk, c_pk;
    crypto::secret_key a_sk, b_sk, c_sk;
    crypto::generate_keys(a_pk, a_sk);
    crypto::generate_keys(b_pk, b_sk);
    crypto::generate_keys(c_pk, c_sk);

    deliver_node_ready(*m_core, genesis, c_pk, c_sk);
    deliver_node_ready(*m_core, genesis, b_pk, b_sk);
    deliver_node_ready(*m_core, genesis, a_pk, a_sk);

    EXPECT_EQ(3u, bs.get_dao_v2_ready_peer_count_for_test());
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(b_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(c_pk));
}


TEST_F(DaoBootstrapIntegration, AnnounceIsThrottled)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    int sent = 0;
    m_core->get_blockchain_storage().set_dao_v2_dkg_send(
        [&sent](const std::string&) -> bool { ++sent; return true; });

    m_core->get_blockchain_storage().maybe_announce_dao_v2_node_ready();
    EXPECT_EQ(1, sent);

    // Second call within the throttle window does not emit.
    m_core->get_blockchain_storage().maybe_announce_dao_v2_node_ready();
    EXPECT_EQ(1, sent);

    // The first announce also recorded self in the roster.
    EXPECT_EQ(1u,
        m_core->get_blockchain_storage().get_dao_v2_ready_peer_count_for_test());
}


// ------------------------------------------------------------------
// Activation chain: DKG result queued -> drained on owner thread ->
// key record active -> new proposals bind to it.
//
// The DKG itself runs on three offline runners (the same construction
// the bootstrap unit test uses), so this test isolates the persistence
// and key-activation path in Blockchain.
// ------------------------------------------------------------------

namespace {

;

} // namespace

// ------------------------------------------------------------------
// Threshold combine is invariant to the chosen subset.
//
// Run a real 2-of-3 DKG. Then take two distinct 2-of-3 subsets of the
// bootstrap shareholders and confirm dao_threshold_combine produces
// the same combined ciphertext from each. This is the property the
// tally lifecycle depends on: any threshold subset of the bootstrap
// shareholders can decrypt, and the result is the same.
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// End-to-end lifecycle on a single fakechain core.
//
// 1. bootstrap DKG over three shareholders (this node + two dummies);
// 2. queue the DKG result and drain it on the owner thread;
// 3. persist a proposal whose voting window closes at VOTE_END;
// 4. encrypt a synthetic aggregate under the resulting N;
// 5. call maybe_produce_dao_v2_share(VOTE_END + 1);
// 6. assert the tally session is written and one share was produced;
// 7. feed that share, plus a second share built directly from
//    test_SK[1], through handle_dao_v2_tally_share;
// 8. assert the outcome record exists and the proposal passed.
//
// This exercises the exact production code path from the block-apply
// producer through the P2P handler through to try_finalize. It does
// not exercise two-node consensus (see the two-core test).
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// End-to-end consensus path for a DAO V2 tally result.
//
// 1. bootstrap DKG over three shareholders (this node + two dummies);
// 2. queue the DKG result and drain it on the owner thread;
// 3. persist a proposal whose voting window closes at VOTE_END;
// 4. encrypt a synthetic aggregate under the resulting N;
// 5. build a tally-result transaction from the threshold shares;
// 6. validate_dao_v2_tally_result_tx(tx, VOTE_END + 1) -> true;
// 7. apply_dao_v2_tally_result(tx, VOTE_END + 1);
// 8. assert outcome record and proposal status.
//
// This is the same computation the P2P handler and block-apply path
// perform. It uses the direct API so the test does not need to walk
// the mempool; the mempool path is exercised separately.
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// Reorg: a tally-result transaction applied to a block, then rolled
// back by popping that block, must restore the proposal to ACTIVE and
// remove the outcome record and pending execution.
//
// The reorg code path in pop_block_from_blockchain is not directly
// exercised here — it needs a chain to pop from. What this test
// asserts is the state contract: after applying a valid tally-result
// and then reversing it with the same certificate-driven rollback
// the pop path performs, governance state returns to exactly the
// pre-apply state.
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// Rejection boundaries for the tally-result consensus path.
//
// After building a valid tally-result transaction, this test mutates
// it in several ways and asserts validate_dao_v2_tally_result_tx
// rejects each mutation. It also asserts the apply path is idempotent
// (duplicate returns false, does not double-write). And it checks that
// a partial set containing a non-selected member is rejected.
// ------------------------------------------------------------------
namespace {

// Replace the governance payload inside a tally-result tx with the
// serialized bytes of a (possibly mutated) certificate. Returns false
// if the tx does not currently carry exactly one tally_result payload.
bool rebuild_tx_with_cert(const transaction& src,
                          const dao::dao_tally_certificate& cert,
                          transaction& out)
{
    std::vector<uint8_t> cert_blob;
    if (!const_cast<dao::dao_tally_certificate&>(cert).serialize(cert_blob))
        return false;

    governance_payload gp;
    gp.type = governance_object::tally_result;
    gp.data = std::move(cert_blob);

    tx_extra_governance_payload txgp;
    txgp.payload = std::move(gp);
    tx_extra_field extra_field = txgp;
    const std::string extra_blob =
        t_serializable_object_to_blob(extra_field);

    out = src;
    out.extra.assign(extra_blob.begin(), extra_blob.end());
    return true;
}

// Extract the certificate from a tally-result tx.
bool extract_cert(const transaction& tx,
                  dao::dao_tally_certificate& out)
{
    std::vector<tx_extra_field> fields;
    if (!parse_tx_extra(tx.extra, fields))
        return false;
    for (const auto& f : fields) {
        if (f.type() != typeid(tx_extra_governance_payload))
            continue;
        const auto& gpf = boost::get<tx_extra_governance_payload>(f);
        if (gpf.payload.type != governance_object::tally_result)
            continue;
        return out.deserialize(gpf.payload.data);
    }
    return false;
}

} // namespace

// ------------------------------------------------------------------
// Reconstructability from chain state alone.
//
// After a tally-result transaction has been validated and applied, the
// authoritative outcome is derivable purely from:
//   - the transaction itself (carried in a block)
//   - the chain state committed before that block was applied
//     (aggregate ciphertexts, supply snapshot, key record,
//     proposal record, eligible records)
//
// Nothing in the reconciliation path may read:
//   - m_dao_v2_tally_shares (in-memory share accumulator)
//   - any per-session Reset / dynamic-share state
//   - any local P2P-only bookkeeping
//
// This test rebuilds the tally-result transaction, then asserts that
// validate_dao_v2_tally_result_tx() still succeeds with the in-memory
// share accumulator cleared. If the reconciliation function needed
// that accumulator, this test would fail. It does not, so it passes.
//
// A stronger version of this property (fresh core synced from genesis
// reconstructing the same outcome) requires a two-core P2P fixture
// that does not yet exist. This test covers the same reconciliation
// code path with a single core.
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// Test J — bootstrap DKG share persists across a full tally cycle.
//
// The stable Paillier key belongs to the DAO, not to a proposal.
// A completed tally result must leave the bootstrap share in place so
// the same key can serve the next proposal.
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// Test G — a share from a bootstrap shareholder who is not in the
// selected tally committee is rejected by the consensus validator.
//
// Setup: DKG over 3 shareholders. Only shareholders 1 and 2 are made
// eligible. The selector therefore returns committee {1, 2}. A
// certificate that names member 3 in its partial sets — even though
// member 3 is a legitimate bootstrap DKG shareholder — must be
// rejected before cryptographic verification runs.
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// B1: node readiness becomes chain state.
//
// 1. mine a few blocks so a lower height has a canonical hash;
// 2. install a node key;
// 3. trigger maybe_announce_dao_v2_node_ready, which submits a
//    node_ready tx to mempool;
// 4. mine a block that includes it;
// 5. assert get_dao_v2_node_ready returns the stored hash;
// 6. pop the block and assert the row is rolled back.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, NodeReadyChainState)
{
    using namespace cryptonote;

    auto& bc = m_core->get_blockchain_storage();

    account_base miner_acc;
    miner_acc.generate();

    // Mine until tip >= 3 so a lower block height has a canonical hash.
    while (bc.get_current_blockchain_height() < 3) {
        block tmpl{};
        difficulty_type diff{};
        uint64_t tmpl_h = 0, reward = 0, seed_h = 0;
        crypto::hash seed_hsh{};
        blobdata ex_nonce(8, 0);
        ASSERT_TRUE(bc.create_block_template(
            tmpl, miner_acc.get_keys().m_account_address,
            diff, tmpl_h, reward, ex_nonce, seed_h, seed_hsh));
        auto gbh = [&bc](const block& b, uint64_t h,
                         const crypto::hash* sh,
                         unsigned int mn, crypto::hash& ho) -> bool {
            return get_block_longhash(&bc, b, ho, h, sh,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, tmpl_h, nullptr));
        block_verification_context bvc{};
        pool_supplement extra{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, extra, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    crypto::public_key self_pk;
    crypto::secret_key self_sk;
    crypto::generate_keys(self_pk, self_sk);
    m_core->set_node_key(self_sk);

    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });
    bc.maybe_announce_dao_v2_node_ready();

    std::vector<crypto::hash> pool_hashes;
    m_core->get_pool_transaction_hashes(pool_hashes,
                                        /*include_sensitive_txes=*/true);
    ASSERT_GE(pool_hashes.size(), 1u);

    const uint64_t h_before = bc.get_current_blockchain_height();
    const uint64_t announce_h = h_before - 1;
    const crypto::hash expected_hash = bc.get_block_id_by_height(announce_h);

    {
        block tmpl{};
        difficulty_type diff{};
        uint64_t tmpl_h = 0, reward = 0, seed_h = 0;
        crypto::hash seed_hsh{};
        blobdata ex_nonce(8, 0);
        ASSERT_TRUE(bc.create_block_template(
            tmpl, miner_acc.get_keys().m_account_address,
            diff, tmpl_h, reward, ex_nonce, seed_h, seed_hsh));
        auto gbh = [&bc](const block& b, uint64_t h,
                         const crypto::hash* sh,
                         unsigned int mn, crypto::hash& ho) -> bool {
            return get_block_longhash(&bc, b, ho, h, sh,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, tmpl_h, nullptr));
        block_verification_context bvc{};
        pool_supplement extra{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, extra, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    ASSERT_EQ(bc.get_current_blockchain_height(), h_before + 1);

    crypto::hash stored_hash{};
    ASSERT_TRUE(bc.get_db().get_dao_v2_node_ready(
        self_pk, announce_h, stored_hash));
    EXPECT_EQ(stored_hash, expected_hash);

    bc.pop_blocks(1);
    ASSERT_EQ(bc.get_current_blockchain_height(), h_before);

    crypto::hash after_hash{};
    EXPECT_FALSE(bc.get_db().get_dao_v2_node_ready(
        self_pk, announce_h, after_hash));
}

// ------------------------------------------------------------------
// B2b2b: a proposal mined into a block starts a per-proposal DKG
// runner, using the chain-state ready roster as its committee.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, ProposalTriggersPerProposalDkg)
{
    using namespace cryptonote;

    auto& bc = m_core->get_blockchain_storage();
    auto& db = bc.get_db();

    // Ready roster: 3 pubkeys at a canonical height.
    crypto::hash can_hash_at_1{};
    while (bc.get_current_blockchain_height() < 3) {
        account_base ma; ma.generate();
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc.create_block_template(tmpl,
            ma.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc](const block& b, uint64_t hh,
                         const crypto::hash* s, unsigned int mn,
                         crypto::hash& o) -> bool {
            return get_block_longhash(&bc, b, o, hh, s,
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
    can_hash_at_1 = bc.get_block_id_by_height(1);

    // First key is this node's identity so start_dao_v2_dkg_for_committee
    // finds us in the committee.
    crypto::public_key self_pk{}; crypto::secret_key self_sk{};
    crypto::generate_keys(self_pk, self_sk);
    m_core->set_node_key(self_sk);
    {
        db_wtxn_guard g(&db);
        db.add_dao_v2_node_ready(self_pk, 1, can_hash_at_1);
    }
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        db_wtxn_guard g(&db);
        db.add_dao_v2_node_ready(pk, 1, can_hash_at_1);
    }
    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    // Seed a proposal record with submission_height = current tip.
    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xA5, 32);
    const uint64_t sub_h = bc.get_current_blockchain_height();
    {
        proposal_record rec{};
        rec.proposal_id = prop_id;
        rec.submission_height = sub_h;
        rec.voting_end_height = sub_h + 720;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        std::memset(rec.tally_key_id.data, 0, 32);
        db_wtxn_guard g(&db);
        db.add_proposal_record(prop_id, rec);
    }

    // Direct invocation of the trigger method (the block-apply loop is
    // a one-line scan that calls the same method; covering that in a
    // multi-node integration is B4 scope).
    EXPECT_EQ(bc.start_dao_v2_dkg_for_proposal(prop_id),
              dao::dao_dkg_start_status::started);

    const std::string ceremony_id =
        epee::string_tools::pod_to_hex(prop_id);
    std::lock_guard<std::mutex> lk2(bc.m_dao_v2_dkg_runners_for_test_mutex());
    EXPECT_GT(bc.m_dao_v2_dkg_runners_for_test().count(ceremony_id), 0u);
}

// ------------------------------------------------------------------
// B2c1 isolation: two proposals' tally keys must not collide.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, TwoProposalsIsolatedTallyKeys)
{
    using namespace cryptonote;

    auto& bc = m_core->get_blockchain_storage();
    auto& db = bc.get_db();

    crypto::public_key self_pk{};
    crypto::secret_key self_sk{};
    crypto::generate_keys(self_pk, self_sk);
    m_core->set_node_key(self_sk);

    auto make_record = [&](uint8_t seed) -> dao::dao_tally_key_record {
        dao::dao_tally_key_record rec{};
        rec.version        = 1;
        rec.committee_size = 3;
        rec.threshold      = 2;
        rec.t              = 1;
        rec.committee_id_hash.assign(32, seed);
        rec.committee_members.resize(3);
        rec.committee_members[0].assign(self_pk.data, self_pk.data + 32);
        for (int i = 1; i < 3; ++i) {
            crypto::public_key pk; crypto::secret_key sk;
            crypto::generate_keys(pk, sk);
            rec.committee_members[i].assign(pk.data, pk.data + 32);
        }
        rec.delta.assign(32, seed);
        rec.N.assign(256, seed);
        rec.G.assign(256, 0);
        rec.theta.assign(256, 0);
        rec.V.assign(512, 0);
        rec.V_K_i.assign(3, std::vector<uint8_t>(512, seed));
        rec.vss_P.assign(64, 0);
        rec.vss_P_prime.assign(64, 0);
        rec.vss_g.assign(1, 4);
        rec.vss_h.assign(64, 0);
        rec.activation_height   = 1;
        rec.dkg_transcript_hash.assign(32, 0);
        rec.key_id.assign(32, seed);
        return rec;
    };

    auto keyA = make_record(0xAA);
    auto keyB = make_record(0xBB);
    ASSERT_NE(keyA.key_id, keyB.key_id);

    std::vector<uint8_t> shareA{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    std::vector<uint8_t> shareB{0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};

    bc.install_dao_tally_key_for_proposal_for_test(keyA, shareA);
    bc.install_dao_tally_key_for_proposal_for_test(keyB, shareB);

    {
        dao::dao_tally_key_record r;
        ASSERT_TRUE(db.get_dao_tally_key_by_id(keyA.key_id, r));
        EXPECT_EQ(r.key_id, keyA.key_id);
        ASSERT_TRUE(db.get_dao_tally_key_by_id(keyB.key_id, r));
        EXPECT_EQ(r.key_id, keyB.key_id);
    }

    const uint32_t ssA = dao::share_set_id_for_key_id(keyA.key_id);
    const uint32_t ssB = dao::share_set_id_for_key_id(keyB.key_id);
    EXPECT_GT(ssA, 1u);
    EXPECT_GT(ssB, 1u);
    EXPECT_NE(ssA, ssB);

    {
        dao::dao_share_set_record ss;
        ASSERT_TRUE(db.get_dao_share_set(ssA, ss));
        EXPECT_EQ(ss.key_id, keyA.key_id);
        ASSERT_TRUE(db.get_dao_share_set(ssB, ss));
        EXPECT_EQ(ss.key_id, keyB.key_id);
    }

    {
        std::vector<uint8_t> lsA, lsB;
        ASSERT_TRUE(db.get_dao_local_share(ssA, 1, lsA));
        ASSERT_TRUE(db.get_dao_local_share(ssB, 1, lsB));
        EXPECT_NE(lsA, lsB);
    }

}

// ------------------------------------------------------------------
// At voting-end, if the ready roster differs from the acceptance
// committee, a reshare must start for the proposal's key.
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// v6 certificate evidence end-to-end. Real 3-party DKG, real reshare
// of the 3-member key to a 3-member subset that includes a new member,
// hand-built v6 cert, verify accepts, tampered evidence rejects.
// ------------------------------------------------------------------
