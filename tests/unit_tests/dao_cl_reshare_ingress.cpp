// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Chain-level ingress authentication tests for CL reshare messages.

#include "gtest/gtest.h"

#ifdef VEILROOT_ENABLE_CL

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "gtest/gtest.h"

#include "blockchain_db/blockchain_db.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_core.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_tally.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace po = boost::program_options;

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

crypto::public_key pk_from_sk(const crypto::secret_key& sk)
{
    crypto::public_key pk{};
    crypto::secret_key_to_public_key(sk, pk);
    return pk;
}

std::vector<uint8_t> pk_bytes(const crypto::public_key& pk)
{
    return std::vector<uint8_t>(pk.data, pk.data + 32);
}

} // namespace

class DaoClReshareIngress : public ::testing::Test
{
protected:
    std::string                m_dir;
    std::unique_ptr<cryptonote::core> m_core;
    crypto::secret_key         m_node_sec;
    crypto::public_key         m_node_pub;

    crypto::secret_key         m_sibling_sec[2];
    crypto::public_key         m_sibling_pub[2];

    crypto::hash               m_prop_id{};
    std::vector<uint8_t>       m_key_id;
    uint64_t                   m_share_set_id = 0;

    void SetUp() override
    {
        boost::filesystem::path tmp =
            boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_cl_ing_%%%%-%%%%");
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
        m_node_sec = sec;
        m_node_pub = pub;
        m_core->set_node_key(m_node_sec);

        crypto::generate_keys(m_sibling_pub[0], m_sibling_sec[0]);
        crypto::generate_keys(m_sibling_pub[1], m_sibling_sec[1]);

        m_prop_id.data[0] = 0xd3;
        m_prop_id.data[31] = 0xd3;

        install_bootstrap(/*qualified=*/{0u, 1u, 2u});
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

    std::vector<crypto::public_key> all_keys() const
    {
        return {m_node_pub, m_sibling_pub[0], m_sibling_pub[1]};
    }

    void install_bootstrap(std::vector<uint32_t> qualified)
    {
        auto keys = all_keys();

        dao_tally_key_record rec;
        rec.version        = 1;
        rec.committee_size = 3;
        rec.threshold      = 2;
        rec.t              = 1;
        for (const auto& k : keys) rec.committee_members.push_back(pk_bytes(k));
        rec.committee_id_hash.assign(32, 0xcc);
        rec.cl_modulus.assign(256, 0xee);
        rec.activation_height = 1;
        rec.dkg_transcript_hash.assign(32, 0xdd);
        rec.key_id.assign(32, 0x00);
        rec.key_id[0] = 0xab;
        m_key_id = rec.key_id;

        dao_share_set_record ss;
        ss.version              = 3;
        ss.share_set_id         = share_set_id_for_key_id(rec.key_id);
        ss.height               = 1;
        ss.threshold            = 2;
        ss.key_id               = rec.key_id;
        ss.committee_id_hash    = rec.committee_id_hash;
        ss.committee_members    = rec.committee_members;
        ss.base_share_set_id    = 0;
        ss.cl_gammas_serialized.assign(256, 0x77);
        ss.qualified_ids        = qualified;
        m_share_set_id          = ss.share_set_id;

        bc().install_cl_tally_key_for_proposal_for_test(rec, ss, {});

        proposal_record pr;
        pr.proposal_id          = m_prop_id;
        pr.submission_height    = 0;
        pr.voting_end_height    = 3;
        pr.status               = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(pr.tally_key_id.data, rec.key_id.data(), 32);

        db().block_wtxn_start();
        db().add_proposal_record(m_prop_id, pr);
        db().block_wtxn_stop();
    }

    // Craft a reshare_prestate envelope with the given session id and
    // dealer id. Crypto payload is dummy (ingress auth runs before any
    // crypto verification).
    std::string craft_prestate(const crypto::hash& sid, uint32_t dealer_id)
    {
        cl_dkg_payload p;
        BICYCL::Mpz q_i(1ul), r_i(2ul), L_i(3ul);
        EXPECT_TRUE(cl_dkg_encode_reshare_prestate(
            sid, dealer_id, q_i, r_i, L_i, p));

        dkg_msg env;
        env.hdr.version     = 2;
        env.hdr.proposal_id = m_prop_id;
        env.hdr.sender_id   = dealer_id + 1;
        env.hdr.recipient_id = 0;
        env.hdr.type        = dkg_msg_type::cl_dkg_envelope;
        EXPECT_TRUE(p.serialize(env.bytes_a));

        std::vector<uint8_t> wire;
        EXPECT_TRUE(env.serialize(wire));
        return std::string(wire.begin(), wire.end());
    }

    // As craft_prestate but caller controls hdr.sender_id independently
    // of dealer_id in the body.
    std::string craft_prestate_sender_override(
        const crypto::hash& sid, uint32_t dealer_id,
        uint32_t hdr_sender_id)
    {
        cl_dkg_payload p;
        BICYCL::Mpz q_i(1ul), r_i(2ul), L_i(3ul);
        EXPECT_TRUE(cl_dkg_encode_reshare_prestate(
            sid, dealer_id, q_i, r_i, L_i, p));

        dkg_msg env;
        env.hdr.version      = 2;
        env.hdr.proposal_id  = m_prop_id;
        env.hdr.sender_id    = hdr_sender_id;
        env.hdr.recipient_id = 0;
        env.hdr.type         = dkg_msg_type::cl_dkg_envelope;
        EXPECT_TRUE(p.serialize(env.bytes_a));

        std::vector<uint8_t> wire;
        EXPECT_TRUE(env.serialize(wire));
        return std::string(wire.begin(), wire.end());
    }
};

TEST_F(DaoClReshareIngress, rejects_sender_not_in_committee)
{
    crypto::hash sid{}; sid.data[0] = 0x11;
    // Dealer 99 not in 3-member committee -> pos0 == UINT32_MAX -> drop.
    auto env = craft_prestate(sid, /*dealer_id=*/99u);
    bc().handle_dao_v2_dkg_msg(m_node_pub, env);
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 0u);
}

TEST_F(DaoClReshareIngress, rejects_sender_id_mismatch)
{
    crypto::hash sid{}; sid.data[0] = 0x22;
    // Authenticated peer is m_node_pub (committee index 0), but header
    // claims sender_id 2 (mismatch). Drop.
    auto env = craft_prestate_sender_override(
        sid, /*dealer_id=*/0u, /*hdr_sender_id=*/2u);
    bc().handle_dao_v2_dkg_msg(m_node_pub, env);
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 0u);
}

TEST_F(DaoClReshareIngress, rejects_sender_not_qualified)
{
    // Reinstall with qualified = {0, 2} (skip index 1). Peer is
    // m_sibling_pub[0] at committee index 1 -> not qualified -> drop.
    // Second install overwrites via LMDB keys.
    install_bootstrap(/*qualified=*/{0u, 2u});

    crypto::hash sid{}; sid.data[0] = 0x33;
    auto env = craft_prestate_sender_override(
        sid, /*dealer_id=*/1u, /*hdr_sender_id=*/2u);
    bc().handle_dao_v2_dkg_msg(m_sibling_pub[0], env);
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 0u);
}

TEST_F(DaoClReshareIngress, accepts_qualified_sender_buffers_for_later_runner)
{
    crypto::hash sid{}; sid.data[0] = 0x44;
    auto env = craft_prestate_sender_override(
        sid, /*dealer_id=*/0u, /*hdr_sender_id=*/1u);
    bc().handle_dao_v2_dkg_msg(m_node_pub, env);
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 1u);
}

TEST_F(DaoClReshareIngress, buffers_multiple_until_cap)
{
    crypto::hash sid{}; sid.data[0] = 0x55;
    for (int i = 0; i < 5; ++i) {
        auto env = craft_prestate_sender_override(
            sid, /*dealer_id=*/0u, /*hdr_sender_id=*/1u);
        bc().handle_dao_v2_dkg_msg(m_node_pub, env);
    }
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 5u);
}

TEST_F(DaoClReshareIngress, wrong_outer_type_dropped)
{
    crypto::hash sid{}; sid.data[0] = 0x66;
    cl_dkg_payload p;
    BICYCL::Mpz q_i(1ul), r_i(2ul), L_i(3ul);
    ASSERT_TRUE(cl_dkg_encode_reshare_prestate(sid, 0u, q_i, r_i, L_i, p));
    dkg_msg env;
    env.hdr.version      = 2;
    env.hdr.proposal_id  = m_prop_id;
    env.hdr.sender_id    = 1;
    env.hdr.type         = dkg_msg_type::key_record_ready;
    ASSERT_TRUE(p.serialize(env.bytes_a));
    std::vector<uint8_t> wire;
    ASSERT_TRUE(env.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    bc().handle_dao_v2_dkg_msg(m_node_pub, payload);
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 0u);
}

TEST_F(DaoClReshareIngress, short_body_dropped)
{
    crypto::hash sid{}; sid.data[0] = 0x77;
    cl_dkg_payload p;
    p.subtype = cl_dkg_subtype::reshare_prestate;
    p.body.assign(16, 0xaa);   // < 32 byte session prefix
    dkg_msg env;
    env.hdr.version      = 2;
    env.hdr.proposal_id  = m_prop_id;
    env.hdr.sender_id    = 1;
    env.hdr.type         = dkg_msg_type::cl_dkg_envelope;
    ASSERT_TRUE(p.serialize(env.bytes_a));
    std::vector<uint8_t> wire;
    ASSERT_TRUE(env.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    bc().handle_dao_v2_dkg_msg(m_node_pub, payload);
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 0u);
}

TEST_F(DaoClReshareIngress, complete_subtype_dropped)
{
    crypto::hash sid{}; sid.data[0] = 0x88;
    cl_dkg_payload p;
    ASSERT_TRUE(cl_dkg_encode_reshare_complete(p));
    dkg_msg env;
    env.hdr.version      = 2;
    env.hdr.proposal_id  = m_prop_id;
    env.hdr.sender_id    = 1;
    env.hdr.type         = dkg_msg_type::cl_dkg_envelope;
    ASSERT_TRUE(p.serialize(env.bytes_a));
    std::vector<uint8_t> wire;
    ASSERT_TRUE(env.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    bc().handle_dao_v2_dkg_msg(m_node_pub, payload);
    EXPECT_EQ(bc().get_dao_v2_pending_reshare_msgs_size_for_test(), 0u);
}

#endif // VEILROOT_ENABLE_CL
