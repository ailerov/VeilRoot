// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// CL reshare runner negative and wire-form tests. Chain-free: no
// DKG, no LMDB, no transport traffic.

#include "gtest/gtest.h"

#ifdef VEILROOT_ENABLE_CL

#include "governance/dao_cl_ballot.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_reshare_runner.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include "crypto/crypto.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

// One CL group reused across preflight tests. Prime search is the
// expensive part; a single construction amortises it.
std::shared_ptr<BICYCL::CL_HSMqk> shared_cl()
{
    static std::shared_ptr<BICYCL::CL_HSMqk> cl;
    static std::once_flag once;
    std::call_once(once, []() {
        std::vector<uint8_t> seed(32);
        for (int i = 0; i < 32; ++i)
            seed[i] = static_cast<uint8_t>(i + 1);
        cl = dao_cl_make_hsmq_from_seed(seed, 128);
    });
    return cl;
}

cl_reshare_config base_config()
{
    cl_reshare_config cfg;
    cfg.cl                    = shared_cl();
    cfg.D_signed              = {0x00, 0x00, 0x00, 0x00, 0x01, 0x01};
    cfg.old_n                 = 3;
    cfg.old_t_internal        = 1;
    cfg.old_contributors      = {0u, 1u};
    cfg.new_n                 = 3;
    cfg.new_t_internal        = 1;
    cfg.is_old_contributor    = true;
    cfg.old_local_id          = 0;
    cfg.is_new_member         = true;
    cfg.new_local_id          = 0;
    cfg.old_pk_qfi.assign(64, 0x11);
    cfg.old_gammas_serialized = {0x00};
    cfg.old_share_bytes       = {0x00, 0x00, 0x00, 0x00, 0x01, 0x07};
    cfg.old_share_set_id      = 1;
    cfg.old_committee_id_hash.assign(32, 0xaa);
    cfg.new_committee_id_hash.assign(32, 0xbb);
    cfg.old_qualified_ids     = {0u, 1u};
    cfg.session_id.data[0]    = 0x01;
    cfg.proposal_id           = crypto::hash{};
    return cfg;
}

bool run_preflight(const cl_reshare_config& cfg)
{
    auto net = dkg_make_inproc_network(1, nullptr);
    cl_reshare_p2p_runner r(cfg, std::move(net.endpoints[0]));
    return r.start();
}

} // namespace

// ---------- Preflight config validation ----------

TEST(DaoClResharePreflight, rejects_null_cl)
{
    auto cfg = base_config();
    cfg.cl = nullptr;
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_empty_contributors)
{
    auto cfg = base_config();
    cfg.old_contributors.clear();
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_unsorted_contributors)
{
    auto cfg = base_config();
    cfg.old_contributors = {1u, 0u};
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_duplicate_contributors)
{
    auto cfg = base_config();
    cfg.old_contributors = {0u, 0u};
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_out_of_range_contributor)
{
    auto cfg = base_config();
    cfg.old_contributors = {0u, 5u};
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_too_few_contributors)
{
    // old_t_internal = 1 implies >= 2 contributors.
    auto cfg = base_config();
    cfg.old_contributors = {0u};
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_contributor_not_in_qualified)
{
    auto cfg = base_config();
    cfg.old_contributors = {0u, 2u};
    cfg.old_qualified_ids = {0u, 1u};
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_empty_qualified)
{
    auto cfg = base_config();
    cfg.old_qualified_ids.clear();
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_empty_D_signed)
{
    auto cfg = base_config();
    cfg.D_signed.clear();
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_empty_old_pk_qfi)
{
    auto cfg = base_config();
    cfg.old_pk_qfi.clear();
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_empty_gammas)
{
    auto cfg = base_config();
    cfg.old_gammas_serialized.clear();
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_zero_share_set_id)
{
    auto cfg = base_config();
    cfg.old_share_set_id = 0;
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_wrong_committee_hash_size)
{
    auto cfg = base_config();
    cfg.old_committee_id_hash.assign(16, 0xaa);
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_zero_session_id)
{
    auto cfg = base_config();
    cfg.session_id = crypto::hash{};
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_neither_old_nor_new)
{
    auto cfg = base_config();
    cfg.is_old_contributor = false;
    cfg.is_new_member = false;
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_old_without_share_bytes)
{
    auto cfg = base_config();
    cfg.old_share_bytes.clear();
    EXPECT_FALSE(run_preflight(cfg));
}

TEST(DaoClResharePreflight, rejects_old_local_id_not_in_contributors)
{
    auto cfg = base_config();
    cfg.old_local_id = 2;
    EXPECT_FALSE(run_preflight(cfg));
}

// ---------- Session-id derivation ----------

namespace {

crypto::hash pick_proposal(uint8_t b0)
{
    crypto::hash h{};
    h.data[0] = b0;
    return h;
}

} // namespace

TEST(DaoClReshareSessionId, deterministic_across_calls)
{
    auto pid = pick_proposal(0x42);
    std::vector<uint8_t> oh(32, 0xaa), nh(32, 0xbb);
    std::vector<uint32_t> c = {0u, 1u, 2u};
    auto a = dao_cl_reshare_compute_session_id(pid, 5, oh, nh, c);
    auto b = dao_cl_reshare_compute_session_id(pid, 5, oh, nh, c);
    EXPECT_EQ(std::memcmp(a.data, b.data, 32), 0);
}

TEST(DaoClReshareSessionId, sensitive_to_proposal)
{
    std::vector<uint8_t> oh(32, 0xaa), nh(32, 0xbb);
    std::vector<uint32_t> c = {0u, 1u, 2u};
    auto a = dao_cl_reshare_compute_session_id(
        pick_proposal(0x42), 5, oh, nh, c);
    auto b = dao_cl_reshare_compute_session_id(
        pick_proposal(0x43), 5, oh, nh, c);
    EXPECT_NE(std::memcmp(a.data, b.data, 32), 0);
}

TEST(DaoClReshareSessionId, sensitive_to_set_id)
{
    auto pid = pick_proposal(0x42);
    std::vector<uint8_t> oh(32, 0xaa), nh(32, 0xbb);
    std::vector<uint32_t> c = {0u, 1u, 2u};
    auto a = dao_cl_reshare_compute_session_id(pid, 5, oh, nh, c);
    auto b = dao_cl_reshare_compute_session_id(pid, 6, oh, nh, c);
    EXPECT_NE(std::memcmp(a.data, b.data, 32), 0);
}

TEST(DaoClReshareSessionId, sensitive_to_old_hash)
{
    auto pid = pick_proposal(0x42);
    std::vector<uint8_t> oh1(32, 0xaa), oh2(32, 0xab);
    std::vector<uint8_t> nh(32, 0xbb);
    std::vector<uint32_t> c = {0u, 1u, 2u};
    auto a = dao_cl_reshare_compute_session_id(pid, 5, oh1, nh, c);
    auto b = dao_cl_reshare_compute_session_id(pid, 5, oh2, nh, c);
    EXPECT_NE(std::memcmp(a.data, b.data, 32), 0);
}

TEST(DaoClReshareSessionId, sensitive_to_new_hash)
{
    auto pid = pick_proposal(0x42);
    std::vector<uint8_t> oh(32, 0xaa);
    std::vector<uint8_t> nh1(32, 0xbb), nh2(32, 0xbc);
    std::vector<uint32_t> c = {0u, 1u, 2u};
    auto a = dao_cl_reshare_compute_session_id(pid, 5, oh, nh1, c);
    auto b = dao_cl_reshare_compute_session_id(pid, 5, oh, nh2, c);
    EXPECT_NE(std::memcmp(a.data, b.data, 32), 0);
}

TEST(DaoClReshareSessionId, sensitive_to_contributor_set)
{
    auto pid = pick_proposal(0x42);
    std::vector<uint8_t> oh(32, 0xaa), nh(32, 0xbb);
    std::vector<uint32_t> c1 = {0u, 1u, 2u};
    std::vector<uint32_t> c2 = {0u, 1u, 3u};
    auto a = dao_cl_reshare_compute_session_id(pid, 5, oh, nh, c1);
    auto b = dao_cl_reshare_compute_session_id(pid, 5, oh, nh, c2);
    EXPECT_NE(std::memcmp(a.data, b.data, 32), 0);
}

TEST(DaoClReshareSessionId, rejects_wrong_hash_size)
{
    auto pid = pick_proposal(0x42);
    std::vector<uint8_t> oh(16, 0xaa);  // wrong
    std::vector<uint8_t> nh(32, 0xbb);
    std::vector<uint32_t> c = {0u, 1u, 2u};
    auto h = dao_cl_reshare_compute_session_id(pid, 5, oh, nh, c);
    crypto::hash zero{};
    EXPECT_EQ(std::memcmp(h.data, zero.data, 32), 0);
}

// ---------- Payload wire form: session binding ----------

TEST(DaoClResharePayload, prestate_carries_session)
{
    BICYCL::Mpz q_i(0x1234ul), r_i(0x5678ul), L_i(0x9abul);
    crypto::hash sid{};
    sid.data[0]  = 0xde;
    sid.data[31] = 0xad;
    cl_dkg_payload p;
    ASSERT_TRUE(cl_dkg_encode_reshare_prestate(sid, 2u, q_i, r_i, L_i, p));
    crypto::hash got_sid{};
    uint32_t got_dealer = 0;
    BICYCL::Mpz got_q, got_r, got_L;
    ASSERT_TRUE(cl_dkg_decode_reshare_prestate(
        p, got_sid, got_dealer, got_q, got_r, got_L));
    EXPECT_EQ(std::memcmp(sid.data, got_sid.data, 32), 0);
    EXPECT_EQ(got_dealer, 2u);
}

TEST(DaoClResharePayload, prestate_old_session_distinguishable)
{
    // The runner compares the carried session against its own. The
    // encode/decode path must round-trip a session unchanged so the
    // comparison is meaningful.
    BICYCL::Mpz q_i(1ul), r_i(2ul), L_i(3ul);
    crypto::hash sid_a{}, sid_b{};
    sid_a.data[0] = 0x01;
    sid_b.data[0] = 0x02;
    cl_dkg_payload p;
    ASSERT_TRUE(cl_dkg_encode_reshare_prestate(sid_a, 0u, q_i, r_i, L_i, p));
    crypto::hash got_sid{};
    uint32_t got_dealer = 0;
    BICYCL::Mpz got_q, got_r, got_L;
    ASSERT_TRUE(cl_dkg_decode_reshare_prestate(
        p, got_sid, got_dealer, got_q, got_r, got_L));
    EXPECT_NE(std::memcmp(sid_a.data, sid_b.data, 32), 0);
    EXPECT_EQ(std::memcmp(got_sid.data, sid_a.data, 32), 0);
}

TEST(DaoClResharePayload, private_share_carries_session)
{
    BICYCL::Mpz share(0x123456789abcdef0ul);
    crypto::hash sid{};
    sid.data[15] = 0xab;
    cl_dkg_payload p;
    ASSERT_TRUE(cl_dkg_encode_reshare_private_share(sid, share, p));
    crypto::hash got_sid{};
    BICYCL::Mpz got_share;
    ASSERT_TRUE(cl_dkg_decode_reshare_private_share(p, got_sid, got_share));
    EXPECT_EQ(std::memcmp(sid.data, got_sid.data, 32), 0);
}

#endif // VEILROOT_ENABLE_CL
