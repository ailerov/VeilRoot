// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_dkg_runner.h"
#include "governance/dao_dkg_transport.h"

#include <atomic>
#include <stdexcept>
#include <vector>
#ifdef BICYCL_WITH_PTHREADS
#include "bicycl/bicycl/parallelism.hpp"
#endif
#ifdef VEILROOT_ENABLE_CL

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

TEST(dao_cl_dkg_p2p, three_party_keygen_matches_pk)
{
    BICYCL::RandGen hsmq_rand;
    hsmq_rand.set_seed(BICYCL::Mpz(999UL));
    auto cl = cl_dkg_make_hsmq(128, hsmq_rand);
    ASSERT_TRUE(cl);

    auto net = dkg_make_inproc_network(3);
    crypto::hash common_attempt{};
    common_attempt.data[0] = 0xA5;
    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 1;
        cfg.member_ids.resize(3);
        cfg.attempt_id = common_attempt;
        cfg.local_party_id = i + 1;
        cfg.soundness_bytes = 32;
        cfg.test_seed = 1000 + i;
        cfg.phase_timeout_seconds = 180;
        auto t = std::move(net.endpoints[i]);
        runners.push_back(
            std::make_unique<cl_dkg_p2p_runner>(cfg, std::move(t)));
    }
    for (auto& r : runners) ASSERT_TRUE(r->start());

    std::vector<cl_dkg_result> results(3);
    for (size_t i = 0; i < 3; ++i) {
        EXPECT_TRUE(runners[i]->wait(results[i], 300))
            << "party " << (i + 1) << " timeout";
        EXPECT_TRUE(results[i].ok) << "party " << (i + 1) << " failed";
    }
    for (size_t i = 1; i < 3; ++i) {
        EXPECT_EQ(results[0].ctx.pk_qfi, results[i].ctx.pk_qfi);
        EXPECT_EQ(results[0].ctx.p,      results[i].ctx.p);
        EXPECT_EQ(results[0].ctx.q,      results[i].ctx.q);
        EXPECT_EQ(results[0].ctx.k,      results[i].ctx.k);
        EXPECT_EQ(results[0].ctx.D,      results[i].ctx.D);
    }

    for (auto& r : runners) r->stop();
}

TEST(dao_cl_dkg_p2p, attempt_id_is_deterministic_and_retry_specific)
{
    crypto::hash proposal{}, retry_a{}, retry_b{}, committee{};
    proposal.data[0] = 1;
    retry_a.data[0] = 2;
    retry_b.data[0] = 3;
    committee.data[0] = 4;
    const auto first = dao_dkg_attempt_id(proposal, retry_a, committee);
    EXPECT_NE(first, crypto::null_hash);
    EXPECT_EQ(first, dao_dkg_attempt_id(proposal, retry_a, committee));
    EXPECT_NE(first, dao_dkg_attempt_id(proposal, retry_b, committee));
}

TEST(dao_cl_dkg_p2p, v3_envelope_round_trips_attempt_id)
{
    dkg_msg msg;
    msg.hdr.version = 3;
    msg.hdr.type = dkg_msg_type::cl_dkg_envelope;
    msg.hdr.proposal_id.data[0] = 0x21;
    msg.hdr.attempt_id.data[0] = 0x43;
    msg.hdr.sender_id = 1;
    std::vector<uint8_t> wire;
    ASSERT_TRUE(msg.serialize(wire));
    dkg_msg decoded;
    ASSERT_TRUE(decoded.deserialize(wire));
    EXPECT_EQ(decoded.hdr.version, 3);
    EXPECT_EQ(decoded.hdr.proposal_id, msg.hdr.proposal_id);
    EXPECT_EQ(decoded.hdr.attempt_id, msg.hdr.attempt_id);
}

TEST(dao_cl_dkg_p2p, stale_attempt_envelopes_do_not_advance_runner)
{
    BICYCL::RandGen hsmq_rand;
    hsmq_rand.set_seed(BICYCL::Mpz(1999UL));
    auto cl = cl_dkg_make_hsmq(128, hsmq_rand);
    ASSERT_TRUE(cl);
    auto net = dkg_make_inproc_network(3);
    crypto::hash proposal{};
    proposal.data[0] = 0x71;
    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 1;
        cfg.member_ids.resize(3);
        cfg.proposal_id = proposal;
        cfg.attempt_id.data[0] = static_cast<uint8_t>(i + 1);
        cfg.local_party_id = i + 1;
        cfg.soundness_bytes = 32;
        cfg.test_seed = 2000 + i;
        cfg.phase_timeout_seconds = 1;
        runners.push_back(std::make_unique<cl_dkg_p2p_runner>(
            cfg, std::move(net.endpoints[i])));
    }
    for (auto& runner : runners) ASSERT_TRUE(runner->start());
    for (auto& runner : runners) {
        cl_dkg_result result;
        ASSERT_TRUE(runner->wait(result, 20));
        EXPECT_FALSE(result.ok);
        EXPECT_EQ(result.failure_stage, "waiting_for_peer_inputs");
    }
    for (auto& runner : runners) runner->stop();
}

#ifdef BICYCL_WITH_PTHREADS
TEST(dao_cl_dkg_p2p, parallel_iterator_exec_joins_after_worker_exception)
{
    std::vector<int> data(8, 0);
    std::atomic<unsigned int> completed{0};
    auto task = [&completed](std::vector<int>::iterator,
                             std::vector<int>::iterator, unsigned int id) {
        if (id == 1) throw std::runtime_error("worker");
        ++completed;
    };
    EXPECT_THROW(BICYCL::Parallelism::exec(
        task, 4, data.begin(), data.end()), std::runtime_error);
    EXPECT_EQ(completed.load(), 3u);
}

TEST(dao_cl_dkg_p2p, parallel_iterator_exec_joins_after_caller_exception)
{
    std::vector<int> data(8, 0);
    std::atomic<unsigned int> completed{0};
    auto task = [&completed](std::vector<int>::iterator,
                             std::vector<int>::iterator, unsigned int id) {
        if (id == 3) throw std::runtime_error("caller");
        ++completed;
    };
    EXPECT_THROW(BICYCL::Parallelism::exec(
        task, 4, data.begin(), data.end()), std::runtime_error);
    EXPECT_EQ(completed.load(), 3u);
}

TEST(dao_cl_dkg_p2p, parallel_iterator_exec_successful_path)
{
    std::vector<int> data(8, 0);
    std::atomic<unsigned int> completed{0};
    BICYCL::Parallelism::exec(
        [&completed](std::vector<int>::iterator,
                     std::vector<int>::iterator, unsigned int) {
            ++completed;
        }, 4, data.begin(), data.end());
    EXPECT_EQ(completed.load(), 4u);
}

TEST(dao_cl_dkg_p2p, parallel_index_exec_joins_after_worker_exception)
{
    std::atomic<unsigned int> completed{0};
    auto task = [&completed](unsigned int, unsigned int, unsigned int id) {
        if (id == 1) throw std::runtime_error("worker");
        ++completed;
    };
    EXPECT_THROW(BICYCL::Parallelism::exec(task, 4, size_t(0), size_t(8)),
                 std::runtime_error);
    EXPECT_EQ(completed.load(), 3u);
}

TEST(dao_cl_dkg_p2p, parallel_index_exec_joins_after_caller_exception)
{
    std::atomic<unsigned int> completed{0};
    auto task = [&completed](unsigned int, unsigned int, unsigned int id) {
        if (id == 3) throw std::runtime_error("caller");
        ++completed;
    };
    EXPECT_THROW(BICYCL::Parallelism::exec(task, 4, size_t(0), size_t(8)),
                 std::runtime_error);
    EXPECT_EQ(completed.load(), 3u);
}

TEST(dao_cl_dkg_p2p, parallel_index_exec_successful_path)
{
    std::atomic<unsigned int> completed{0};
    BICYCL::Parallelism::exec(
        [&completed](unsigned int, unsigned int, unsigned int) {
            ++completed;
        }, 4, size_t(0), size_t(8));
    EXPECT_EQ(completed.load(), 4u);
}
#endif // BICYCL_WITH_PTHREADS

} // namespace

#endif // VEILROOT_ENABLE_CL
