// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_dkg_runner.h"
#include "governance/dao_dkg_transport.h"

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

    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 1;
        cfg.member_ids.resize(3);
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

} // namespace

#endif // VEILROOT_ENABLE_CL
