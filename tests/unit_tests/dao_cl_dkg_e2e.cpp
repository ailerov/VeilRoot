// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_dkg_runner.h"
#include "governance/dao_cl_party.h"
#include "governance/dao_dkg_transport.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"

#include <algorithm>
#include <array>
#include <memory>

using namespace cryptonote::dao;

namespace {

static BICYCL::Mpz decode_share(const std::vector<uint8_t>& in)
{
    if (in.size() < 5) return BICYCL::Mpz();
    uint32_t len = (static_cast<uint32_t>(in[1]) << 24)
                 | (static_cast<uint32_t>(in[2]) << 16)
                 | (static_cast<uint32_t>(in[3]) <<  8)
                 |  static_cast<uint32_t>(in[4]);
    if (in.size() != 5u + len) return BICYCL::Mpz();
    if (len == 0) return BICYCL::Mpz();
    std::vector<unsigned char> mag(in.begin() + 5, in.end());
    BICYCL::Mpz v(mag);
    if (in[0] == 1) v.neg();
    return v;
}

TEST(dao_cl_dkg_e2e, p2p_dkg_aggregate_and_threshold_decrypt)
{
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(20241113UL));
    auto cl = cl_dkg_make_hsmq(128, rng);
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
        cfg.test_seed = 3000 + i;
        cfg.phase_timeout_seconds = 180;
        runners.push_back(std::make_unique<cl_dkg_p2p_runner>(
            cfg, std::move(net.endpoints[i])));
    }
    for (auto& r : runners) ASSERT_TRUE(r->start());

    std::vector<cl_dkg_result> results(3);
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(runners[i]->wait(results[i], 300))
            << "party " << (i + 1) << " timeout";
        ASSERT_TRUE(results[i].ok) << "party " << (i + 1) << " failed";
    }
    for (auto& r : runners) r->stop();
    runners.clear();

    for (size_t i = 1; i < 3; ++i) {
        ASSERT_EQ(results[0].ctx.pk_qfi, results[i].ctx.pk_qfi);
        ASSERT_EQ(results[0].gammas_serialized, results[i].gammas_serialized);
        ASSERT_EQ(results[0].qualified_ids, results[i].qualified_ids);
    }

    BICYCL::QFI pk_qfi;
    std::size_t off = 0;
    ASSERT_TRUE(cl_dkg_qfi_from_bytes(
        results[0].ctx.pk_qfi, off, pk_qfi, cl->Cl_G().discriminant()));
    ASSERT_EQ(off, results[0].ctx.pk_qfi.size());
    BICYCL::CL_HSMqk::PublicKey pk(*cl, pk_qfi);

    std::vector<std::unique_ptr<CLCommitteeParty>> parties;
    for (uint32_t i = 0; i < 3; ++i) {
        BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI> gammas;
        ASSERT_TRUE(cl_dkg_deserialize_gammas(
            results[i].gammas_serialized, cl->Cl_G().discriminant(), gammas));

        BICYCL::CL_Threshold_Static::ParticipantsSet qualified(
            results[i].qualified_ids.begin(), results[i].qualified_ids.end());

        BICYCL::Mpz share = decode_share(results[i].local_secret_share);
        auto p = std::make_unique<CLCommitteeParty>(cl, 3, 1, i, 32);
        ASSERT_TRUE(p->restore_decryption_state(pk, gammas, qualified, share))
            << "party " << i << " restore failed";
        parties.push_back(std::move(p));
    }

    BICYCL::Mpz w_int(100UL), s_int(50UL), b_int(25UL);
    auto cw = cl->encrypt(pk, BICYCL::CL_HSMqk::ClearText(*cl, w_int), rng);
    auto cs = cl->encrypt(pk, BICYCL::CL_HSMqk::ClearText(*cl, s_int), rng);
    auto cb = cl->encrypt(pk, BICYCL::CL_HSMqk::ClearText(*cl, b_int), rng);

    auto agg = cl->add_ciphertexts(pk, cw, cs, rng);
    agg = cl->add_ciphertexts(pk, agg, cb, rng);

    for (auto& p : parties) ASSERT_TRUE(p->partial_decrypt(agg, rng));
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = 0; j < 3; ++j) {
            if (i == j) continue;
            parties[j]->add_partial_dec(i, parties[i]->partial());
        }
    for (auto& p : parties) ASSERT_TRUE(p->verify_partials(rng));

    BICYCL::CL_HSMqk::ClearText got(*cl, BICYCL::Mpz(0UL));
    ASSERT_TRUE(parties[0]->combine(got, agg));
    EXPECT_EQ(static_cast<BICYCL::Mpz>(got), BICYCL::Mpz(175UL));
}

} // namespace

#endif // VEILROOT_ENABLE_CL
