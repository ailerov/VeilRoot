// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_dkg_runner.h"
#include "governance/dao_cl_party.h"
#include "governance/dao_cl_reshare_runner.h"
#include "governance/dao_dkg_transport.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"

#include <algorithm>
#include <memory>

using namespace cryptonote::dao;

namespace {

static BICYCL::Mpz decode_share_wire(const std::vector<uint8_t>& in)
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

TEST(dao_cl_reshare_e2e, three_to_three_preserves_pk_and_decrypts_pre_reshare_ct)
{
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(112233UL));
    auto cl = cl_dkg_make_hsmq(128, rng);
    ASSERT_TRUE(cl);

    // ---- Phase 1: 3-party P2P DKG ----
    auto net1 = dkg_make_inproc_network(3);
    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> dkg_runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 1;
        cfg.member_ids.resize(3);
        cfg.local_party_id = i + 1;
        cfg.soundness_bytes = 32;
        cfg.test_seed = 4000 + i;
        cfg.phase_timeout_seconds = 180;
        dkg_runners.push_back(std::make_unique<cl_dkg_p2p_runner>(
            cfg, std::move(net1.endpoints[i])));
    }
    for (auto& r : dkg_runners) ASSERT_TRUE(r->start());

    std::vector<cl_dkg_result> dkg_results(3);
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(dkg_runners[i]->wait(dkg_results[i], 300))
            << "party " << i << " DKG timeout";
        ASSERT_TRUE(dkg_results[i].ok) << "party " << i << " DKG failed";
    }
    for (auto& r : dkg_runners) r->stop();
    dkg_runners.clear();

    // ---- Reconstruct old pk and encrypt pre-reshare ciphertext ----
    BICYCL::QFI pk_qfi;
    std::size_t pk_off = 0;
    ASSERT_TRUE(cl_dkg_qfi_from_bytes(
        dkg_results[0].ctx.pk_qfi, pk_off, pk_qfi,
        cl->Cl_G().discriminant()));
    ASSERT_EQ(pk_off, dkg_results[0].ctx.pk_qfi.size());
    BICYCL::CL_HSMqk::PublicKey old_pk(*cl, pk_qfi);

    BICYCL::Mpz w_int(77UL);
    auto ct = cl->encrypt(old_pk,
                          BICYCL::CL_HSMqk::ClearText(*cl, w_int), rng);

    // ---- Phase 2: 3->3 reshare over P2P ----
    auto net2 = dkg_make_inproc_network(3);
    std::vector<std::unique_ptr<cl_reshare_p2p_runner>> r_runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_reshare_config cfg;
        cfg.cl = cl;
        cfg.D_signed             = dkg_results[0].ctx.D;
        cfg.old_n                = 3;
        cfg.old_t_internal       = 1;
        cfg.old_contributors     = {0u, 1u};
        cfg.new_n                = 3;
        cfg.new_t_internal       = 1;
        cfg.is_old_contributor   = (i < 2);
        cfg.old_local_id         = i;
        cfg.is_new_member        = true;
        cfg.new_local_id         = i;
        cfg.old_pk_qfi           = dkg_results[0].ctx.pk_qfi;
        cfg.old_gammas_serialized = dkg_results[0].gammas_serialized;
        if (i < 2)
            cfg.old_share_bytes = dkg_results[i].local_secret_share;
        cfg.soundness_bytes      = 32;
        cfg.phase_timeout_seconds = 180;
        cfg.test_seed            = 5000 + i;
        r_runners.push_back(std::make_unique<cl_reshare_p2p_runner>(
            cfg, std::move(net2.endpoints[i])));
    }
    for (auto& r : r_runners) ASSERT_TRUE(r->start());

    std::vector<cl_reshare_result> r_results(3);
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(r_runners[i]->wait(r_results[i], 300))
            << "reshare party " << i << " timeout";
        ASSERT_TRUE(r_results[i].ok)
            << "reshare party " << i << " failed";
    }
    for (auto& r : r_runners) r->stop();
    r_runners.clear();

    // ---- pk unchanged ----
    for (size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(r_results[i].pk_qfi, dkg_results[0].ctx.pk_qfi)
            << "party " << i << " pk changed";
    }

    // ---- Reconstruct new parties, decrypt pre-reshare ct ----
    std::vector<std::unique_ptr<CLCommitteeParty>> new_parties;
    for (size_t i = 0; i < 3; ++i) {
        BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI> gammas;
        ASSERT_TRUE(cl_dkg_deserialize_gammas(
            r_results[i].new_gammas_serialized,
            cl->Cl_G().discriminant(), gammas));

        BICYCL::CL_Threshold_Static::ParticipantsSet qualified(
            r_results[i].qualified_ids.begin(),
            r_results[i].qualified_ids.end());

        BICYCL::Mpz share = decode_share_wire(r_results[i].new_share_bytes);
        auto p = std::make_unique<CLCommitteeParty>(cl, 3, 1, i, 32);
        ASSERT_TRUE(p->restore_decryption_state(old_pk, gammas, qualified, share))
            << "new party " << i << " restore failed";
        new_parties.push_back(std::move(p));
    }

    for (auto& p : new_parties) ASSERT_TRUE(p->partial_decrypt(ct, rng));
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = 0; j < 3; ++j) {
            if (i == j) continue;
            new_parties[j]->add_partial_dec(i, new_parties[i]->partial());
        }
    for (auto& p : new_parties) ASSERT_TRUE(p->verify_partials(rng));

    BICYCL::CL_HSMqk::ClearText got(*cl, BICYCL::Mpz(0UL));
    ASSERT_TRUE(new_parties[0]->combine(got, ct));
    EXPECT_EQ(static_cast<BICYCL::Mpz>(got), w_int);
}

} // namespace

#endif // VEILROOT_ENABLE_CL
