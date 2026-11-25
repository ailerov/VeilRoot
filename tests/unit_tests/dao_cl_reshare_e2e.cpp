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

static bool key_context_D_to_reshare_wire(
    const std::vector<uint8_t>& in, std::vector<uint8_t>& out)
{
    // D is positive (enforced by cl_dkg_p2p_runner::fill_result).
    // Key-context format is sign||magnitude; the reshare runner expects
    // sign||u32(BE)||magnitude.
    constexpr std::size_t max_magnitude_bytes = 4095;
    if (in.size() < 2 || in[0] != 0 || in[1] == 0 ||
        in.size() - 1 > max_magnitude_bytes)
        return false;

    const uint32_t len = static_cast<uint32_t>(in.size() - 1);
    out.clear();
    out.reserve(in.size() + 4);
    out.push_back(in[0]);
    out.push_back(static_cast<uint8_t>((len >> 24) & 0xffu));
    out.push_back(static_cast<uint8_t>((len >> 16) & 0xffu));
    out.push_back(static_cast<uint8_t>((len >> 8) & 0xffu));
    out.push_back(static_cast<uint8_t>(len & 0xffu));
    out.insert(out.end(), in.begin() + 1, in.end());
    return true;
}

TEST(dao_cl_reshare_e2e, three_to_three_preserves_pk_and_decrypts_pre_reshare_ct)
{
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(112233UL));
    auto cl = cl_dkg_make_hsmq(128, rng);
    ASSERT_TRUE(cl);

    // ---- Phase 1: 3-party P2P DKG ----
    auto net1 = dkg_make_inproc_network(3);
    crypto::hash common_attempt{};
    common_attempt.data[0] = 0xD2;
    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> dkg_runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 1;
        cfg.attempt_id = common_attempt;
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
    std::vector<uint8_t> D_signed;
    ASSERT_TRUE(key_context_D_to_reshare_wire(
        dkg_results[0].ctx.D, D_signed));

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
        cfg.D_signed = D_signed;
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
        cfg.old_share_set_id     = 1;
        cfg.old_committee_id_hash.assign(32, 0xA1);
        cfg.new_committee_id_hash.assign(32, 0xB2);
        cfg.old_qualified_ids    = dkg_results[0].qualified_ids;
        cfg.session_id           = dao_cl_reshare_compute_session_id(
            /*proposal_id=*/crypto::hash{},
            /*old_share_set_id=*/1,
            cfg.old_committee_id_hash,
            cfg.new_committee_id_hash,
            /*sorted_old_contributors=*/{0u, 1u});
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


TEST(dao_cl_reshare_e2e, old_only_contributor_gets_gammas_via_completion)
{
    // Old committee size 3, new committee size 2 taken from the
    // strict subset {0, 1}. Party 2 is an old-only contributor: it
    // is a reshare dealer but is not in the new committee and holds
    // no new local share. It must still receive the new Gamma map
    // and qualified ids via reshare_complete broadcasts from the
    // new committee.
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(20260216UL));
    auto cl = cl_dkg_make_hsmq(128, rng);
    ASSERT_TRUE(cl);

    auto net = dkg_make_inproc_network(3);
    crypto::hash common_attempt{};
    common_attempt.data[0] = 0xD3;
    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> dkg_runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 2;
        cfg.attempt_id = common_attempt;
        cfg.member_ids.resize(3);
        cfg.local_party_id = i + 1;
        cfg.soundness_bytes = 32;
        cfg.test_seed = 7500 + i;
        cfg.phase_timeout_seconds = 180;
        dkg_runners.push_back(std::make_unique<cl_dkg_p2p_runner>(
            cfg, std::move(net.endpoints[i])));
    }
    for (auto& r : dkg_runners) ASSERT_TRUE(r->start());
    std::vector<cl_dkg_result> dkg_results(3);
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(dkg_runners[i]->wait(dkg_results[i], 300));
        ASSERT_TRUE(dkg_results[i].ok);
    }
    for (auto& r : dkg_runners) r->stop();
    dkg_runners.clear();
    std::vector<uint8_t> D_signed;
    ASSERT_TRUE(key_context_D_to_reshare_wire(
        dkg_results[0].ctx.D, D_signed));

    std::vector<crypto::public_key> new_pks(2);
    std::vector<crypto::secret_key> new_sks(2);
    for (int i = 0; i < 2; ++i)
        crypto::generate_keys(new_pks[i], new_sks[i]);

    auto net2 = dkg_make_inproc_network(3);
    std::vector<std::unique_ptr<cl_reshare_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_reshare_config cfg;
        cfg.cl                    = cl;
        cfg.D_signed = D_signed;
        cfg.old_n                 = 3;
        cfg.old_t_internal        = 2;
        cfg.old_contributors      = {0u, 1u, 2u};
        cfg.new_n                 = 2;
        cfg.new_t_internal        = 1;
        cfg.is_old_contributor    = true;
        cfg.old_local_id          = i;
        cfg.is_new_member         = (i < 2);
        cfg.new_local_id          = (i < 2) ? i : 0;
        cfg.old_pk_qfi            = dkg_results[0].ctx.pk_qfi;
        cfg.old_gammas_serialized = dkg_results[0].gammas_serialized;
        cfg.old_share_bytes       = dkg_results[i].local_secret_share;
        cfg.old_share_set_id      = 1;
        cfg.old_committee_id_hash.assign(32, 0xA1);
        cfg.new_committee_id_hash.assign(32, 0xB2);
        cfg.old_qualified_ids     = dkg_results[0].qualified_ids;
        cfg.new_member_pks        = new_pks;
        cfg.session_id            = dao_cl_reshare_compute_session_id(
            /*proposal_id=*/crypto::hash{},
            /*old_share_set_id=*/1,
            cfg.old_committee_id_hash,
            cfg.new_committee_id_hash,
            /*sorted_old_contributors=*/{0u, 1u, 2u});
        cfg.soundness_bytes       = 32;
        cfg.phase_timeout_seconds = 180;
        cfg.test_seed             = 6000 + i;
        runners.push_back(std::make_unique<cl_reshare_p2p_runner>(
            cfg, std::move(net2.endpoints[i])));
    }
    for (auto& r : runners) ASSERT_TRUE(r->start());

    std::vector<cl_reshare_result> results(3);
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(runners[i]->wait(results[i], 300))
            << "party " << i << " timeout";
        ASSERT_TRUE(results[i].ok)
            << "party " << i << " failed";
    }
    for (auto& r : runners) r->stop();
    runners.clear();

    // New members have their own new local share; old-only does not.
    EXPECT_TRUE(results[0].has_local_new_share);
    EXPECT_TRUE(results[1].has_local_new_share);
    EXPECT_FALSE(results[2].has_local_new_share);

    // All three end with identical public share-set metadata.
    EXPECT_FALSE(results[0].new_gammas_serialized.empty());
    EXPECT_EQ(results[0].new_gammas_serialized,
              results[1].new_gammas_serialized);
    EXPECT_EQ(results[0].new_gammas_serialized,
              results[2].new_gammas_serialized);
    EXPECT_EQ(results[0].qualified_ids, results[1].qualified_ids);
    EXPECT_EQ(results[0].qualified_ids, results[2].qualified_ids);
}

#endif // VEILROOT_ENABLE_CL
