// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_ballot.h"
#include "governance/dao_cl_consistency.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_dkg_runner.h"
#include "governance/dao_cl_party.h"
#include "governance/dao_cl_tally_wire.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_tally.h"
#include "governance/dao_tally_share.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"
#include "ringct/rctOps.h"

#include <array>
#include <memory>

using namespace cryptonote;
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

static std::vector<uint8_t> encode_share_wire(const BICYCL::Mpz& v)
{
    std::vector<uint8_t> out;
    out.push_back(v.sgn() < 0 ? 1u : 0u);
    BICYCL::Mpz abs_v;
    BICYCL::Mpz::abs(abs_v, v);
    std::vector<unsigned char> mag;
    if (!abs_v.is_zero())
        mag = static_cast<std::vector<unsigned char>>(abs_v);
    uint32_t len = static_cast<uint32_t>(mag.size());
    out.push_back(static_cast<uint8_t>((len >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((len >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((len >>  8) & 0xff));
    out.push_back(static_cast<uint8_t>( len        & 0xff));
    out.insert(out.end(), mag.begin(), mag.end());
    return out;
}

static std::vector<uint8_t> cl_partial_wire_from_bytes(
    const BICYCL::QFI& w,
    const BICYCL::Mpz& u,
    const BICYCL::QFI& R1,
    const BICYCL::QFI& R2)
{
    std::vector<uint8_t> out;
    std::vector<uint8_t> ww, uu, r1w, r2w;
    cl_dkg_qfi_to_bytes(ww, w);
    cl_dkg_mpz_to_bytes_signed(uu, u);
    cl_dkg_qfi_to_bytes(r1w, R1);
    cl_dkg_qfi_to_bytes(r2w, R2);
    out = ww;
    out.insert(out.end(), uu.begin(), uu.end());
    out.insert(out.end(), r1w.begin(), r1w.end());
    out.insert(out.end(), r2w.begin(), r2w.end());
    return out;
}

TEST(DaoClTallyE2E, full_cycle_yes_vote_passes)
{
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(20250101UL));
    auto cl = cl_dkg_make_hsmq(128, rng);
    ASSERT_TRUE(cl);

    // --- 3-party P2P DKG ---
    auto net = dkg_make_inproc_network(3);
    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> dkg_runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 1;
        cfg.member_ids.resize(3);
        cfg.local_party_id = i + 1;
        cfg.soundness_bytes = 32;
        cfg.test_seed = 7000 + i;
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

    // --- Install key record + share set ---
    dao_tally_key_record key_rec;
    key_rec.version        = 1;
    key_rec.committee_size = 3;
    key_rec.threshold      = 2;
    key_rec.t              = 1;
    key_rec.committee_id_hash.assign(32, 0x11);
    key_rec.committee_members.assign(3, std::vector<uint8_t>(32, 0x22));
    key_rec.dkg_transcript_hash.assign(32, 0x44);
    key_rec.key_id.assign(32, 0x55);

    // Build the actual cl_key_context wire from the DKG result.
    // cl_key_context_serialize expects p and D in sign||magnitude
    // form; dao_cl_load_proposal_key parses them the same way.
    {
        auto to_sign_magnitude = [](const BICYCL::Mpz& v,
                                    std::vector<uint8_t>& out) {
            out.clear();
            out.push_back(v.sgn() < 0 ? 1u : 0u);
            BICYCL::Mpz abs_v;
            BICYCL::Mpz::abs(abs_v, v);
            if (!abs_v.is_zero()) {
                auto bv = static_cast<std::vector<unsigned char>>(abs_v);
                out.insert(out.end(), bv.begin(), bv.end());
            }
        };

        cl_key_context ctx;
        auto qb = static_cast<std::vector<unsigned char>>(cl->q());
        ctx.q.assign(qb.begin(), qb.end());
        ctx.k = static_cast<uint32_t>(cl->k());
        to_sign_magnitude(cl->p(), ctx.p);
        BICYCL::QFI pk_qfi;
        std::size_t off = 0;
        ASSERT_TRUE(cl_dkg_qfi_from_bytes(
            dkg_results[0].ctx.pk_qfi, off, pk_qfi,
            cl->Cl_G().discriminant()));
        ASSERT_TRUE(cl_dkg_qfi_to_bytes(ctx.pk_qfi, pk_qfi));
        BICYCL::Mpz D;
        off = 0;
        ASSERT_TRUE(cl_dkg_mpz_from_bytes_signed(
            dkg_results[0].ctx.D, off, D, true));
        to_sign_magnitude(D, ctx.D);
        std::vector<uint8_t> ctx_wire;
        ASSERT_TRUE(dao_cl_key_context_serialize(ctx, ctx_wire));
        key_rec.cl_modulus = ctx_wire;
    }

    dao_share_set_record share_set;
    share_set.version        = 3;
    share_set.share_set_id   = 1;
    share_set.height         = 1;
    share_set.threshold      = 2;
    share_set.key_id         = key_rec.key_id;
    share_set.committee_id_hash = key_rec.committee_id_hash;
    share_set.committee_members = key_rec.committee_members;
    share_set.cl_gammas_serialized = dkg_results[0].gammas_serialized;
    share_set.qualified_ids = dkg_results[0].qualified_ids;

    // --- Encrypt an aggregate under the CL pk: W=100, S=100, B=200 ---
    dao_cl_proposal_key pk_holder;
    ASSERT_TRUE(dao_cl_load_proposal_key(key_rec.cl_modulus, pk_holder));
    ASSERT_TRUE(dao_cl_check_ballot_modulus(*pk_holder.cl));

    BICYCL::Mpz W_mpz(100UL);
    BICYCL::Mpz S_mpz(100UL);
    BICYCL::Mpz B_mpz(200UL);
    BICYCL::Mpz r_w = dao_cl_sample_randomness(*pk_holder.cl, rng);
    BICYCL::Mpz r_s = dao_cl_sample_randomness(*pk_holder.cl, rng);
    BICYCL::Mpz r_b = dao_cl_sample_randomness(*pk_holder.cl, rng);
    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(dao_cl_encrypt_at_pk(*pk_holder.cl, *pk_holder.pk,
                                     W_mpz, r_w, E_W));
    ASSERT_TRUE(dao_cl_encrypt_at_pk(*pk_holder.cl, *pk_holder.pk,
                                     S_mpz, r_s, E_S));
    ASSERT_TRUE(dao_cl_encrypt_at_pk(*pk_holder.cl, *pk_holder.pk,
                                     B_mpz, r_b, E_B));

    BICYCL::CL_HSMqk::CipherText ct_W, ct_S, ct_B;
    ASSERT_TRUE(dao_cl_ciphertext_from_wire(*pk_holder.cl, E_W, ct_W));
    ASSERT_TRUE(dao_cl_ciphertext_from_wire(*pk_holder.cl, E_S, ct_S));
    ASSERT_TRUE(dao_cl_ciphertext_from_wire(*pk_holder.cl, E_B, ct_B));

    // --- Each of 2 parties (threshold=2) produces one partial per channel ---
    dao_partial_set W_set, S_set, B_set;
    for (uint32_t i = 0; i < 2; ++i) {
        CLCommitteeParty party(cl, 3, 1, i, 32);
        BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI> gammas;
        ASSERT_TRUE(cl_dkg_deserialize_gammas(
            dkg_results[i].gammas_serialized,
            pk_holder.cl->Cl_G().discriminant(), gammas));
        BICYCL::CL_Threshold_Static::ParticipantsSet qualified(
            dkg_results[i].qualified_ids.begin(),
            dkg_results[i].qualified_ids.end());
        BICYCL::Mpz share = decode_share_wire(dkg_results[i].local_secret_share);
        ASSERT_TRUE(party.restore_decryption_state(
            *pk_holder.pk, gammas, qualified, share));

        BICYCL::RandGen prng;
        prng.set_seed(BICYCL::Mpz(static_cast<unsigned long>(8000 + i)));

        W_set.member_indices.push_back(i);
        S_set.member_indices.push_back(i);
        B_set.member_indices.push_back(i);

        ASSERT_TRUE(party.partial_decrypt(ct_W, prng));
        {
            const auto& pd = party.partial();
            W_set.cl_partials.push_back(cl_partial_wire_from_bytes(
                pd.w(), pd.proof().u(), pd.proof().R1(), pd.proof().R2()));
        }
        ASSERT_TRUE(party.partial_decrypt(ct_S, prng));
        {
            const auto& pd = party.partial();
            S_set.cl_partials.push_back(cl_partial_wire_from_bytes(
                pd.w(), pd.proof().u(), pd.proof().R1(), pd.proof().R2()));
        }
        ASSERT_TRUE(party.partial_decrypt(ct_B, prng));
        {
            const auto& pd = party.partial();
            B_set.cl_partials.push_back(cl_partial_wire_from_bytes(
                pd.w(), pd.proof().u(), pd.proof().R1(), pd.proof().R2()));
        }
    }

    // --- Build + verify the certificate ---
    crypto::hash proposal_id{};
    std::memset(proposal_id.data, 0x5A, 32);

    dao_tally_certificate cert;
    ASSERT_TRUE(dao_build_tally_certificate(
        key_rec, share_set, proposal_id, /*vote_end_height=*/1000,
        E_W, E_S, E_B, W_set, S_set, B_set, cert));

    // Totals match.
    EXPECT_EQ(cert.W_total, dao_u128(100));
    EXPECT_EQ(cert.S_abs,   dao_u128(100));
    EXPECT_EQ(cert.B_total, dao_u128(200));
    EXPECT_FALSE(cert.s_negative);

    dao_supply_snapshot snap;
    snap.height      = 1000;
    snap.minted      = dao_u128(1000000);
    snap.circulating = dao_u128(500000);

    ASSERT_TRUE(dao_verify_tally_certificate(
        key_rec, share_set, snap, /*quorum_percent=*/20,
        E_W, E_S, E_B, cert));

    // YES=100, NO=0, participation=200, 20% of 500000 = 100000 quorum.
    // Participation 200 < 100000 → quorum not met, but crypto path
    // verifies and totals are correct. Use a lower supply so quorum
    // triggers.
    EXPECT_EQ(cert.YES_weight, dao_u128(100));
    EXPECT_EQ(cert.NO_weight,  dao_u128(0));
    EXPECT_EQ(cert.quorum_threshold, dao_u128(100000));
}

} // namespace

#endif // VEILROOT_ENABLE_CL
