// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_party.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"
#include "ringct/rctOps.h"

#include <array>
#include <memory>

using namespace cryptonote::dao;

namespace {

static std::shared_ptr<BICYCL::CL_HSMqk>
make_cl(BICYCL::RandGen& rng)
{
    std::array<uint8_t, 32> be{};
    const auto L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    BICYCL::Mpz q(std::vector<uint8_t>(be.begin(), be.end()));
    BICYCL::SecLevel sl(128);
    return std::make_shared<BICYCL::CL_HSMqk>(
        q, 1, sl, rng, BICYCL::CL_Params(static_cast<size_t>(128)));
}

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

static void run_inproc_keygen(
    std::vector<std::unique_ptr<CLCommitteeParty>>& ps,
    BICYCL::RandGen& rng)
{
    ASSERT_EQ(ps.size(), 3u);
    for (auto& p : ps) ASSERT_TRUE(p->keygen_dealing(rng));
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned j = 0; j < 3; ++j) {
            if (i == j) continue;
            ASSERT_TRUE(ps[j]->keygen_add_commitments(
                i, ps[i]->keygen_commitments()));
            ASSERT_TRUE(ps[j]->keygen_add_proof(
                i, ps[i]->keygen_batch_proof()));
        }
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned j = 0; j < 3; ++j) {
            if (i == j) continue;
            ASSERT_TRUE(ps[j]->keygen_add_share(i, ps[i]->keygen_y_k(j)));
        }
    for (auto& p : ps) ASSERT_TRUE(p->keygen_check_verify_all());
    for (auto& p : ps) ASSERT_TRUE(p->keygen_extract());
}

TEST(dao_cl_party_restore, restart_restores_share_and_decrypts)
{
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(424242UL));
    auto cl = make_cl(rng);
    ASSERT_TRUE(cl);

    std::vector<std::unique_ptr<CLCommitteeParty>> first;
    for (unsigned i = 0; i < 3; ++i)
        first.push_back(std::make_unique<CLCommitteeParty>(
            cl, 3, 1, i, 32));
    run_inproc_keygen(first, rng);

    struct saved_t {
        std::shared_ptr<BICYCL::CL_HSMqk::PublicKey> pk;
        BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI> gammas;
        BICYCL::CL_Threshold_Static::ParticipantsSet qualified;
        std::vector<uint8_t> sk_bytes;
    };
    std::vector<saved_t> saved(3);
    for (size_t i = 0; i < 3; ++i) {
        saved[i].pk = std::make_shared<BICYCL::CL_HSMqk::PublicKey>(
            first[i]->public_key());
        saved[i].gammas = first[i]->gammas();
        saved[i].qualified = first[i]->qualified_players();
        ASSERT_TRUE(first[i]->serialize_secret_share(saved[i].sk_bytes));
        ASSERT_FALSE(saved[i].sk_bytes.empty());
    }

    BICYCL::Mpz m_int(42UL);
    BICYCL::CL_HSMqk::ClearText m(*cl, m_int);
    auto ct = cl->encrypt(*saved[0].pk, m, rng);

    first.clear();

    std::vector<std::unique_ptr<CLCommitteeParty>> second;
    for (unsigned i = 0; i < 3; ++i) {
        second.push_back(std::make_unique<CLCommitteeParty>(
            cl, 3, 1, i, 32));
        BICYCL::Mpz share = decode_share(saved[i].sk_bytes);
        ASSERT_TRUE(second[i]->restore_decryption_state(
            *saved[i].pk, saved[i].gammas, saved[i].qualified, share))
            << "party " << i << " restore failed";
    }

    for (auto& p : second) ASSERT_TRUE(p->partial_decrypt(ct, rng));
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned j = 0; j < 3; ++j) {
            if (i == j) continue;
            second[j]->add_partial_dec(i, second[i]->partial());
        }
    for (auto& p : second) ASSERT_TRUE(p->verify_partials(rng));

    BICYCL::CL_HSMqk::ClearText got(*cl, BICYCL::Mpz(0UL));
    ASSERT_TRUE(second[0]->combine(got, ct));
    EXPECT_EQ(static_cast<BICYCL::Mpz>(got), m_int);
}

TEST(dao_cl_party_restore, wrong_share_rejected)
{
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(777UL));
    auto cl = make_cl(rng);
    ASSERT_TRUE(cl);

    std::vector<std::unique_ptr<CLCommitteeParty>> ps;
    for (unsigned i = 0; i < 3; ++i)
        ps.push_back(std::make_unique<CLCommitteeParty>(cl, 3, 1, i, 32));
    run_inproc_keygen(ps, rng);

    BICYCL::CL_HSMqk::PublicKey pk(ps[0]->public_key());
    auto gammas = ps[0]->gammas();
    auto qualified = ps[0]->qualified_players();

    std::vector<uint8_t> ok_bytes;
    ASSERT_TRUE(ps[0]->serialize_secret_share(ok_bytes));
    std::vector<uint8_t> bad = ok_bytes;
    ASSERT_GT(bad.size(), 5u);
    bad.back() ^= 0x01;
    BICYCL::Mpz tampered = decode_share(bad);

    auto fresh = std::make_unique<CLCommitteeParty>(cl, 3, 1, 0, 32);
    EXPECT_FALSE(fresh->restore_decryption_state(
        pk, gammas, qualified, tampered));
}

} // namespace

#endif // VEILROOT_ENABLE_CL
