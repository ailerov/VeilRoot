// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#ifdef VEILROOT_ENABLE_CL

#include <cstring>
#include <memory>
#include <vector>

#include "gtest/gtest.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"

#include "governance/dao_cl_reshare.h"
#include "ringct/rctOps.h"

using namespace cryptonote;
using namespace cryptonote::dao;
using namespace BICYCL;

namespace {

constexpr unsigned long kSecLevel     = 128;
constexpr unsigned long kSoundness    = 16;

std::shared_ptr<CL_HSMqk> make_cl(RandGen& randgen)
{
    rct::key L = rct::curveOrder();
    std::array<uint8_t, 32> be{};
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    Mpz q(std::vector<unsigned char>(be.begin(), be.end()));
    std::random_device rd;
    randgen.set_seed(Mpz(static_cast<unsigned long>(rd())));
    SecLevel sl(static_cast<int>(kSecLevel));
    return std::make_shared<CL_HSMqk>(q, 1, sl, randgen, CL_Params{kSecLevel});
}

// Run DKG across the given players (full flow, in-process).
bool run_dkg(const CL_HSMqk& CL,
             std::vector<std::unique_ptr<CL_Threshold_Static>>& players,
             unsigned int n, RandGen& randgen)
{
    try {
        for (auto& p : players) p->keygen_dealing(CL, randgen);
        for (unsigned int i = 0; i < n; ++i) {
            for (unsigned int j = 0; j < n; ++j) {
                if (i == j) continue;
                players[j]->keygen_add_commitments(i, players[i]->C());
                players[j]->keygen_add_proof(i, players[i]->batch_proof());
            }
        }
        for (unsigned int i = 0; i < n; ++i) {
            for (unsigned int j = 0; j < n; ++j) {
                if (i == j) continue;
                players[j]->keygen_add_share(i, players[i]->y_k(j));
            }
        }
        for (auto& p : players)
            if (!p->keygen_check_verify_all_players(CL)) return false;
        for (auto& p : players)
            p->keygen_extract(CL);
        return true;
    }
    catch (...) {
        return false;
    }
}

std::vector<std::unique_ptr<CL_Threshold_Static>>
make_players(const CL_HSMqk& CL, unsigned int n, unsigned int t,
             const Mpz& D)
{
    std::vector<std::unique_ptr<CL_Threshold_Static>> v;
    for (unsigned int i = 0; i < n; ++i)
        v.push_back(std::make_unique<CL_Threshold_Static>(
            CL, n, t, i, kSoundness, D));
    return v;
}

Mpz factorial_of(unsigned int x)
{
    Mpz out;
    Mpz::factorial(out, x);
    return out;
}

// Run the threshold decryption protocol among a subset of players.
bool decrypt_with_subset(
    const CL_HSMqk& CL,
    std::vector<std::unique_ptr<CL_Threshold_Static>>& players,
    const std::vector<unsigned int>& subset,
    const CL_HSMqk::CipherText& ct,
    RandGen& randgen,
    Mpz& plaintext_out,
    std::string* err = nullptr)
{
    try {
        for (unsigned int i : subset)
            players[i]->decrypt_partial(CL, randgen, ct);
    } catch (const std::exception& e) {
        if (err) *err = std::string("step1_partial: ") + e.what();
        return false;
    }
    try {
        for (unsigned int i : subset) {
            for (unsigned int j : subset) {
                if (i == j) continue;
                players[i]->decrypt_add_partial_dec(j, players[j]->part_dec());
            }
        }
    } catch (const std::exception& e) {
        if (err) *err = std::string("step2_add: ") + e.what();
        return false;
    }
    try {
        for (unsigned int i : subset)
            if (!players[i]->decrypt_verify_batch(CL, randgen)) {
                if (err) *err = "step3_verify: batch returned false";
                return false;
            }
    } catch (const std::exception& e) {
        if (err) *err = std::string("step3_verify: ") + e.what();
        return false;
    }
    try {
        CL_HSMqk::ClearText m(CL, Mpz(0UL));
        players[subset[0]]->decrypt_combine(m, CL, ct);
        plaintext_out = static_cast<Mpz>(m);
    } catch (const std::exception& e) {
        if (err) *err = std::string("step4_combine: ") + e.what();
        return false;
    }
    return true;
}

// Common fixture-style helper: DKG-old, encrypt, reshare, decrypt-with-new.
struct Scenario
{
    std::shared_ptr<CL_HSMqk> cl;
    std::vector<std::unique_ptr<CL_Threshold_Static>> old_players;
    std::vector<std::unique_ptr<CL_Threshold_Static>> new_players;
    QFI pk_old;
    std::vector<unsigned int> old_contributors;
    unsigned int n_old, t_old, n_new, t_new;
    RandGen rg;
};

bool setup_scenario(Scenario& s,
                    unsigned int n_old, unsigned int t_old,
                    unsigned int n_new, unsigned int t_new)
{
    s.cl = make_cl(s.rg);
    s.n_old = n_old; s.t_old = t_old;
    s.n_new = n_new; s.t_new = t_new;
    // Fixed key-lifetime interpolation scale D = max(n_old, n_new)!.
    // Ensures Lagrange coefficients are integral at both sizes.
    Mpz D = factorial_of(n_old > n_new ? n_old : n_new);
    s.old_players = make_players(*s.cl, n_old, t_old, D);
    if (!run_dkg(*s.cl, s.old_players, n_old, s.rg)) return false;
    s.pk_old = s.old_players[0]->pk().elt();
    s.old_contributors.clear();
    for (unsigned int i = 0; i <= t_old; ++i) s.old_contributors.push_back(i);
    s.new_players = make_players(*s.cl, n_new, t_new, D);
    return true;
}

bool do_reshare(Scenario& s, std::string* err_out = nullptr)
{
    dao_cl_reshare_params p;
    p.n_old = s.n_old; p.t_old = s.t_old;
    p.n_new = s.n_new; p.t_new = s.t_new;
    p.old_contributors = s.old_contributors;
    p.soundness_bytes = kSoundness;
    std::string err;
    bool ok = dao_cl_reshare_inproc(*s.cl, s.old_players, s.new_players, p, s.rg, &err);
    if (err_out) *err_out = err;
    return ok;
}

} // namespace

// ---- Acceptance tests ----

TEST(dao_cl_reshare, pk_preserved_same_size)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 3, 1));
    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }
    for (auto& np : s.new_players)
        EXPECT_EQ(np->pk().elt(), s.pk_old);
}

TEST(dao_cl_reshare, pk_preserved_larger_committee)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 5, 2));
    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }
    for (auto& np : s.new_players)
        EXPECT_EQ(np->pk().elt(), s.pk_old);
}

TEST(dao_cl_reshare, pk_preserved_smaller_committee)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 5, 2, 3, 1));
    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }
    for (auto& np : s.new_players)
        EXPECT_EQ(np->pk().elt(), s.pk_old);
}

TEST(dao_cl_reshare, pk_preserved_different_threshold)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 2, 3, 1));
    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }
    for (auto& np : s.new_players)
        EXPECT_EQ(np->pk().elt(), s.pk_old);
}

TEST(dao_cl_reshare, pk_preserved_3to6_of_4)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 6, 3));
    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }
    for (auto& np : s.new_players)
        EXPECT_EQ(np->pk().elt(), s.pk_old);
}

// ---- Ciphertext survival across reshare ----

TEST(dao_cl_reshare, old_ciphertext_decryptable_by_new_committee_same_size)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 3, 1));

    // Encrypt under old pk.
    Mpz plaintext(54321UL);
    CL_HSMqk::ClearText m(*s.cl, plaintext);
    CL_HSMqk::CipherText ct = s.cl->encrypt(s.old_players[0]->pk(), m, s.rg);

    // Reshare.
    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }

    // Decrypt with new committee (any t_new+1 subset).
    std::vector<unsigned int> subset = {0, 1};
    Mpz recovered;
    std::string derr;
    ASSERT_TRUE(decrypt_with_subset(
        *s.cl, s.new_players, subset, ct, s.rg, recovered, &derr)) << derr;
    EXPECT_EQ(recovered, plaintext);
}

TEST(dao_cl_reshare, old_ciphertext_decryptable_by_new_committee_larger)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 5, 2));

    Mpz plaintext(99999UL);
    CL_HSMqk::ClearText m(*s.cl, plaintext);
    CL_HSMqk::CipherText ct = s.cl->encrypt(s.old_players[0]->pk(), m, s.rg);

    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }

    // Any 3-of-5 subset (t_new + 1 = 3).
    std::vector<unsigned int> subset = {0, 2, 4};
    Mpz recovered;
    ASSERT_TRUE(decrypt_with_subset(
        *s.cl, s.new_players, subset, ct, s.rg, recovered));
    EXPECT_EQ(recovered, plaintext);
}

TEST(dao_cl_reshare, old_ciphertext_decryptable_by_new_committee_smaller)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 5, 2, 3, 1));

    Mpz plaintext(12345UL);
    CL_HSMqk::ClearText m(*s.cl, plaintext);
    CL_HSMqk::CipherText ct = s.cl->encrypt(s.old_players[0]->pk(), m, s.rg);

    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }

    std::vector<unsigned int> subset = {0, 1};
    Mpz recovered;
    ASSERT_TRUE(decrypt_with_subset(
        *s.cl, s.new_players, subset, ct, s.rg, recovered));
    EXPECT_EQ(recovered, plaintext);
}

TEST(dao_cl_reshare, different_new_subsets_all_decrypt)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 3, 1));

    Mpz plaintext(777UL);
    CL_HSMqk::ClearText m(*s.cl, plaintext);
    CL_HSMqk::CipherText ct = s.cl->encrypt(s.old_players[0]->pk(), m, s.rg);

    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }

    for (auto& subset : std::vector<std::vector<unsigned int>>{
             {0, 1}, {0, 2}, {1, 2}}) {
        Mpz recovered;
        ASSERT_TRUE(decrypt_with_subset(
            *s.cl, s.new_players, subset, ct, s.rg, recovered));
        EXPECT_EQ(recovered, plaintext);
    }
}

TEST(dao_cl_reshare, below_threshold_subset_fails)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 5, 2, 5, 2));

    Mpz plaintext(1234UL);
    CL_HSMqk::ClearText m(*s.cl, plaintext);
    CL_HSMqk::CipherText ct = s.cl->encrypt(s.old_players[0]->pk(), m, s.rg);

    { std::string err; ASSERT_TRUE(do_reshare(s, &err)) << err; }

    // t_new + 1 = 3 required; try with only 2.
    std::vector<unsigned int> subset = {0, 1};
    Mpz recovered;
    EXPECT_FALSE(decrypt_with_subset(
        *s.cl, s.new_players, subset, ct, s.rg, recovered));
}

// ---- Rejection tests ----

TEST(dao_cl_reshare, wrong_contributor_count_rejected)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 3, 1));
    // t_old + 1 = 2, but we supply 1.
    s.old_contributors = {0};
    EXPECT_FALSE(do_reshare(s));
}

TEST(dao_cl_reshare, contributor_index_out_of_range_rejected)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 3, 1));
    s.old_contributors = {0, 99};
    EXPECT_FALSE(do_reshare(s));
}

TEST(dao_cl_reshare, wrong_n_old_rejected)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 3, 1));
    s.n_old = 4;  // mismatches actual players count
    EXPECT_FALSE(do_reshare(s));
}

TEST(dao_cl_reshare, wrong_n_new_rejected)
{
    Scenario s;
    ASSERT_TRUE(setup_scenario(s, 3, 1, 3, 1));
    s.n_new = 4;
    EXPECT_FALSE(do_reshare(s));
}

TEST(dao_cl_reshare, tampered_contribution_share_rejected)
{
    auto rg_ptr = std::make_shared<RandGen>();
    auto cl = make_cl(*rg_ptr);
    Mpz D = factorial_of(3);
    auto old_players = make_players(*cl, 3, 1, D);
    ASSERT_TRUE(run_dkg(*cl, old_players, 3, *rg_ptr));
    auto new_players = make_players(*cl, 3, 1, D);

    CL_Threshold_Static::ParticipantsSet old_set = {0, 1};
    // Two-pass: compute prestates, R, assign c_i
    auto pre0 = old_players[0]->compute_reshare_prestate(old_set);
    auto pre1 = old_players[1]->compute_reshare_prestate(old_set);
    Mpz D2; Mpz::mul(D2, D, D);
    Mpz r_sum; Mpz::add(r_sum, pre0.r_i, pre1.r_i);
    Mpz R, rem; Mpz::fdiv_qr(R, rem, r_sum, D2);
    ASSERT_TRUE(rem.is_zero());
    Mpz c0_val(0UL), c1_val = R;  // lowest ID (0) gets R

    auto c0 = old_players[0]->create_reshare_contribution(
        *cl, old_set, 3, 1, *rg_ptr, c0_val);
    auto c1 = old_players[1]->create_reshare_contribution(
        *cl, old_set, 3, 1, *rg_ptr, c1_val);
    const auto& gamma = old_players[0]->Gammas(); (void)gamma;

    for (auto& np : new_players)
        np->begin_reshare(old_set, 3, 1);

    // Deliver c0 correctly.
    for (unsigned int j = 0; j < 3; ++j) {
        new_players[j]->add_reshare_contribution(
            *cl, 0, c0.shares[j], c0.c_i, c0.r_i, c0.L_i,
            c0.commitments, *c0.batch_proof, *c0.old_share_link_proof,
            gamma.at(0));
    }
    // Deliver c1 with corrupted share to player 2 - expect VSS rejection.
    Mpz bad_share = c1.shares[2];
    Mpz::add(bad_share, bad_share, Mpz(1UL));
    for (unsigned int j = 0; j < 3; ++j) {
        Mpz share = (j == 2) ? bad_share : c1.shares[j];
        if (j == 2) {
            EXPECT_THROW(
                new_players[j]->add_reshare_contribution(
                    *cl, 1, share, c1.c_i, c1.r_i, c1.L_i,
                    c1.commitments, *c1.batch_proof,
                    *c1.old_share_link_proof, gamma.at(1)),
                std::invalid_argument);
        } else {
            new_players[j]->add_reshare_contribution(
                *cl, 1, share, c1.c_i, c1.r_i, c1.L_i,
                c1.commitments, *c1.batch_proof,
                *c1.old_share_link_proof, gamma.at(1));
        }
    }
}

TEST(dao_cl_reshare, duplicate_contribution_rejected)
{
    auto rg = RandGen();
    auto cl = make_cl(rg);
    Mpz D = factorial_of(3);
    auto old_players = make_players(*cl, 3, 1, D);
    ASSERT_TRUE(run_dkg(*cl, old_players, 3, rg));
    auto new_players = make_players(*cl, 3, 1, D);

    CL_Threshold_Static::ParticipantsSet old_set = {0, 1};
    auto pre0 = old_players[0]->compute_reshare_prestate(old_set);
    auto pre1 = old_players[1]->compute_reshare_prestate(old_set);
    Mpz D2; Mpz::mul(D2, D, D);
    Mpz r_sum; Mpz::add(r_sum, pre0.r_i, pre1.r_i);
    Mpz R, rem; Mpz::fdiv_qr(R, rem, r_sum, D2);
    ASSERT_TRUE(rem.is_zero());
    Mpz c0_val(0UL), c1_val = R;

    auto c0 = old_players[0]->create_reshare_contribution(
        *cl, old_set, 3, 1, rg, c0_val);
    const auto& gamma = old_players[0]->Gammas(); (void)gamma;

    for (auto& np : new_players)
        np->begin_reshare(old_set, 3, 1);

    new_players[0]->add_reshare_contribution(
        *cl, 0, c0.shares[0], c0.c_i, c0.r_i, c0.L_i,
        c0.commitments, *c0.batch_proof, *c0.old_share_link_proof,
        gamma.at(0));
    EXPECT_THROW(
        new_players[0]->add_reshare_contribution(
            *cl, 0, c0.shares[0], c0.c_i, c0.r_i, c0.L_i,
            c0.commitments, *c0.batch_proof, *c0.old_share_link_proof,
            gamma.at(0)),
        std::invalid_argument);
}

#endif // VEILROOT_ENABLE_CL
