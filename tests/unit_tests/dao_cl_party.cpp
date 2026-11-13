// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#ifdef VEILROOT_ENABLE_CL

#include <memory>
#include <vector>

#include "gtest/gtest.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include "governance/dao_cl_party.h"
#include "ringct/rctOps.h"

using namespace cryptonote;
using namespace cryptonote::dao;
using namespace BICYCL;

namespace {

constexpr unsigned long kSecLevel      = 128;
constexpr unsigned long kSoundnessB    = 16;
constexpr unsigned int  kCommitteeN    = 3;

std::shared_ptr<CL_HSMqk> make_cl(RandGen& rg)
{
    rct::key L = rct::curveOrder();
    std::array<uint8_t, 32> be{};
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    Mpz q(std::vector<unsigned char>(be.begin(), be.end()));
    std::random_device rd;
    rg.set_seed(Mpz(static_cast<unsigned long>(rd())));
    SecLevel sl(static_cast<int>(kSecLevel));
    return std::make_shared<CL_HSMqk>(q, 1, sl, rg, CL_Params{kSecLevel});
}

// Drive an in-process 3-of-2 keygen manually through CLCommitteeParty
// instances. Returns true on success, leaves pk in the parties.
bool drive_manual_keygen(
    const CL_HSMqk& CL,
    std::vector<std::unique_ptr<CLCommitteeParty>>& parties,
    RandGen& rg)
{
    for (auto& p : parties) if (!p->keygen_dealing(rg)) return false;
    for (unsigned int i = 0; i < kCommitteeN; ++i) {
        for (unsigned int j = 0; j < kCommitteeN; ++j) {
            if (i == j) continue;
            if (!parties[j]->keygen_add_commitments(
                    i, parties[i]->keygen_commitments())) return false;
            if (!parties[j]->keygen_add_proof(
                    i, parties[i]->keygen_batch_proof())) return false;
        }
    }
    for (unsigned int i = 0; i < kCommitteeN; ++i) {
        for (unsigned int j = 0; j < kCommitteeN; ++j) {
            if (i == j) continue;
            if (!parties[j]->keygen_add_share(
                    i, parties[i]->keygen_y_k(j))) return false;
        }
    }
    for (auto& p : parties) if (!p->keygen_check_verify_all()) return false;
    for (auto& p : parties) if (!p->keygen_extract()) return false;
    return true;
}

} // namespace

// ---- Ctor validation ----

TEST(dao_cl_party, rejects_null_cl)
{
    RandGen rg;
    EXPECT_THROW(CLCommitteeParty(nullptr, 3, 1, 0, kSoundnessB),
                 std::invalid_argument);
}

TEST(dao_cl_party, rejects_n_lt_2)
{
    RandGen rg;
    auto cl = make_cl(rg);
    EXPECT_THROW(CLCommitteeParty(cl, 1, 0, 0, kSoundnessB),
                 std::invalid_argument);
}

TEST(dao_cl_party, rejects_t_ge_n)
{
    RandGen rg;
    auto cl = make_cl(rg);
    EXPECT_THROW(CLCommitteeParty(cl, 3, 3, 0, kSoundnessB),
                 std::invalid_argument);
}

TEST(dao_cl_party, rejects_local_id_out_of_range)
{
    RandGen rg;
    auto cl = make_cl(rg);
    EXPECT_THROW(CLCommitteeParty(cl, 3, 1, 3, kSoundnessB),
                 std::invalid_argument);
}

TEST(dao_cl_party, rejects_zero_soundness)
{
    RandGen rg;
    auto cl = make_cl(rg);
    EXPECT_THROW(CLCommitteeParty(cl, 3, 1, 0, 0),
                 std::invalid_argument);
}

// ---- Manual 3-party keygen ----

TEST(dao_cl_party, keygen_three_parties_agree_on_pk)
{
    RandGen rg;
    auto cl = make_cl(rg);
    std::vector<std::unique_ptr<CLCommitteeParty>> parties;
    for (unsigned int i = 0; i < kCommitteeN; ++i)
        parties.push_back(std::make_unique<CLCommitteeParty>(
            cl, kCommitteeN, 1, i, kSoundnessB));

    ASSERT_TRUE(drive_manual_keygen(*cl, parties, rg));
    for (auto& p : parties) {
        EXPECT_TRUE(p->keygen_done());
        EXPECT_EQ(p->public_key().elt(), parties[0]->public_key().elt());
    }
}

// ---- Public key throws before extract ----

TEST(dao_cl_party, public_key_throws_before_keygen)
{
    RandGen rg;
    auto cl = make_cl(rg);
    CLCommitteeParty p(cl, kCommitteeN, 1, 0, kSoundnessB);
    EXPECT_THROW(p.public_key(), std::logic_error);
}

// ---- End-to-end decrypt through 2-of-3 subset ----

TEST(dao_cl_party, two_of_three_parties_decrypt_a_ciphertext)
{
    RandGen rg;
    auto cl = make_cl(rg);
    std::vector<std::unique_ptr<CLCommitteeParty>> parties;
    for (unsigned int i = 0; i < kCommitteeN; ++i)
        parties.push_back(std::make_unique<CLCommitteeParty>(
            cl, kCommitteeN, 1, i, kSoundnessB));

    ASSERT_TRUE(drive_manual_keygen(*cl, parties, rg));

    // Encrypt under committee pk.
    Mpz W(12345UL);
    CL_HSMqk::ClearText pt(*cl, W);
    CL_HSMqk::CipherText ct = cl->encrypt(parties[0]->public_key(), pt, rg);

    // Parties 0 and 1 produce partials, exchange, verify, combine.
    ASSERT_TRUE(parties[0]->partial_decrypt(ct, rg));
    ASSERT_TRUE(parties[1]->partial_decrypt(ct, rg));

    parties[0]->add_partial_dec(1, parties[1]->partial());
    parties[1]->add_partial_dec(0, parties[0]->partial());

    ASSERT_TRUE(parties[0]->verify_partials(rg));
    ASSERT_TRUE(parties[1]->verify_partials(rg));

    CL_HSMqk::ClearText out0(*cl, Mpz(0UL));
    CL_HSMqk::ClearText out1(*cl, Mpz(0UL));
    ASSERT_TRUE(parties[0]->combine(out0, ct));
    ASSERT_TRUE(parties[1]->combine(out1, ct));

    Mpz recovered0 = static_cast<Mpz>(out0);
    Mpz recovered1 = static_cast<Mpz>(out1);
    EXPECT_EQ(recovered0, W);
    EXPECT_EQ(recovered1, W);
}

// ---- Different subsets decrypt the same value ----

TEST(dao_cl_party, alternate_subset_decrypts_same_value)
{
    RandGen rg;
    auto cl = make_cl(rg);
    std::vector<std::unique_ptr<CLCommitteeParty>> parties;
    for (unsigned int i = 0; i < kCommitteeN; ++i)
        parties.push_back(std::make_unique<CLCommitteeParty>(
            cl, kCommitteeN, 1, i, kSoundnessB));

    ASSERT_TRUE(drive_manual_keygen(*cl, parties, rg));

    Mpz W(54321UL);
    CL_HSMqk::ClearText pt(*cl, W);
    CL_HSMqk::CipherText ct = cl->encrypt(parties[0]->public_key(), pt, rg);

    // Parties 0 and 2 (different subset from the previous test).
    ASSERT_TRUE(parties[0]->partial_decrypt(ct, rg));
    ASSERT_TRUE(parties[2]->partial_decrypt(ct, rg));

    parties[0]->add_partial_dec(2, parties[2]->partial());
    parties[2]->add_partial_dec(0, parties[0]->partial());

    ASSERT_TRUE(parties[0]->verify_partials(rg));
    ASSERT_TRUE(parties[2]->verify_partials(rg));

    CL_HSMqk::ClearText out(*cl, Mpz(0UL));
    ASSERT_TRUE(parties[0]->combine(out, ct));
    EXPECT_EQ(static_cast<Mpz>(out), W);
}

#endif // VEILROOT_ENABLE_CL
