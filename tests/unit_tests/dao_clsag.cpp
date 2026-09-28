// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "governance/dao_clsag.h"

using namespace cryptonote;

namespace {

rct::key hex_to_key(const char* hex)
{
    rct::key k;
    for (int i = 0; i < 32; ++i)
    {
        auto hv = [](char c)->int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return 0;
        };
        k.bytes[i] = static_cast<uint8_t>((hv(hex[2*i]) << 4) | hv(hex[2*i + 1]));
    }
    return k;
}

crypto::hash hex_to_hash(const char* hex)
{
    crypto::hash h;
    for (int i = 0; i < 32; ++i)
    {
        auto hv = [](char c)->int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return 0;
        };
        h.data[i] = static_cast<char>((hv(hex[2*i]) << 4) | hv(hex[2*i + 1]));
    }
    return h;
}

crypto::secret_key sec_from_hex(const char* hex)
{
    crypto::secret_key sk;
    rct::key k = hex_to_key(hex);
    std::memcpy(sk.data, k.bytes, 32);
    return sk;
}

dao_clsag_context make_reference_context()
{
    dao_clsag_context ctx;
    ctx.proposal_id = hex_to_hash(
        "3333333333333333333333333333333333333333333333333333333333333333");
    ctx.proposal_submission_height = 50000;
    ctx.vote_height                = 51000;
    ctx.tally_key_epoch            = 1;

    ctx.P = {
        hex_to_key("4228dd6dce46fdb1dff47cc02f1a483fe0e9dabe16bc84a37199e25c403d2fa4"),
        hex_to_key("a3d2cbfd994ca1a2924bc653f34fb140f8b4352f6c40925385d192ca086bb75f"),
        hex_to_key("6435b6953c351a7fc49f74342d93ff02912d153478ec8bdb7a4f599c5323b7ef"),
        hex_to_key("b6e00c6dbbc2b25cfd33a6ccf155c28b3079788ab26b3738dad40197bed183eb")
    };
    ctx.C = {
        hex_to_key("b57a663175174bd4f3723dfc772f69f9bc2dbf295c8ce25f1695155dd0056725"),
        hex_to_key("f1a55d19372a38adebcad8e9f57127365073db9256c69ade3d7c3ab32c88b6e8"),
        hex_to_key("d28b43dcab95a38ce5f4a50bef0f3edf1c6a7aa8490c2bafa3160efb8b11f240"),
        hex_to_key("38f8a87b0db7c0c06590a5d53e1d90a7a57f616ac595b1e8a1dce8d4cd76ffd8")
    };
    ctx.output_indices = { 1000, 2000, 3000, 4000 };
    ctx.output_heights = { 40000, 30000, 20000, 10000 };
    ctx.age_factors    = { 4, 4, 5, 5 };

    ctx.V = hex_to_key(
        "59467a19f14c01373af9035a1deb909e988a00316e1ea2b60d2c8e55ad98fe6c");
    return ctx;
}

rct::clsag make_reference_sig()
{
    rct::clsag sig;
    sig.s  = {
        hex_to_key("44117aa4c35a23dff3a5645c90498c05ffffffffffffffffffffffffffffff04"),
        hex_to_key("45117aa4c35a23dff3a5645c90498c05ffffffffffffffffffffffffffffff03"),
        hex_to_key("1f990fe59996a27b6f0093c30bbbc9fe21088e23f71dad9012a36ea36e3f4f05"),
        hex_to_key("47117aa4c35a23dff3a5645c90498c05ffffffffffffffffffffffffffffff05")
    };
    sig.c1 = hex_to_key("4e888978058f670f1bbe6e4fa652aab93d28131c00f9ac3146c02b95f266c306");
    sig.I  = hex_to_key("35e281077984811952d31d39fa7103ba11dae6cd1befb0712016fb10e9ce4eca");
    sig.D  = hex_to_key("1c96b01c70452fea17a029c5cae0f3e7d72dc81c22a9f71c214f4c5226fe5443");
    return sig;
}

const char* X_L_HEX =
    "e3e46f01debd3537ca425cff6e436b1affffffffffffffffffffffffffffff06";
const char* RHO_HEX =
    "4a698eea8e94fe2e476c7516d355cedbfeffffffffffffffffffffffffffff04";

} // namespace

// ---- Positive ----

TEST(dao_clsag, reference_vector_verifies)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    EXPECT_TRUE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, generate_then_verify)
{
    auto ctx = make_reference_context();
    crypto::secret_key sk = sec_from_hex(X_L_HEX);
    rct::key rho = hex_to_key(RHO_HEX);

    rct::clsag sig;
    ASSERT_TRUE(dao_clsag_generate(ctx, 2, sk, rho, sig));
    EXPECT_EQ(sig.I, hex_to_key(
        "35e281077984811952d31d39fa7103ba11dae6cd1befb0712016fb10e9ce4eca"));
    EXPECT_TRUE(dao_clsag_verify(ctx, sig));
}

// ---- Nullifier scope ----

TEST(dao_clsag, different_proposal_different_nullifier)
{
    auto ctx_a = make_reference_context();
    auto ctx_b = make_reference_context();
    ctx_b.proposal_id = hex_to_hash(
        "4444444444444444444444444444444444444444444444444444444444444444");

    crypto::secret_key sk = sec_from_hex(X_L_HEX);
    rct::key rho = hex_to_key(RHO_HEX);

    rct::clsag sig_a, sig_b;
    ASSERT_TRUE(dao_clsag_generate(ctx_a, 2, sk, rho, sig_a));
    ASSERT_TRUE(dao_clsag_generate(ctx_b, 2, sk, rho, sig_b));

    EXPECT_FALSE(sig_a.I == sig_b.I);
    EXPECT_TRUE(dao_clsag_verify(ctx_a, sig_a));
    EXPECT_TRUE(dao_clsag_verify(ctx_b, sig_b));
}

// ---- Tamper: signature fields ----

TEST(dao_clsag, tamper_signature_I_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    sig.I = hex_to_key(
        "1111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_signature_D_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    sig.D = hex_to_key(
        "2222222222222222222222222222222222222222222222222222222222222222");
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_signature_c1_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    sig.c1 = hex_to_key(
        "3333333333333333333333333333333333333333333333333333333333333333");
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_signature_s_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    sig.s[2] = hex_to_key(
        "5555555555555555555555555555555555555555555555555555555555555555");
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

// ---- Tamper: context ----

TEST(dao_clsag, tamper_proposal_id_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.proposal_id = hex_to_hash(
        "6666666666666666666666666666666666666666666666666666666666666666");
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_vote_height_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.vote_height += 1;
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_proposal_submission_height_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.proposal_submission_height += 1;
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_tally_key_epoch_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.tally_key_epoch += 1;
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_output_index_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.output_indices[2] += 1;
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_output_height_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.output_heights[2] += 1;
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_age_factor_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.age_factors[2] = static_cast<uint8_t>(ctx.age_factors[2] + 1);
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_ring_P_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    // Replace P[1] with P[2]'s value; must still fail.
    ctx.P[1] = ctx.P[2];
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_ring_C_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.C[1] = ctx.C[2];
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}

TEST(dao_clsag, tamper_V_fails)
{
    auto ctx = make_reference_context();
    auto sig = make_reference_sig();
    ctx.V = hex_to_key(
        "7777777777777777777777777777777777777777777777777777777777777777");
    EXPECT_FALSE(dao_clsag_verify(ctx, sig));
}