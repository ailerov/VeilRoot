// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_wallet_v2.h"

#include <array>
#include <cstring>
#include <limits>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "crypto/crypto.h"
#include "governance/dao_clsag.h"
#include "governance/dao_consistency.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_vote_or_proof.h"

namespace cryptonote {
namespace dao {

namespace {

uint8_t age_factor_from_height(uint64_t vote_height, uint64_t output_height)
{
    if (output_height > vote_height) return 0;
    uint64_t raw = (vote_height - output_height) / 720;
    if (raw > 7300) raw = 7300;
    uint64_t f = 0;
    uint64_t n = raw + 1;
    while (n > 1) { n >>= 1; ++f; }
    if (f > 255) f = 255;
    return static_cast<uint8_t>(f);
}

// Build a small scalar whose low bytes are `v` (little-endian).
rct::key scalar_from_u64(uint64_t v)
{
    rct::key k = rct::zero();
    for (int i = 0; i < 8; ++i) k.bytes[i] = (v >> (8*i)) & 0xff;
    return k;
}

bool bn_to_vec_be(const BIGNUM* b, std::vector<uint8_t>& out, size_t fixed)
{
    out.assign(fixed, 0);
    if (BN_num_bytes(b) > static_cast<int>(fixed)) return false;
    BN_bn2binpad(b, out.data(), static_cast<int>(fixed));
    return true;
}

} // anonymous namespace

bool build_dao_v2_vote(
    const crypto::hash& proposal_id,
    uint64_t proposal_submission_height,
    uint64_t vote_height,
    uint32_t tally_key_epoch,
    const crypto::hash& tally_key_id,
    const std::vector<uint8_t>& paillier_modulus,
    uint8_t direction,
    const std::vector<dao_v2_vote_source>& sources,
    vote_proof_v2& out)
{
    out = vote_proof_v2{};

    if (direction > 1) return false;
    if (sources.empty()) return false;
    if (paillier_modulus.size() != 256) return false;

    for (const auto& s : sources) {
        if (s.P.empty() || s.P.size() != s.C.size()) return false;
        if (s.output_indices.size() != s.P.size()) return false;
        if (s.output_heights.size() != s.P.size()) return false;
        if (s.key_offsets.size()    != s.P.size()) return false;
        if (s.real_index >= s.P.size()) return false;
    }

    PaillierPublicKey ppk;
    if (!ppk.deserialize_modulus(paillier_modulus)) return false;

    BIGNUM* N_bn = BN_new();
    if (!N_bn) return false;
    BN_bin2bn(paillier_modulus.data(),
              static_cast<int>(paillier_modulus.size()), N_bn);

    out.version         = vote_proof_v2::VERSION;
    out.proposal_id     = proposal_id;
    out.vote_height     = vote_height;
    out.tally_key_epoch = tally_key_epoch;

    rct::key C_W = rct::identity();
    rct::key C_B = rct::identity();
    rct::key R_W = rct::zero();
    rct::key R_B = rct::zero();

    uint64_t W_total = 0;
    uint64_t B_total = 0;

    std::vector<rct::key> nullifiers;

    dao_vote_transcript_input ti;
    ti.version                    = 2;
    ti.proposal_id                = proposal_id;
    ti.proposal_submission_height = proposal_submission_height;
    ti.vote_height                = vote_height;
    ti.tally_key_epoch            = tally_key_epoch;
    std::memcpy(ti.tally_key_id.data, tally_key_id.data, 32);

    bool ok = true;

    for (const auto& s : sources)
    {
        if (!ok) break;

        const size_t ring_size = s.P.size();
        const size_t real_index = s.real_index;

        std::vector<uint8_t> age_factors;
        age_factors.reserve(ring_size);
        for (size_t j = 0; j < ring_size; ++j)
            age_factors.push_back(age_factor_from_height(
                vote_height, s.output_heights[j]));

        const uint8_t f_real = age_factors[real_index];

        // Real commitment and self-check.
        const rct::key C_real = rct::commit(s.real_amount, s.real_mask);
        if (std::memcmp(C_real.bytes, s.C[real_index].bytes, 32) != 0) {
            ok = false;
            break;
        }

        const rct::key f_scalar = scalar_from_u64(f_real);

        rct::key rho_W = rct::skGen();
        rct::key rho_B = rct::skGen();

        rct::key fC{}, rhoWG{}, V_i{};
        rct::scalarmultKey(fC, C_real, f_scalar);
        rct::scalarmultBase(rhoWG, rho_W);
        rct::addKeys(V_i, fC, rhoWG);

        rct::key rhoBG{}, B_i{};
        rct::scalarmultBase(rhoBG, rho_B);
        rct::addKeys(B_i, C_real, rhoBG);

        rct::addKeys(C_W, C_W, V_i);
        rct::addKeys(C_B, C_B, B_i);

        {
            rct::key f_mask{};
            sc_mul(f_mask.bytes, f_scalar.bytes, s.real_mask.bytes);
            rct::key sum{};
            sc_add(sum.bytes, f_mask.bytes, rho_W.bytes);
            rct::key nxt{};
            sc_add(nxt.bytes, R_W.bytes, sum.bytes);
            R_W = nxt;
        }
        {
            rct::key sum{};
            sc_add(sum.bytes, s.real_mask.bytes, rho_B.bytes);
            rct::key nxt{};
            sc_add(nxt.bytes, R_B.bytes, sum.bytes);
            R_B = nxt;
        }

        // Weighted CLSAG.
        dao_clsag_context cc;
        cc.proposal_id                = proposal_id;
        cc.proposal_submission_height = proposal_submission_height;
        cc.vote_height                = vote_height;
        cc.tally_key_epoch            = tally_key_epoch;
        cc.P = s.P;
        cc.C = s.C;
        cc.output_indices = s.output_indices;
        cc.output_heights = s.output_heights;
        cc.age_factors    = age_factors;
        cc.V              = V_i;

        rct::clsag w_sig{};
        if (!dao_clsag_generate(cc, real_index, s.real_spend_secret,
                                rho_W, w_sig)) {
            ok = false;
            break;
        }

        dao_clsag_context bcc = cc;
        bcc.age_factors.assign(ring_size, 1);
        bcc.V = B_i;

        rct::clsag b_sig{};
        if (!dao_clsag_generate(bcc, real_index, s.real_spend_secret,
                                rho_B, b_sig)) {
            ok = false;
            break;
        }
        if (!(w_sig.I == b_sig.I)) {
            ok = false;
            break;
        }

        crypto::hash nf{};
        std::memcpy(nf.data, w_sig.I.bytes, 32);
        nullifiers.push_back(w_sig.I);

        vote_input_v2 in;
        in.key_offsets        = s.key_offsets;
        in.weight_commitment  = V_i;
        in.weight_signature   = w_sig;
        in.balance_commitment = B_i;
        in.balance_signature  = b_sig;
        out.inputs.push_back(std::move(in));
        out.nullifiers.push_back(nf);

        ti.key_offsets.push_back(s.key_offsets);
        ti.absolute_indices.push_back(s.output_indices);
        ti.P.push_back(s.P);
        ti.C.push_back(s.C);
        ti.output_heights.push_back(s.output_heights);
        ti.age_factors.push_back(age_factors);
        ti.nullifiers.push_back(nf);
        ti.balance_commitments.push_back(B_i);

        W_total += static_cast<uint64_t>(f_real) * s.real_amount;
        B_total += s.real_amount;
    }

    if (!ok) {
        BN_free(N_bn);
        return false;
    }

    // Signed weight. Three values, deliberately distinct:
    //   S_signed_bn   mathematical signed value (+W / -W), used for
    //                 C_S and for the consistency proof `m` argument.
    //   S_paillier_bn Paillier plaintext representative (+W / N-W),
    //                 used only for E_S.
    // The consistency prover internally reduces the signed value mod
    // N for the Paillier side and mod the curve order for the curve
    // side, so passing S_signed_bn is correct in both places.
    const bool is_yes = (direction == 0);
    BIGNUM* W_bn = BN_new();
    BIGNUM* B_bn = BN_new();
    BIGNUM* S_signed_bn = BN_new();
    BIGNUM* S_paillier_bn = BN_new();
    BN_set_word(W_bn, W_total);
    BN_set_word(B_bn, B_total);

    BN_copy(S_signed_bn, W_bn);
    if (!is_yes && !BN_is_zero(S_signed_bn))
        BN_set_negative(S_signed_bn, 1);

    if (!is_yes && !BN_is_zero(W_bn))
        BN_sub(S_paillier_bn, N_bn, W_bn);
    else
        BN_copy(S_paillier_bn, W_bn);

    // C_S over signed total.
    rct::key R_S = rct::skGen();
    rct::key S_scalar = rct::zero();
    {
        // S_scalar = S_signed mod curve_order, little-endian.
        BIGNUM* L = nullptr;
        BN_hex2bn(&L, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
        BN_CTX* sctx = BN_CTX_new();
        BIGNUM* S_red = BN_new();
        if (L && sctx && S_red &&
            BN_nnmod(S_red, S_signed_bn, L, sctx)) {
            std::array<uint8_t, 32> s_be{};
            BN_bn2binpad(S_red, s_be.data(), 32);
            for (int i = 0; i < 32; ++i)
                S_scalar.bytes[i] = s_be[31 - i];
        }
        BN_free(L);
        BN_free(S_red);
        BN_CTX_free(sctx);
    }
    rct::key SH{}, RSG{}, C_S{};
    rct::scalarmultKey(SH, rct::H, S_scalar);
    rct::scalarmultBase(RSG, R_S);
    rct::addKeys(C_S, SH, RSG);

    // Encrypt W, S, B.
    BIGNUM* r_W = BN_new();
    BIGNUM* r_S = BN_new();
    BIGNUM* r_B = BN_new();
    std::vector<uint8_t> E_W_raw, E_S_raw, E_B_raw;
    if (!dao_dkg_sample_r(ppk, r_W) ||
        !dao_dkg_sample_r(ppk, r_S) ||
        !dao_dkg_sample_r(ppk, r_B) ||
        !ppk.encrypt(W_bn, r_W, E_W_raw) ||
        !ppk.encrypt(S_paillier_bn, r_S, E_S_raw) ||
        !ppk.encrypt(B_bn, r_B, E_B_raw)) {
        BN_free(N_bn);
        BN_free(W_bn); BN_free(B_bn); BN_free(S_signed_bn); BN_free(S_paillier_bn);
        BN_free(r_W); BN_free(r_S); BN_free(r_B);
        return false;
    }

    ti.C_W = C_W;
    ti.C_S = C_S;
    ti.C_B = C_B;
    ti.E_W = E_W_raw;
    ti.E_S = E_S_raw;
    ti.E_B = E_B_raw;

    std::vector<uint8_t> digest = dao_vote_input_transcript(ti);
    if (digest.size() != 32) {
        BN_free(N_bn);
        BN_free(W_bn); BN_free(B_bn); BN_free(S_signed_bn); BN_free(S_paillier_bn);
        BN_free(r_W); BN_free(r_S); BN_free(r_B);
        return false;
    }

    // Consistency proofs.
    dao_consistency_context cctx;
    cctx.version               = 2;
    cctx.proposal_id           = proposal_id;
    cctx.vote_height           = vote_height;
    cctx.tally_key_epoch       = tally_key_epoch;
    cctx.vote_input_transcript = digest;

    cctx.domain = "C_W-Enc(W)";
    if (!dao_consistency_prove(cctx, N_bn, E_W_raw, C_W, W_bn,
                               r_W, R_W, out.proof_W)) {
        BN_free(N_bn);
        BN_free(W_bn); BN_free(B_bn); BN_free(S_signed_bn); BN_free(S_paillier_bn);
        BN_free(r_W); BN_free(r_S); BN_free(r_B);
        return false;
    }
    cctx.domain = "C_S-Enc(S)";
    if (!dao_consistency_prove(cctx, N_bn, E_S_raw, C_S, S_signed_bn,
                               r_S, R_S, out.proof_S)) {
        BN_free(N_bn);
        BN_free(W_bn); BN_free(B_bn); BN_free(S_signed_bn); BN_free(S_paillier_bn);
        BN_free(r_W); BN_free(r_S); BN_free(r_B);
        return false;
    }
    cctx.domain = "C_B-Enc(B)";
    if (!dao_consistency_prove(cctx, N_bn, E_B_raw, C_B, B_bn,
                               r_B, R_B, out.proof_B)) {
        BN_free(N_bn);
        BN_free(W_bn); BN_free(B_bn); BN_free(S_signed_bn); BN_free(S_paillier_bn);
        BN_free(r_W); BN_free(r_S); BN_free(r_B);
        return false;
    }

    // Direction OR proof.
    dao_or_context octx;
    octx.version     = 2;
    octx.proposal_id = proposal_id;
    octx.vote_height = vote_height;
    octx.nullifiers  = nullifiers;
    for (const auto& in : out.inputs)
        for (uint64_t o : in.key_offsets)
            octx.key_offsets.push_back(o);
    octx.extra_binding = dao_extra_binding(E_W_raw, E_S_raw,
                                           out.proof_W, out.proof_S);
    octx.C_W = C_W;
    octx.C_S = C_S;

    if (!dao_or_prove(octx, is_yes, R_S, R_W, out.direction_proof)) {
        BN_free(N_bn);
        BN_free(W_bn); BN_free(B_bn); BN_free(S_signed_bn); BN_free(S_paillier_bn);
        BN_free(r_W); BN_free(r_S); BN_free(r_B);
        return false;
    }

    // Assembly.
    out.C_W = C_W;
    out.C_S = C_S;
    out.C_B = C_B;
    std::memcpy(out.E_W.data.data(), E_W_raw.data(), 512);
    std::memcpy(out.E_S.data.data(), E_S_raw.data(), 512);
    std::memcpy(out.E_B.data.data(), E_B_raw.data(), 512);
    std::memcpy(out.transcript_hash.data, digest.data(), 32);

    BN_free(N_bn);
    BN_free(W_bn); BN_free(B_bn); BN_free(S_signed_bn); BN_free(S_paillier_bn);
    BN_free(r_W); BN_free(r_S); BN_free(r_B);
    return true;
}

} // namespace dao
} // namespace cryptonote
