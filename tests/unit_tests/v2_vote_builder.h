// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shared helper that builds one fully-valid DAO V2 vote for tests.
// Covers the weight channel (V_i, weighted CLSAG), the signed channel
// (C_S, E_S, proof_S), the participation-balance channel (B_i,
// balance CLSAG with f=1, C_B, E_B, proof_B), and the hidden-direction
// OR proof.

#pragma once

#include <array>
#include <cstring>
#include <unordered_map>
#include <vector>

#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "blockchain_db/blockchain_db.h"
#include "governance/dao_clsag.h"
#include "governance/dao_consistency.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_vote_or_proof.h"
#include "governance/vote_proof_v2.h"

namespace cryptonote {
namespace v2test {

struct ValidVote
{
    vote_proof_v2 proof;

    dao::dao_tally_key_record key_rec;
    crypto::hash              proposal_id;
    crypto::hash              nullifier;

    uint64_t proposal_submission_height = 0;
    uint64_t proposal_voting_end_height = 0;
    uint64_t vote_height                = 0;
    uint32_t tally_epoch                = 0;

    std::unordered_map<uint64_t, output_data_t> outputs;

    std::vector<uint8_t> E_W() const
    { return std::vector<uint8_t>(proof.E_W.data.begin(),
                                  proof.E_W.data.end()); }
    std::vector<uint8_t> E_S() const
    { return std::vector<uint8_t>(proof.E_S.data.begin(),
                                  proof.E_S.data.end()); }
    std::vector<uint8_t> E_B() const
    { return std::vector<uint8_t>(proof.E_B.data.begin(),
                                  proof.E_B.data.end()); }
};

inline rct::key mk_scalar(uint8_t v)
{
    rct::key k{};
    k.bytes[0] = v;
    return k;
}

inline rct::key small_scalar(uint64_t v)
{
    rct::key k{};
    for (int i = 0; i < 8; ++i) k.bytes[i] = (v >> (8 * i)) & 0xff;
    return k;
}

inline crypto::hash hash_from_byte(uint8_t seed)
{
    crypto::hash h{};
    std::memset(h.data, seed, 32);
    return h;
}

// Build one fully-valid DAO V2 vote. The shared Paillier public key
// must be the same across every vote that will be aggregated into one
// proposal, otherwise the homomorphic add is meaningless.
inline bool build_valid_vote(
    ValidVote& fx,
    const dao::PaillierPublicKey& ppk,
    const crypto::hash& proposal_id,
    const crypto::hash& nullifier,
    uint32_t tally_epoch,
    uint64_t vote_height,
    uint64_t proposal_submission_height,
    uint64_t proposal_voting_end_height)
{
    fx = ValidVote{};
    fx.proposal_id = proposal_id;
    fx.nullifier = nullifier;
    fx.vote_height = vote_height;
    fx.proposal_submission_height = proposal_submission_height;
    fx.proposal_voting_end_height = proposal_voting_end_height;
    fx.tally_epoch = tally_epoch;

    constexpr size_t N = 4;
    constexpr size_t L = 2;

    uint64_t heights[N] = {40000, 30000, 20000, 10000};
    uint8_t  exp_f[N]   = {4, 4, 5, 5};
    uint64_t amt[N]     = {10, 11, 12, 13};
    uint64_t abs[N]     = {1000, 2000, 3000, 4000};
    std::vector<uint64_t> rel_offsets = {1000, 1000, 1000, 1000};

    rct::key x_s[N], mask[N], P[N], C[N], f_s[N], Q[N];
    for (size_t i = 0; i < N; ++i) {
        x_s[i]  = mk_scalar(static_cast<uint8_t>(0x10 + i));
        mask[i] = mk_scalar(static_cast<uint8_t>(0x20 + i));
        rct::scalarmultBase(P[i], x_s[i]);

        rct::key aH, mG;
        rct::scalarmultKey(aH, rct::H, small_scalar(amt[i]));
        rct::scalarmultBase(mG, mask[i]);
        rct::addKeys(C[i], aH, mG);

        f_s[i] = small_scalar(exp_f[i]);
        rct::scalarmultKey(Q[i], C[i], f_s[i]);
    }

    rct::key rho_l = mk_scalar(0x40);
    rct::key rhoG;
    rct::scalarmultBase(rhoG, rho_l);
    rct::key V;
    rct::addKeys(V, Q[L], rhoG);

    rct::key R_W;
    sc_muladd(R_W.bytes, f_s[L].bytes, mask[L].bytes, rho_l.bytes);

    uint64_t W_val = static_cast<uint64_t>(exp_f[L]) * amt[L];

    rct::key S_s = small_scalar(W_val);
    rct::key R_S = mk_scalar(0x55);
    rct::key SH, RSG, C_S;
    rct::scalarmultKey(SH, rct::H, S_s);
    rct::scalarmultBase(RSG, R_S);
    rct::addKeys(C_S, SH, RSG);

    // --- Balance channel: B_l = C_l + rho_B * G ---
    rct::key rho_B = mk_scalar(0x60);
    rct::key rho_B_G;
    rct::scalarmultBase(rho_B_G, rho_B);
    rct::key B_l;
    rct::addKeys(B_l, C[L], rho_B_G);

    rct::key R_B;
    sc_add(R_B.bytes, mask[L].bytes, rho_B.bytes);

    uint64_t B_val = amt[L];

    // --- Encrypt W, S, B ---
    BIGNUM* W_bn = BN_new(); BN_set_word(W_bn, W_val);
    BIGNUM* S_bn = BN_new(); BN_set_word(S_bn, W_val);
    BIGNUM* B_bn = BN_new(); BN_set_word(B_bn, B_val);
    BIGNUM* r_W  = BN_new(); BN_set_word(r_W, 3);
    BIGNUM* r_S  = BN_new(); BN_set_word(r_S, 5);
    BIGNUM* r_B  = BN_new(); BN_set_word(r_B, 7);

    std::vector<uint8_t> E_W_raw, E_S_raw, E_B_raw;
    bool ok = ppk.encrypt(W_bn, r_W, E_W_raw) &&
              ppk.encrypt(S_bn, r_S, E_S_raw) &&
              ppk.encrypt(B_bn, r_B, E_B_raw);
    if (!ok) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    // --- Tally key record (from ppk) ---
    fx.key_rec.version        = 1;
    fx.key_rec.epoch          = tally_epoch;
    fx.key_rec.committee_size = 16;
    fx.key_rec.threshold      = 8;
    fx.key_rec.t              = 7;
    fx.key_rec.committee_id_hash.assign(32, 0);
    fx.key_rec.committee_members.assign(16, std::vector<uint8_t>(32, 0));
    fx.key_rec.delta.assign(32, 0);
    fx.key_rec.N.assign(256, 0);
    BN_bn2binpad(ppk.N(), fx.key_rec.N.data(), 256);
    fx.key_rec.G.assign(256, 0);
    fx.key_rec.theta.assign(256, 0);
    fx.key_rec.V.assign(512, 0);
    fx.key_rec.V_K_i.assign(16, std::vector<uint8_t>(512, 0));
    fx.key_rec.vss_P.assign(64, 0);
    fx.key_rec.vss_P_prime.assign(64, 0);
    fx.key_rec.vss_g.assign(1, 4);
    fx.key_rec.vss_h.assign(64, 0);
    fx.key_rec.activation_height = 1;
    fx.key_rec.dkg_transcript_hash.assign(32, 0);
    fx.key_rec.key_id.assign(32, 0);
    std::memset(fx.key_rec.key_id.data(), 0x11, 32);

    // --- Build transcript input ---
    dao::dao_vote_transcript_input ti;
    ti.version                    = 2;
    ti.proposal_id                = proposal_id;
    ti.proposal_submission_height = proposal_submission_height;
    ti.vote_height                = vote_height;
    ti.tally_key_epoch            = tally_epoch;
    std::memcpy(ti.tally_key_id.data, fx.key_rec.key_id.data(), 32);

    std::vector<uint64_t> abs_indices(abs, abs + N);
    std::vector<rct::key> Pv(P, P + N), Cv(C, C + N);
    std::vector<uint64_t> hv(heights, heights + N);
    std::vector<uint8_t>  fv(exp_f, exp_f + N);

    ti.key_offsets.push_back(rel_offsets);
    ti.absolute_indices.push_back(abs_indices);
    ti.P.push_back(Pv);
    ti.C.push_back(Cv);
    ti.output_heights.push_back(hv);
    ti.age_factors.push_back(fv);
    ti.nullifiers.push_back(nullifier);
    ti.balance_commitments.push_back(B_l);
    ti.C_W = V;
    ti.C_S = C_S;
    ti.C_B = B_l;
    ti.E_W = E_W_raw;
    ti.E_S = E_S_raw;
    ti.E_B = E_B_raw;

    std::vector<uint8_t> digest = dao::dao_vote_input_transcript(ti);
    if (digest.size() != 32) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    // --- Consistency proofs W, S, B ---
    dao::dao_consistency_context cctx;
    cctx.domain                = "C_W-Enc(W)";
    cctx.version               = 2;
    cctx.proposal_id           = proposal_id;
    cctx.vote_height           = vote_height;
    cctx.tally_key_epoch       = tally_epoch;
    cctx.vote_input_transcript = digest;

    dao::dao_consistency_proof pW;
    if (!dao::dao_consistency_prove(cctx, ppk.N(), E_W_raw, V,
                                    W_bn, r_W, R_W, pW)) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    dao::dao_consistency_context cctx_s = cctx;
    cctx_s.domain = "C_S-Enc(S)";
    dao::dao_consistency_proof pS;
    if (!dao::dao_consistency_prove(cctx_s, ppk.N(), E_S_raw, C_S,
                                    S_bn, r_S, R_S, pS)) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    dao::dao_consistency_context cctx_b = cctx;
    cctx_b.domain = "C_B-Enc(B)";
    dao::dao_consistency_proof pB;
    if (!dao::dao_consistency_prove(cctx_b, ppk.N(), E_B_raw, B_l,
                                    B_bn, r_B, R_B, pB)) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    // --- Direction OR proof (independent of B) ---
    dao_or_context octx;
    octx.version     = 2;
    octx.proposal_id = proposal_id;
    octx.vote_height = vote_height;
    {
        rct::key nfk{};
        std::memcpy(nfk.bytes, nullifier.data, 32);
        octx.nullifiers.push_back(nfk);
    }
    octx.key_offsets   = rel_offsets;
    octx.extra_binding = dao::dao_extra_binding(E_W_raw, E_S_raw, pW, pS);
    octx.C_W = V;
    octx.C_S = C_S;

    dao_vote_or_proof orp;
    if (!dao_or_prove(octx, true, R_S, R_W, orp)) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    // --- Weight CLSAG ---
    dao_clsag_context cc;
    cc.proposal_id                = proposal_id;
    cc.proposal_submission_height = proposal_submission_height;
    cc.vote_height                = vote_height;
    cc.tally_key_epoch            = tally_epoch;
    cc.P = Pv;
    cc.C = Cv;
    cc.output_indices = abs_indices;
    cc.output_heights = hv;
    cc.age_factors    = fv;
    cc.V              = V;

    rct::clsag w_sig;
    crypto::secret_key sk;
    std::memcpy(sk.data, x_s[L].bytes, 32);
    if (!dao_clsag_generate(cc, L, sk, rho_l, w_sig)) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    // --- Balance CLSAG (same ring, f=1) ---
    dao_clsag_context bcc = cc;
    bcc.age_factors.assign(N, 1);
    bcc.V = B_l;

    rct::clsag b_sig;
    if (!dao_clsag_generate(bcc, L, sk, rho_B, b_sig)) {
        BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
        BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
        return false;
    }

    // --- Assemble wire ---
    fx.proof.version         = vote_proof_v2::VERSION;
    fx.proof.proposal_id     = proposal_id;
    fx.proof.vote_height     = vote_height;
    fx.proof.tally_key_epoch = tally_epoch;

    vote_input_v2 in;
    in.key_offsets        = rel_offsets;
    in.weight_commitment  = V;
    in.weight_signature   = w_sig;
    in.balance_commitment = B_l;
    in.balance_signature  = b_sig;
    fx.proof.inputs.push_back(in);
    fx.proof.nullifiers.push_back(nullifier);

    fx.proof.C_W = V;
    fx.proof.C_S = C_S;
    fx.proof.C_B = B_l;
    std::memcpy(fx.proof.E_W.data.data(), E_W_raw.data(), 512);
    std::memcpy(fx.proof.E_S.data.data(), E_S_raw.data(), 512);
    std::memcpy(fx.proof.E_B.data.data(), E_B_raw.data(), 512);
    fx.proof.proof_W = pW;
    fx.proof.proof_S = pS;
    fx.proof.proof_B = pB;
    fx.proof.direction_proof = orp;
    std::memcpy(fx.proof.transcript_hash.data, digest.data(), 32);

    for (size_t i = 0; i < N; ++i) {
        output_data_t od{};
        std::memcpy(od.pubkey.data, P[i].bytes, 32);
        od.commitment = C[i];
        od.height     = heights[i];
        fx.outputs[abs[i]] = od;
    }

    BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
    BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
    return true;
}

} // namespace v2test
} // namespace cryptonote
