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
#include "governance/dao_cl_ballot.h"
#include "governance/dao_cl_consistency.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_tally_wire.h"
#include "governance/dao_clsag.h"
#include "governance/dao_crypto_backend.h"
#include "governance/dao_dkg.h"
#include "governance/dao_vote_or_proof.h"
#include "governance/vote_proof_v2.h"

// Some upstream headers in this translation unit define a two-arg
// setbit macro that collides with the bicycl function of the same name.
#ifdef setbit
#undef setbit
#endif
#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include <memory>
#include <random>

namespace cryptonote {
namespace v2test {

// One CL test key: a class group instance with a freshly-generated
// key pair and the canonical cl_key_context wire bytes for the record.
struct CLTestKey
{
    std::shared_ptr<BICYCL::CL_HSMqk> cl;
    std::shared_ptr<BICYCL::CL_HSMqk::PublicKey> pk;
    std::shared_ptr<BICYCL::CL_HSMqk::SecretKey> sk;
    std::vector<uint8_t> context_wire;
    BICYCL::Mpz D;
};

inline void mpz_to_sign_magnitude(const BICYCL::Mpz& v,
                                   std::vector<uint8_t>& out)
{
    out.clear();
    out.push_back(v.sgn() < 0 ? 1u : 0u);
    BICYCL::Mpz abs_v;
    BICYCL::Mpz::abs(abs_v, v);
    if (!abs_v.is_zero()) {
        auto bv = static_cast<std::vector<unsigned char>>(abs_v);
        out.insert(out.end(), bv.begin(), bv.end());
    }
}

inline bool make_cl_test_key(CLTestKey& out, uint64_t seed)
{
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(static_cast<unsigned long>(seed)));
    auto cl = dao::cl_dkg_make_hsmq(128, rng);
    if (!cl) return false;
    auto sk = std::make_shared<BICYCL::CL_HSMqk::SecretKey>(*cl, rng);
    auto pk = std::make_shared<BICYCL::CL_HSMqk::PublicKey>(*cl, *sk);

    dao::cl_key_context ctx;
    {
        auto qb = static_cast<std::vector<unsigned char>>(cl->q());
        ctx.q.assign(qb.begin(), qb.end());
        ctx.k = static_cast<uint32_t>(cl->k());
        // cl_key_context_serialize expects p and D as sign||magnitude
        // (no length prefix); dao_cl_key_context_parse returns them in
        // the same encoding, and dao_cl_load_proposal_key parses with
        // cl_dkg_mpz_from_bytes_signed, which expects
        // sign||u32(len)||magnitude. Both files agree on the sign
        // format; only the internal framing differs. Build both forms
        // here as the serializer requires.
        mpz_to_sign_magnitude(cl->p(), ctx.p);
        if (!dao::cl_dkg_qfi_to_bytes(ctx.pk_qfi, pk->elt())) return false;
    }
    BICYCL::Mpz D = BICYCL::Mpz(6UL);
    mpz_to_sign_magnitude(D, ctx.D);
    if (!dao::dao_cl_key_context_serialize(ctx, out.context_wire)) return false;

    out.cl = cl;
    out.pk = pk;
    out.sk = sk;
    out.D = D;
    return true;
}

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

    std::vector<uint8_t> E_W() const { return proof.E_W; }
    std::vector<uint8_t> E_S() const { return proof.E_S; }
    std::vector<uint8_t> E_B() const { return proof.E_B; }
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
    const CLTestKey& cl_key,
    const crypto::hash& proposal_id,
    uint8_t variant,
    uint32_t tally_epoch,
    uint64_t vote_height,
    uint64_t proposal_submission_height,
    uint64_t proposal_voting_end_height,
    bool vote_yes = true)
{
    fx = ValidVote{};
    fx.proposal_id = proposal_id;
    fx.vote_height = vote_height;
    fx.proposal_submission_height = proposal_submission_height;
    fx.proposal_voting_end_height = proposal_voting_end_height;
    fx.tally_epoch = tally_epoch;

    constexpr size_t N = 4;
    constexpr size_t L = 2;

    // All ring members are placed in the same age-factor bucket at
    // vote_height 51000. Heights 10000..25000 all give raw_days in
    // [36, 56], i.e. f = 5. The DAO verifier (step 14) rejects
    // mixed-age rings; the fixture must match that rule.
    uint64_t heights[N] = {10000, 15000, 20000, 25000};
    uint8_t  exp_f[N]   = {5, 5, 5, 5};
    uint64_t amt[N]     = {10, 11, 12, 13};
    uint64_t abs[N]     = {1000, 2000, 3000, 4000};
    std::vector<uint64_t> rel_offsets = {1000, 1000, 1000, 1000};

    rct::key x_s[N], mask[N], P[N], C[N], f_s[N], Q[N];
    for (size_t i = 0; i < N; ++i) {
        x_s[i]  = mk_scalar(static_cast<uint8_t>(0x10 + i + variant));
        mask[i] = mk_scalar(static_cast<uint8_t>(0x20 + i + variant));
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

    BICYCL::Mpz W_mpz = BICYCL::Mpz(static_cast<unsigned long>(W_val));
    BICYCL::Mpz S_signed = W_mpz;
    if (!vote_yes) S_signed.neg();
    BICYCL::Mpz S_res;
    if (!dao::dao_cl_encode_signed_plaintext(S_signed, cl_key.cl->q(), S_res))
        return false;

    rct::key S_s = small_scalar(W_val);
    if (!vote_yes) {
        rct::key zero = rct::zero();
        rct::key tmp;
        sc_sub(tmp.bytes, zero.bytes, S_s.bytes);
        S_s = tmp;
    }
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

    // --- CL: encrypt W, S (canonical residue), B ---
    BICYCL::Mpz B_mpz = BICYCL::Mpz(static_cast<unsigned long>(B_val));
    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(static_cast<unsigned long>(0xC0FFEE + variant)));

    BICYCL::Mpz r_W = dao::dao_cl_sample_randomness(*cl_key.cl, rng);
    BICYCL::Mpz r_S = dao::dao_cl_sample_randomness(*cl_key.cl, rng);
    BICYCL::Mpz r_B = dao::dao_cl_sample_randomness(*cl_key.cl, rng);

    std::vector<uint8_t> E_W_raw, E_S_raw, E_B_raw;
    if (!dao::dao_cl_encrypt_at_pk(*cl_key.cl, *cl_key.pk, W_mpz, r_W, E_W_raw))
        return false;
    if (!dao::dao_cl_encrypt_at_pk(*cl_key.cl, *cl_key.pk, S_res, r_S, E_S_raw))
        return false;
    if (!dao::dao_cl_encrypt_at_pk(*cl_key.cl, *cl_key.pk, B_mpz, r_B, E_B_raw))
        return false;

    // --- Tally key record (CL). Paillier placeholder fields are
    fx.key_rec.version        = 2;
    fx.key_rec.committee_size = 16;
    fx.key_rec.threshold      = 8;
    fx.key_rec.t              = 7;
    fx.key_rec.committee_id_hash.assign(32, 0);
    fx.key_rec.committee_members.assign(16, std::vector<uint8_t>(32, 0));
    fx.key_rec.cl_modulus     = cl_key.context_wire;
    fx.key_rec.activation_height = 1;
    fx.key_rec.dkg_transcript_hash.assign(32, 0);
    fx.key_rec.key_id.assign(32, 0);
    std::memset(fx.key_rec.key_id.data(), 0x11, 32);

    // --- Derive the proposal-scoped DAO nullifier the same way the
    // DAO CLSAG will when it computes sig.I = x * H_vote(P, pid). This
    // is the only value accepted on the wire; the CLSAG I produced
    // below must equal it. ---
    crypto::hash nullifier{};
    {
        rct::key H_l = cryptonote::dao_hash_to_point(P[L], proposal_id);
        rct::key N{};
        rct::scalarmultKey(N, H_l, x_s[L]);
        std::memcpy(nullifier.data, N.bytes, sizeof(nullifier.data));
    }
    fx.nullifier = nullifier;

    // --- Build transcript input ---
    dao::dao_vote_transcript_input ti;
    ti.version                    = vote_proof_v2::VERSION;
    ti.proposal_id                = proposal_id;
    ti.proposal_submission_height = proposal_submission_height;
    ti.vote_height                = vote_height;
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
return false;
    }

    // --- CL consistency proofs W (full), S (no-range), B (full) ---
    BICYCL::CL_HSMqk::CipherText ct_W, ct_S, ct_B;
    if (!dao::dao_cl_ciphertext_from_wire(*cl_key.cl, E_W_raw, ct_W)) return false;
    if (!dao::dao_cl_ciphertext_from_wire(*cl_key.cl, E_S_raw, ct_S)) return false;
    if (!dao::dao_cl_ciphertext_from_wire(*cl_key.cl, E_B_raw, ct_B)) return false;

    dao::dao_consistency_context cctx;
    cctx.domain                = "C_W-Enc(W)";
    cctx.version               = vote_proof_v2::VERSION;
    cctx.proposal_id           = proposal_id;
    cctx.vote_height           = vote_height;
    std::memcpy(cctx.tally_key_id.data, fx.key_rec.key_id.data(), 32);
    cctx.vote_input_transcript = digest;

    dao::dao_cl_pedersen_proof pW;
    if (!dao::dao_cl_consistency_prove(*cl_key.cl, *cl_key.pk, ct_W,
                                       W_mpz, r_W, V, R_W, cctx, rng, pW))
        return false;
    std::vector<uint8_t> pW_bytes;
    if (!pW.serialize(pW_bytes)) return false;

    dao::dao_consistency_context cctx_s = cctx;
    cctx_s.domain = "C_S-Enc(S)";
    dao::dao_cl_pedersen_proof_no_range pS;
    if (!dao::dao_cl_consistency_prove_no_range(*cl_key.cl, *cl_key.pk, ct_S,
                                                S_res, r_S, C_S, R_S,
                                                cctx_s, rng, pS))
        return false;
    std::vector<uint8_t> pS_bytes;
    if (!pS.serialize(pS_bytes)) return false;

    dao::dao_consistency_context cctx_b = cctx;
    cctx_b.domain = "C_B-Enc(B)";
    dao::dao_cl_pedersen_proof pB;
    if (!dao::dao_cl_consistency_prove(*cl_key.cl, *cl_key.pk, ct_B,
                                       B_mpz, r_B, B_l, R_B, cctx_b, rng, pB))
        return false;
    std::vector<uint8_t> pB_bytes;
    if (!pB.serialize(pB_bytes)) return false;

    // --- Direction OR proof (independent of B) ---
    dao_or_context octx;
    octx.version     = vote_proof_v2::VERSION;
    octx.proposal_id = proposal_id;
    octx.vote_height = vote_height;
    {
        rct::key nfk{};
        std::memcpy(nfk.bytes, nullifier.data, 32);
        octx.nullifiers.push_back(nfk);
    }
    octx.key_offsets   = rel_offsets;
    octx.extra_binding = dao::dao_cl_extra_binding(E_W_raw, E_S_raw,
                                                    pW_bytes, pS_bytes);
    octx.C_W = V;
    octx.C_S = C_S;

    dao_vote_or_proof orp;
    if (!dao_or_prove(octx, vote_yes, R_S, R_W, orp))
        return false;

    // --- Weight CLSAG ---
    dao_clsag_context cc;
    cc.proposal_id                = proposal_id;
    cc.proposal_submission_height = proposal_submission_height;
    cc.vote_height                = vote_height;
    std::memcpy(cc.tally_key_id.data, fx.key_rec.key_id.data(), 32);
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
return false;
    }

    // The CLSAG I must equal the nullifier we committed to in the
    // transcript and OR proof.
    {
        crypto::hash from_I{};
        std::memcpy(from_I.data, w_sig.I.bytes,
                    sizeof(from_I.data));
        if (std::memcmp(from_I.data, nullifier.data, 32) != 0) {
return false;
        }
    }

    // --- Balance CLSAG (same ring, f=1) ---
    dao_clsag_context bcc = cc;
    bcc.age_factors.assign(N, 1);
    bcc.V = B_l;

    rct::clsag b_sig;
    if (!dao_clsag_generate(bcc, L, sk, rho_B, b_sig)) {
return false;
    }
    if (!(w_sig.I == b_sig.I)) {
return false;
    }

    // --- Assemble wire ---
    fx.proof.version         = vote_proof_v2::VERSION;
    fx.proof.proposal_id     = proposal_id;
    fx.proof.vote_height     = vote_height;
    std::memcpy(fx.proof.tally_key_id.data, fx.key_rec.key_id.data(), 32);

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
    fx.proof.E_W = E_W_raw;
    fx.proof.E_S = E_S_raw;
    fx.proof.E_B = E_B_raw;
    fx.proof.proof_W = std::move(pW_bytes);
    fx.proof.proof_S = std::move(pS_bytes);
    fx.proof.proof_B = std::move(pB_bytes);
    fx.proof.direction_proof = orp;
    std::memcpy(fx.proof.transcript_hash.data, digest.data(), 32);

    for (size_t i = 0; i < N; ++i) {
        output_data_t od{};
        std::memcpy(od.pubkey.data, P[i].bytes, 32);
        od.commitment = C[i];
        od.height     = heights[i];
        fx.outputs[abs[i]] = od;
    }

    return true;
}

} // namespace v2test
} // namespace cryptonote
