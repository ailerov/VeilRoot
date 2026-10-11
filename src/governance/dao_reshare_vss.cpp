// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_reshare_vss.h"

#include <cstring>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/rand.h>

namespace cryptonote {
namespace dao {

namespace {

struct CtxGuard {
    BN_CTX* ctx;
    CtxGuard() : ctx(BN_CTX_new()) {}
    ~CtxGuard() { if (ctx) BN_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
    bool ok() const { return ctx != nullptr; }
};

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

bool pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out)
{
    if (off + 4 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= uint32_t(v[off++]) << (8 * i);
    return true;
}

bool bn_fixed(const BIGNUM* b, size_t w, std::vector<uint8_t>& out)
{
    out.assign(w, 0);
    return BN_bn2binpad(b, out.data(), static_cast<int>(w)) ==
           static_cast<int>(w);
}

bool modexp_signed(const BIGNUM* base, const BIGNUM* exp,
                   const BIGNUM* mod, BIGNUM* out, BN_CTX* ctx)
{
    if (!BN_is_negative(exp))
        return BN_mod_exp(out, base, exp, mod, ctx) == 1;
    BIGNUM* inv = BN_mod_inverse(nullptr, base, mod, ctx);
    if (!inv) return false;
    BIGNUM* pos = BN_dup(exp);
    if (!pos) { BN_free(inv); return false; }
    BN_set_negative(pos, 0);
    const bool ok = BN_mod_exp(out, inv, pos, mod, ctx) == 1;
    BN_free(inv); BN_free(pos);
    return ok;
}

} // namespace

void dao_reshare_serialize_signed(const BIGNUM* x, std::vector<uint8_t>& out)
{
    out.assign(DAO_RESHARE_SIGNED_BYTES, 0);
    if (!x) return;
    out[0] = BN_is_negative(x) ? 1 : 0;
    BIGNUM* abs_x = BN_dup(x);
    BN_set_negative(abs_x, 0);
    const size_t width = DAO_RESHARE_SIGNED_BYTES - 1;
    if (static_cast<size_t>(BN_num_bytes(abs_x)) > width) {
        // Caller must treat this as a hard failure. The size is
        // DAO_RESHARE_SIGNED_BYTES - 1 magnitude bytes.
        BN_free(abs_x);
        return;
    }
    BN_bn2binpad(abs_x, out.data() + 1, static_cast<int>(width));
    BN_free(abs_x);
}

bool dao_reshare_deserialize_signed(const std::vector<uint8_t>& in,
                                     BIGNUM* out)
{
    if (!out) return false;
    if (in.size() != DAO_RESHARE_SIGNED_BYTES) return false;
    if (in[0] != 0 && in[0] != 1) return false;
    const int width = static_cast<int>(DAO_RESHARE_SIGNED_BYTES - 1);
    BN_bin2bn(in.data() + 1, width, out);
    if (in[0] == 1) BN_set_negative(out, 1);
    return true;
}

bool dao_reshare_vss_commitments::serialize(std::vector<uint8_t>& out) const
{
    if (C_0.size() != PAILLIER_CT_BYTES) return false;
    if (C_k.size() != t_new) return false;
    for (const auto& c : C_k)
        if (c.size() != PAILLIER_CT_BYTES) return false;
    out.clear();
    push_u32(out, t_new);
    out.insert(out.end(), C_0.begin(), C_0.end());
    for (const auto& c : C_k)
        out.insert(out.end(), c.begin(), c.end());
    return true;
}

bool dao_reshare_vss_commitments::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (!pull_u32(in, off, t_new)) return false;
    if (t_new == 0 || t_new > 256) return false;
    const size_t need = off + PAILLIER_CT_BYTES * (1 + t_new);
    if (in.size() != need) return false;
    C_0.assign(in.begin() + off, in.begin() + off + PAILLIER_CT_BYTES);
    off += PAILLIER_CT_BYTES;
    C_k.assign(t_new, {});
    for (uint32_t k = 0; k < t_new; ++k) {
        C_k[k].assign(in.begin() + off, in.begin() + off + PAILLIER_CT_BYTES);
        off += PAILLIER_CT_BYTES;
    }
    return true;
}

bool dao_reshare_vss_deal(
    const PaillierPublicKey& pk,
    const std::vector<uint8_t>& V_bytes,
    const BIGNUM* s_i,
    const BIGNUM* mu_i,
    const BIGNUM* delta,
    uint32_t t_new,
    const std::vector<uint32_t>& new_indices,
    dao_reshare_link_context link_ctx,
    dao_reshare_link_proof& link_proof_out,
    dao_reshare_vss_commitments& commits_out,
    std::vector<dao_reshare_vss_share>& shares_out)
{
    if (!pk.valid() || !s_i || !mu_i || !delta) return false;
    if (t_new == 0 || t_new > 256) return false;
    if (new_indices.empty()) return false;
    if (V_bytes.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    const BIGNUM* N2 = pk.N2();
    BIGNUM* V = BN_bin2bn(V_bytes.data(),
                           static_cast<int>(V_bytes.size()), nullptr);
    if (!V) return false;

    // Constant: C_0 = V^(mu_i * s_i) mod N^2. mu_i is a signed
    // Lagrange coefficient, so this must be signed exponentiation.
    BIGNUM* c0_exp = BN_new();
    BN_mul(c0_exp, mu_i, s_i, g.ctx);
    BIGNUM* C0 = BN_new();
    if (!modexp_signed(V, c0_exp, N2, C0, g.ctx)) {
        BN_free(V); BN_free(c0_exp); BN_free(C0);
        return false;
    }

    commits_out.t_new = t_new;
    if (!bn_fixed(C0, PAILLIER_CT_BYTES, commits_out.C_0)) {
        BN_free(V); BN_free(c0_exp); BN_free(C0);
        return false;
    }

    // Bind C_0 to the contributor's existing VK_i via the
    // common-exponent proof. The transcript commits to the just-computed
    // C_0 via link_ctx.
    link_ctx.C_i0 = commits_out.C_0;
    {
        std::vector<uint8_t> sgn(1 + 512, 0);
        sgn[0] = BN_is_negative(mu_i) ? 1 : 0;
        BIGNUM* abs_mu = BN_dup(mu_i);
        BN_set_negative(abs_mu, 0);
        if (static_cast<size_t>(BN_num_bytes(abs_mu)) > 512) {
            BN_free(abs_mu);
            BN_free(V); BN_free(c0_exp); BN_free(C0);
            return false;
        }
        BN_bn2binpad(abs_mu, sgn.data() + 1, 512);
        BN_free(abs_mu);
        link_ctx.mu_i = std::move(sgn);
    }
    if (!dao_reshare_link_prove(link_ctx, s_i, link_proof_out)) {
        BN_free(V); BN_free(c0_exp); BN_free(C0);
        return false;
    }

    // Expert Stage D sampling. x is uniform in [0, 2^65), b = x - 2^64
    // so b is in [-2^64, 2^64). The Paillier commitment uses scale
    // 2^8281 so the effective nonconstant contribution is
    // Delta * 2^8281 * b_k, sized to mask the constant mu_i*s_i
    // statistically while remaining small enough to range-prove.
    BIGNUM* coeff_range   = BN_new();
    BIGNUM* sample_limit  = BN_new();
    BIGNUM* coeff_scale   = BN_new();
    BN_one(coeff_range);
    BN_lshift(coeff_range, coeff_range, DAO_RESHARE_COEFF_BITS);
    BN_one(sample_limit);
    BN_lshift(sample_limit, sample_limit,
              DAO_RESHARE_COEFF_BITS + 1);
    BN_one(coeff_scale);
    BN_lshift(coeff_scale, coeff_scale, DAO_RESHARE_COEFF_SCALE_BITS);
    if (!coeff_range || !sample_limit || !coeff_scale) {
        BN_free(coeff_range); BN_free(sample_limit); BN_free(coeff_scale);
        BN_free(V); BN_free(c0_exp); BN_free(C0);
        return false;
    }

    std::vector<BIGNUM*> b(t_new, nullptr);
    std::vector<BIGNUM*> xs(t_new, nullptr);
    commits_out.C_k.assign(t_new, {});
    for (uint32_t k = 0; k < t_new; ++k) {
        b[k] = BN_new();
        xs[k] = BN_new();
        if (!b[k] || !xs[k] || !BN_rand_range(xs[k], sample_limit)) {
            BN_free(xs[k]);
            for (auto* p : b) if (p) BN_free(p);
            BN_free(coeff_range); BN_free(sample_limit); BN_free(coeff_scale);
            BN_free(V); BN_free(c0_exp); BN_free(C0);
            return false;
        }
        if (!BN_sub(b[k], xs[k], coeff_range)) {
            BN_free(xs[k]);
            for (auto* p : b) if (p) BN_free(p);
            BN_free(coeff_range); BN_free(sample_limit); BN_free(coeff_scale);
            BN_free(V); BN_free(c0_exp); BN_free(C0);
            return false;
        }

        BIGNUM* exp = BN_new();
        BN_mul(exp, delta, coeff_scale, g.ctx);
        BN_mul(exp, exp, b[k], g.ctx);
        BIGNUM* Ck = BN_new();
        if (!modexp_signed(V, exp, N2, Ck, g.ctx)) {
            BN_free(exp); BN_free(Ck); BN_free(xs[k]);
            for (auto* p : b) if (p) BN_free(p);
            BN_free(coeff_range); BN_free(sample_limit);
            BN_free(coeff_scale);
            BN_free(V); BN_free(c0_exp); BN_free(C0);
            return false;
        }
        if (!bn_fixed(Ck, PAILLIER_CT_BYTES, commits_out.C_k[k])) {
            BN_free(exp); BN_free(Ck); BN_free(xs[k]);
            for (auto* p : b) if (p) BN_free(p);
            BN_free(coeff_range); BN_free(sample_limit);
            BN_free(coeff_scale);
            BN_free(V); BN_free(c0_exp); BN_free(C0);
            return false;
        }
        BN_free(exp); BN_free(Ck);
    }

    // Constant term: q_i(0) = mu_i * s_i
    BIGNUM* q_const = BN_new();
    BN_mul(q_const, mu_i, s_i, g.ctx);

    shares_out.clear();
    shares_out.reserve(new_indices.size());
    for (uint32_t j : new_indices) {
        BIGNUM* qj = BN_dup(q_const);
        BIGNUM* pow = BN_new();
        BN_set_word(pow, j);
        for (uint32_t k = 0; k < t_new; ++k) {
            BIGNUM* term = BN_new();
            BN_mul(term, delta, coeff_scale, g.ctx);
            BN_mul(term, term, b[k], g.ctx);
            BN_mul(term, term, pow, g.ctx);
            BN_add(qj, qj, term);
            BN_free(term);
            if (k + 1 < t_new)
                BN_mul(pow, pow, BN_value_one(), g.ctx),
                BN_mul_word(pow, j);
        }
        BN_free(pow);

        dao_reshare_vss_share sh;
        sh.j = j;
        dao_reshare_serialize_signed(qj, sh.q_i_j);
        shares_out.push_back(std::move(sh));
        BN_free(qj);
    }

    BN_free(q_const);
    for (auto* p : b) if (p) BN_free(p);
    for (auto* p : xs) if (p) BN_free(p);
    BN_free(coeff_range); BN_free(sample_limit); BN_free(coeff_scale);
    BN_free(V); BN_free(c0_exp); BN_free(C0);
    return true;
}

bool dao_reshare_vss_verify(
    const PaillierPublicKey& pk,
    const std::vector<uint8_t>& V_bytes,
    const dao_reshare_link_context& link_ctx,
    const dao_reshare_link_proof& link_proof,
    const dao_reshare_vss_commitments& commits,
    uint32_t j,
    const std::vector<uint8_t>& q_i_j)
{
    if (!pk.valid()) return false;

    // The common-exponent proof must validate against the same C_0
    // stored in the commitments. This rejects a swapped C_0 that
    // belongs to a different contributor.
    {
        if (link_ctx.C_i0.size() != PAILLIER_CT_BYTES) return false;
        if (link_ctx.C_i0 != commits.C_0) return false;
        if (!dao_reshare_link_verify(link_ctx, link_proof)) return false;
    }
    if (V_bytes.size() != PAILLIER_CT_BYTES) return false;
    if (commits.C_0.size() != PAILLIER_CT_BYTES) return false;
    if (commits.C_k.size() != commits.t_new) return false;
    if (j == 0) return false;

    CtxGuard g;
    if (!g.ok()) return false;
    const BIGNUM* N2 = pk.N2();

    BIGNUM* V = BN_bin2bn(V_bytes.data(),
                           static_cast<int>(V_bytes.size()), nullptr);
    BIGNUM* q = BN_new();
    if (!V || !dao_reshare_deserialize_signed(q_i_j, q)) {
        BN_free(V); BN_free(q);
        return false;
    }

    // LHS = V^q_i(j); q may be negative.
    BIGNUM* lhs = BN_new();
    if (!modexp_signed(V, q, N2, lhs, g.ctx)) {
        BN_free(V); BN_free(q); BN_free(lhs);
        return false;
    }

    // RHS = C_0 * prod C_k^(j^k)
    BIGNUM* rhs = BN_bin2bn(commits.C_0.data(),
                             static_cast<int>(commits.C_0.size()), nullptr);
    BIGNUM* jpow = BN_new();
    BN_one(jpow);
    bool ok = true;
    for (uint32_t k = 0; k < commits.t_new && ok; ++k) {
        BN_mul_word(jpow, j);
        BIGNUM* Ck = BN_bin2bn(commits.C_k[k].data(),
                                static_cast<int>(commits.C_k[k].size()),
                                nullptr);
        BIGNUM* term = BN_new();
        if (!Ck || !term ||
            !BN_mod_exp(term, Ck, jpow, N2, g.ctx) ||
            !BN_mod_mul(rhs, rhs, term, N2, g.ctx)) {
            ok = false;
        }
        BN_free(Ck); BN_free(term);
    }
    if (ok) ok = (BN_cmp(lhs, rhs) == 0);

    BN_free(V); BN_free(q); BN_free(lhs); BN_free(rhs); BN_free(jpow);
    return ok;
}

bool dao_reshare_vss_compute_vk(
    const PaillierPublicKey& pk,
    const std::vector<uint8_t>& V_bytes,
    const std::vector<dao_reshare_vss_commitments>& all_commits,
    uint32_t j,
    std::vector<uint8_t>& VK_j_out)
{
    if (!pk.valid() || all_commits.empty() || j == 0) return false;

    CtxGuard g;
    if (!g.ok()) return false;
    const BIGNUM* N2 = pk.N2();

    BIGNUM* acc = BN_new();
    BN_one(acc);

    for (const auto& commits : all_commits) {
        if (commits.C_0.size() != PAILLIER_CT_BYTES) return false;
        if (commits.C_k.size() != commits.t_new) return false;

        BIGNUM* C0 = BN_bin2bn(commits.C_0.data(),
                                static_cast<int>(commits.C_0.size()),
                                nullptr);
        BIGNUM* term = BN_dup(C0);
        BIGNUM* jpow = BN_new();
        BN_one(jpow);
        for (uint32_t k = 0; k < commits.t_new; ++k) {
            BN_mul_word(jpow, j);
            BIGNUM* Ck = BN_bin2bn(commits.C_k[k].data(),
                                    static_cast<int>(commits.C_k[k].size()),
                                    nullptr);
            BIGNUM* p = BN_new();
            BN_mod_exp(p, Ck, jpow, N2, g.ctx);
            BN_mod_mul(term, term, p, N2, g.ctx);
            BN_free(Ck); BN_free(p);
        }
        BN_mod_mul(acc, acc, term, N2, g.ctx);
        BN_free(C0); BN_free(term); BN_free(jpow);
    }

    VK_j_out.assign(PAILLIER_CT_BYTES, 0);
    bool ok = BN_bn2binpad(acc, VK_j_out.data(),
                            static_cast<int>(PAILLIER_CT_BYTES)) ==
              static_cast<int>(PAILLIER_CT_BYTES);
    BN_free(acc);
    return ok;
}

} // namespace dao
} // namespace cryptonote
