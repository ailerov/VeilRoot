// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_clsag.h"

#include <cstring>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "cryptonote_config.h"

using namespace rct;

namespace cryptonote {

namespace {

constexpr const char* DAO_HASH_DOMAIN = "VeilRoot-DAO-VOTE-V2";
constexpr const char* MSG_DOMAIN      = "VeilRoot-DAO-CLSAG-V2-MSG";

void push_le32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8*i)) & 0xff));
}

void push_le64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>((x >> (8*i)) & 0xff));
}

void dao_hash_to_p3_internal(ge_p3& out, const key& P, const crypto::hash& proposal_id)
{
    unsigned char buf[20 + 32 + 32];
    std::memcpy(buf,       DAO_HASH_DOMAIN, 20);
    std::memcpy(buf + 20,  proposal_id.data, 32);
    std::memcpy(buf + 52,  P.bytes, 32);

    key h;
    cn_fast_hash(h, buf, sizeof(buf));

    ge_p2 p2;
    ge_fromfe_frombytes_vartime(&p2, h.bytes);
    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2);
    ge_p1p1_to_p3(&out, &p1p1);
}

void compute_weighted_commitments(const dao_clsag_context& ctx,
                                  std::vector<key>& Q)
{
    Q.resize(ctx.C.size());
    for (size_t i = 0; i < ctx.C.size(); ++i)
    {
        if (ctx.age_factors[i] == 0)
        {
            identity(Q[i]);
        }
        else
        {
            key s_f;
            std::memset(s_f.bytes, 0, 32);
            s_f.bytes[0] = ctx.age_factors[i];
            sc_reduce32(s_f.bytes);
            scalarmultKey(Q[i], ctx.C[i], s_f);
        }
    }
}

bool context_well_formed(const dao_clsag_context& ctx, size_t sig_n)
{
    const size_t n = ctx.P.size();
    if (n < 1) return false;
    if (sig_n != n) return false;
    return ctx.C.size() == n
        && ctx.output_indices.size() == n
        && ctx.output_heights.size() == n
        && ctx.age_factors.size() == n;
}

} // anonymous namespace

key dao_hash_to_point(const key& P, const crypto::hash& proposal_id)
{
    ge_p3 p3;
    dao_hash_to_p3_internal(p3, P, proposal_id);
    key out;
    ge_p3_tobytes(out.bytes, &p3);
    return out;
}

key dao_clsag_message(const dao_clsag_context& ctx,
                      const key& N,
                      const key& V)
{
    std::vector<uint8_t> ring;
    push_le32(ring, static_cast<uint32_t>(ctx.P.size()));
    for (size_t i = 0; i < ctx.P.size(); ++i)
    {
        push_le64(ring, ctx.output_indices[i]);
        push_le64(ring, ctx.output_heights[i]);
        ring.insert(ring.end(), ctx.P[i].bytes, ctx.P[i].bytes + 32);
        ring.insert(ring.end(), ctx.C[i].bytes, ctx.C[i].bytes + 32);
        ring.push_back(ctx.age_factors[i]);
    }
    key ring_digest;
    cn_fast_hash(ring_digest, ring.data(), ring.size());

    std::vector<uint8_t> m;
    m.insert(m.end(), MSG_DOMAIN, MSG_DOMAIN + 25);
    m.push_back(2);
    const uint8_t* pi = reinterpret_cast<const uint8_t*>(ctx.proposal_id.data);
    m.insert(m.end(), pi, pi + 32);
    push_le64(m, ctx.proposal_submission_height);
    push_le64(m, ctx.vote_height);
    push_le32(m, ctx.tally_key_epoch);
    m.insert(m.end(), ring_digest.bytes, ring_digest.bytes + 32);
    m.insert(m.end(), N.bytes,           N.bytes + 32);
    m.insert(m.end(), V.bytes,           V.bytes + 32);

    key out;
    cn_fast_hash(out, m.data(), m.size());
    return out;
}

bool dao_clsag_generate(const dao_clsag_context& ctx,
                        size_t real_index,
                        const crypto::secret_key& output_secret,
                        const key& weight_blinding,
                        clsag& sig)
{
    const size_t n = ctx.P.size();
    if (!context_well_formed(ctx, n)) return false;
    if (real_index >= n) return false;

    std::vector<key> Q;
    compute_weighted_commitments(ctx, Q);

    std::vector<key> C_prime(n);
    for (size_t i = 0; i < n; ++i)
        subKeys(C_prime[i], Q[i], ctx.V);

    key z;
    sc_0(z.bytes);
    sc_sub(z.bytes, z.bytes, weight_blinding.bytes);

    key x;
    std::memcpy(x.bytes, output_secret.data, 32);

    key H_l = dao_hash_to_point(ctx.P[real_index], ctx.proposal_id);
    key N;
    scalarmultKey(N, H_l, x);

    key D_full;
    scalarmultKey(D_full, H_l, z);
    scalarmultKey(sig.D, D_full, INV_EIGHT);

    sig.I = N;
    sig.s.assign(n, key{});

    key a  = skGen();
    key aG, aH;
    scalarmultBase(aG, a);
    scalarmultKey(aH, H_l, a);

    key m = dao_clsag_message(ctx, N, ctx.V);

    std::vector<key> mu_P_to_hash(2*n + 4);
    std::vector<key> mu_C_to_hash(2*n + 4);
    sc_0(mu_P_to_hash[0].bytes);
    std::memcpy(mu_P_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_0,
                sizeof(config::HASH_KEY_CLSAG_AGG_0) - 1);
    sc_0(mu_C_to_hash[0].bytes);
    std::memcpy(mu_C_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_1,
                sizeof(config::HASH_KEY_CLSAG_AGG_1) - 1);
    for (size_t i = 0; i < n; ++i)
    {
        mu_P_to_hash[i + 1]     = ctx.P[i];
        mu_C_to_hash[i + 1]     = ctx.P[i];
        mu_P_to_hash[i + n + 1] = Q[i];
        mu_C_to_hash[i + n + 1] = Q[i];
    }
    mu_P_to_hash[2*n + 1] = sig.I;
    mu_P_to_hash[2*n + 2] = sig.D;
    mu_P_to_hash[2*n + 3] = ctx.V;
    mu_C_to_hash[2*n + 1] = sig.I;
    mu_C_to_hash[2*n + 2] = sig.D;
    mu_C_to_hash[2*n + 3] = ctx.V;

    key mu_P = hash_to_scalar(mu_P_to_hash);
    key mu_C = hash_to_scalar(mu_C_to_hash);

    std::vector<key> c_to_hash(2*n + 5);
    sc_0(c_to_hash[0].bytes);
    std::memcpy(c_to_hash[0].bytes, config::HASH_KEY_CLSAG_ROUND,
                sizeof(config::HASH_KEY_CLSAG_ROUND) - 1);
    for (size_t i = 0; i < n; ++i)
    {
        c_to_hash[i + 1]     = ctx.P[i];
        c_to_hash[i + n + 1] = Q[i];
    }
    c_to_hash[2*n + 1] = ctx.V;
    c_to_hash[2*n + 2] = m;
    c_to_hash[2*n + 3] = aG;
    c_to_hash[2*n + 4] = aH;

    key c = hash_to_scalar(c_to_hash);

    geDsmp I_precomp, D_precomp;
    precomp(I_precomp.k, sig.I);
    precomp(D_precomp.k, D_full);

    size_t i = (real_index + 1) % n;
    if (i == 0)
        sig.c1 = c;

    while (i != real_index)
    {
        sig.s[i] = skGen();

        key c_p, c_c;
        sc_mul(c_p.bytes, mu_P.bytes, c.bytes);
        sc_mul(c_c.bytes, mu_C.bytes, c.bytes);

        geDsmp P_pre, C_pre;
        precomp(P_pre.k, ctx.P[i]);
        precomp(C_pre.k, C_prime[i]);
        key L;
        addKeys_aGbBcC(L, sig.s[i], c_p, P_pre.k, c_c, C_pre.k);

        ge_p3 H_i_p3;
        dao_hash_to_p3_internal(H_i_p3, ctx.P[i], ctx.proposal_id);
        geDsmp H_pre;
        ge_dsm_precomp(H_pre.k, &H_i_p3);
        key R;
        addKeys_aAbBcC(R, sig.s[i], H_pre.k, c_p, I_precomp.k, c_c, D_precomp.k);

        c_to_hash[2*n + 3] = L;
        c_to_hash[2*n + 4] = R;
        c = hash_to_scalar(c_to_hash);

        i = (i + 1) % n;
        if (i == 0)
            sig.c1 = c;
    }

    key mu_P_x;
    sc_mul(mu_P_x.bytes, mu_P.bytes, x.bytes);
    key sum;
    sc_muladd(sum.bytes, mu_C.bytes, z.bytes, mu_P_x.bytes);
    sc_mulsub(sig.s[real_index].bytes, c.bytes, sum.bytes, a.bytes);

    sc_0(a.bytes);
    sc_0(x.bytes);
    sc_0(z.bytes);
    return true;
}

bool dao_clsag_verify(const dao_clsag_context& ctx,
                      const clsag& sig)
{
    const size_t n = ctx.P.size();
    if (!context_well_formed(ctx, sig.s.size())) return false;

    for (size_t i = 0; i < n; ++i)
        if (sc_check(sig.s[i].bytes) != 0) return false;
    if (sc_check(sig.c1.bytes) != 0) return false;
    if (sig.I == identity()) return false;

    key D_full = scalarmult8(sig.D);
    if (D_full == identity()) return false;

    std::vector<key> Q;
    compute_weighted_commitments(ctx, Q);

    std::vector<key> C_prime(n);
    for (size_t i = 0; i < n; ++i)
        subKeys(C_prime[i], Q[i], ctx.V);

    key m = dao_clsag_message(ctx, sig.I, ctx.V);

    std::vector<key> mu_P_to_hash(2*n + 4);
    std::vector<key> mu_C_to_hash(2*n + 4);
    sc_0(mu_P_to_hash[0].bytes);
    std::memcpy(mu_P_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_0,
                sizeof(config::HASH_KEY_CLSAG_AGG_0) - 1);
    sc_0(mu_C_to_hash[0].bytes);
    std::memcpy(mu_C_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_1,
                sizeof(config::HASH_KEY_CLSAG_AGG_1) - 1);
    for (size_t i = 0; i < n; ++i)
    {
        mu_P_to_hash[i + 1]     = ctx.P[i];
        mu_C_to_hash[i + 1]     = ctx.P[i];
        mu_P_to_hash[i + n + 1] = Q[i];
        mu_C_to_hash[i + n + 1] = Q[i];
    }
    mu_P_to_hash[2*n + 1] = sig.I;
    mu_P_to_hash[2*n + 2] = sig.D;
    mu_P_to_hash[2*n + 3] = ctx.V;
    mu_C_to_hash[2*n + 1] = sig.I;
    mu_C_to_hash[2*n + 2] = sig.D;
    mu_C_to_hash[2*n + 3] = ctx.V;

    key mu_P = hash_to_scalar(mu_P_to_hash);
    key mu_C = hash_to_scalar(mu_C_to_hash);

    std::vector<key> c_to_hash(2*n + 5);
    sc_0(c_to_hash[0].bytes);
    std::memcpy(c_to_hash[0].bytes, config::HASH_KEY_CLSAG_ROUND,
                sizeof(config::HASH_KEY_CLSAG_ROUND) - 1);
    for (size_t i = 0; i < n; ++i)
    {
        c_to_hash[i + 1]     = ctx.P[i];
        c_to_hash[i + n + 1] = Q[i];
    }
    c_to_hash[2*n + 1] = ctx.V;
    c_to_hash[2*n + 2] = m;

    geDsmp I_precomp, D_precomp;
    precomp(I_precomp.k, sig.I);
    precomp(D_precomp.k, D_full);

    key c = sig.c1;
    for (size_t i = 0; i < n; ++i)
    {
        key c_p, c_c;
        sc_mul(c_p.bytes, mu_P.bytes, c.bytes);
        sc_mul(c_c.bytes, mu_C.bytes, c.bytes);

        geDsmp P_pre, C_pre;
        precomp(P_pre.k, ctx.P[i]);
        precomp(C_pre.k, C_prime[i]);
        key L;
        addKeys_aGbBcC(L, sig.s[i], c_p, P_pre.k, c_c, C_pre.k);

        ge_p3 H_i_p3;
        dao_hash_to_p3_internal(H_i_p3, ctx.P[i], ctx.proposal_id);
        geDsmp H_pre;
        ge_dsm_precomp(H_pre.k, &H_i_p3);
        key R;
        addKeys_aAbBcC(R, sig.s[i], H_pre.k, c_p, I_precomp.k, c_c, D_precomp.k);

        c_to_hash[2*n + 3] = L;
        c_to_hash[2*n + 4] = R;
        c = hash_to_scalar(c_to_hash);
    }

    return c == sig.c1;
}

} // namespace cryptonote