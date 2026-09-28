// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_vote_or_proof.h"

#include <cstring>

#include "ringct/rctOps.h"

using namespace rct;

namespace cryptonote {

namespace {

constexpr const char* OR_DOMAIN = "VeilRoot-DAO-OR-V2";  // 19 bytes

void push_le32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i)
        v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
}

void push_le64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i)
        v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
}

void push_key(std::vector<uint8_t>& v, const key& k)
{
    v.insert(v.end(), k.bytes, k.bytes + 32);
}

key compute_or_challenge(const dao_or_context& ctx,
                         const key& T0, const key& T1,
                         const key& D0, const key& D1)
{
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), OR_DOMAIN, OR_DOMAIN + 19);
    buf.push_back(ctx.version);

    const uint8_t* pi = reinterpret_cast<const uint8_t*>(ctx.proposal_id.data);
    buf.insert(buf.end(), pi, pi + 32);
    push_le64(buf, ctx.vote_height);

    push_le32(buf, static_cast<uint32_t>(ctx.nullifiers.size()));
    for (const auto& nf : ctx.nullifiers)
        push_key(buf, nf);

    push_le32(buf, static_cast<uint32_t>(ctx.key_offsets.size()));
    for (uint64_t ko : ctx.key_offsets)
        push_le64(buf, ko);

    push_le32(buf, static_cast<uint32_t>(ctx.extra_binding.size()));
    buf.insert(buf.end(), ctx.extra_binding.begin(), ctx.extra_binding.end());

    push_key(buf, ctx.C_W);
    push_key(buf, ctx.C_S);
    push_key(buf, T0);
    push_key(buf, T1);
    push_key(buf, D0);
    push_key(buf, D1);

    key out;
    cn_fast_hash(out, buf.data(), buf.size());
    sc_reduce32(out.bytes);
    return out;
}

} // anonymous namespace

bool dao_or_prove(const dao_or_context& ctx,
                  bool direction_yes,
                  const key& R_S,
                  const key& R_W,
                  dao_vote_or_proof& proof)
{
    key D0, D1;
    subKeys(D0, ctx.C_S, ctx.C_W);
    addKeys(D1, ctx.C_S, ctx.C_W);
    if (D0 == identity() || D1 == identity()) return false;

    // r = dlog of the known branch.
    key r;
    if (direction_yes)
        sc_sub(r.bytes, R_S.bytes, R_W.bytes);
    else
        sc_add(r.bytes, R_S.bytes, R_W.bytes);

    const int j = direction_yes ? 0 : 1;

    key k = skGen();
    key T_known;
    scalarmultBase(T_known, k);

    key c_unknown = skGen();
    key s_unknown = skGen();

    key sG, cD, T_unknown;
    scalarmultBase(sG, s_unknown);
    const key& D_unknown = (j == 0) ? D1 : D0;
    scalarmultKey(cD, D_unknown, c_unknown);
    subKeys(T_unknown, sG, cD);

    key T0, T1;
    if (j == 0) { T0 = T_known; T1 = T_unknown; }
    else        { T0 = T_unknown; T1 = T_known; }

    key c = compute_or_challenge(ctx, T0, T1, D0, D1);

    key c_known;
    sc_sub(c_known.bytes, c.bytes, c_unknown.bytes);

    key c_r, s_known;
    sc_mul(c_r.bytes, c_known.bytes, r.bytes);
    sc_add(s_known.bytes, k.bytes, c_r.bytes);

    if (j == 0)
    {
        proof.c_yes = c_known;
        proof.s_yes = s_known;
        proof.c_no  = c_unknown;
        proof.s_no  = s_unknown;
    }
    else
    {
        proof.c_yes = c_unknown;
        proof.s_yes = s_unknown;
        proof.c_no  = c_known;
        proof.s_no  = s_known;
    }

    sc_0(k.bytes);
    sc_0(r.bytes);
    return true;
}

bool dao_or_verify(const dao_or_context& ctx,
                   const dao_vote_or_proof& proof)
{
    if (sc_check(proof.c_yes.bytes) != 0) return false;
    if (sc_check(proof.c_no.bytes)  != 0) return false;
    if (sc_check(proof.s_yes.bytes) != 0) return false;
    if (sc_check(proof.s_no.bytes)  != 0) return false;

    key D0, D1;
    subKeys(D0, ctx.C_S, ctx.C_W);
    addKeys(D1, ctx.C_S, ctx.C_W);
    if (D0 == identity() || D1 == identity()) return false;

    key sG_yes, cD_yes, T0;
    scalarmultBase(sG_yes, proof.s_yes);
    scalarmultKey(cD_yes, D0, proof.c_yes);
    subKeys(T0, sG_yes, cD_yes);

    key sG_no, cD_no, T1;
    scalarmultBase(sG_no, proof.s_no);
    scalarmultKey(cD_no, D1, proof.c_no);
    subKeys(T1, sG_no, cD_no);

    key c = compute_or_challenge(ctx, T0, T1, D0, D1);

    key sum;
    sc_add(sum.bytes, proof.c_yes.bytes, proof.c_no.bytes);
    return sum == c;
}

} // namespace cryptonote