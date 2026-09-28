// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_weight.h"

#include <cstring>

#include "ringct/rctOps.h"

using namespace rct;

namespace cryptonote {

void dao_weight_to_scalar(const governance_weight_t& w, key& out)
{
    std::memset(out.bytes, 0, 32);

    const governance_weight_t mask64 = (governance_weight_t(1) << 64) - 1;
    const uint64_t lo = (w & mask64).convert_to<uint64_t>();
    const uint64_t hi = (w >> 64).convert_to<uint64_t>();

    for (int i = 0; i < 8; ++i)
        out.bytes[i] = static_cast<uint8_t>((lo >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; ++i)
        out.bytes[i + 8] = static_cast<uint8_t>((hi >> (8 * i)) & 0xff);

    sc_reduce32(out.bytes);
}

bool dao_commit_output_weight(uint64_t amount,
                              uint8_t  age_factor,
                              const key& C_i,
                              const key& mask_i,
                              const key& rho_i,
                              dao_output_weight& out)
{
    key s_f;
    std::memset(s_f.bytes, 0, 32);
    s_f.bytes[0] = age_factor;
    sc_reduce32(s_f.bytes);

    // Q_i = f_i * C_i
    key Q_i;
    if (age_factor == 0)
        identity(Q_i);
    else
        scalarmultKey(Q_i, C_i, s_f);

    // V_i = Q_i + rho_i * G
    key rho_G;
    scalarmultBase(rho_G, rho_i);
    addKeys(out.commitment, Q_i, rho_G);

    // total_blinding = f_i*mask_i + rho_i
    key f_mask;
    sc_mul(f_mask.bytes, s_f.bytes, mask_i.bytes);
    sc_add(out.total_blinding.bytes, f_mask.bytes, rho_i.bytes);

    out.rho_i = rho_i;

    out.weight = governance_weight_t(amount) * governance_weight_t(age_factor);
    if (out.weight > governance_w_max())
        return false;

    return true;
}

void dao_aggregate_init(dao_vote_aggregate& agg)
{
    identity(agg.C_W);
    identity(agg.C_S);
    identity(agg.R_S);
    identity(agg.R_W);
    agg.W_total       = 0;
    agg.direction_yes = true;
    agg.num_inputs    = 0;
}

bool dao_accumulate_output(dao_vote_aggregate& agg, const dao_output_weight& ow)
{
    addKeys(agg.C_W, agg.C_W, ow.commitment);

    if (agg.num_inputs == 0)
        agg.R_W = ow.total_blinding;
    else
        sc_add(agg.R_W.bytes, agg.R_W.bytes, ow.total_blinding.bytes);

    agg.W_total += ow.weight;
    if (agg.W_total > governance_w_max())
        return false;

    ++agg.num_inputs;
    return true;
}

bool dao_finalize_aggregate(dao_vote_aggregate& agg,
                            bool yes,
                            const key& R_S)
{
    if (agg.num_inputs == 0) return false;
    if (sc_check(R_S.bytes) != 0) return false;

    agg.R_S = R_S;

    key w_scalar;
    dao_weight_to_scalar(agg.W_total, w_scalar);

    if (!yes)
    {
        key neg;
        sc_0(neg.bytes);
        sc_sub(neg.bytes, neg.bytes, w_scalar.bytes);
        w_scalar = neg;
    }

    key wH, rS_G;
    scalarmultKey(wH, H, w_scalar);
    scalarmultBase(rS_G, R_S);
    addKeys(agg.C_S, wH, rS_G);

    agg.direction_yes = yes;
    return true;
}

bool dao_verify_aggregate(const dao_vote_aggregate& agg)
{
    if (agg.num_inputs == 0) return false;

    // C_W = R_W*G + W_total*H
    key w_scalar;
    dao_weight_to_scalar(agg.W_total, w_scalar);

    key rW_G, wH, expected_C_W;
    scalarmultBase(rW_G, agg.R_W);
    scalarmultKey(wH, H, w_scalar);
    addKeys(expected_C_W, rW_G, wH);

    if (!(expected_C_W == agg.C_W)) return false;

    // C_S = ±W_total*H + R_S*G
    key s_scalar;
    dao_weight_to_scalar(agg.W_total, s_scalar);
    if (!agg.direction_yes)
    {
        key neg;
        sc_0(neg.bytes);
        sc_sub(neg.bytes, neg.bytes, s_scalar.bytes);
        s_scalar = neg;
    }

    key sH, rS_G2, expected_C_S;
    scalarmultKey(sH, H, s_scalar);
    scalarmultBase(rS_G2, agg.R_S);
    addKeys(expected_C_S, sH, rS_G2);

    return expected_C_S == agg.C_S;
}

} // namespace cryptonote