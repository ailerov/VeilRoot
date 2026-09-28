// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_weight.h"

#include <cstring>

#include "ringct/rctOps.h"

using namespace rct;

namespace cryptonote {

bool dao_commit_output_weight(uint64_t amount,
                              uint8_t  age_factor,
                              const key& C_i,
                              const key& rho_i,
                              dao_output_weight& out)
{
    // Q_i = f_i * C_i (identity if f_i == 0).
    key Q_i;
    if (age_factor == 0)
    {
        identity(Q_i);
    }
    else
    {
        key s_f;
        std::memset(s_f.bytes, 0, 32);
        s_f.bytes[0] = age_factor;
        sc_reduce32(s_f.bytes);
        scalarmultKey(Q_i, C_i, s_f);
    }

    // V_i = Q_i + rho_i * G
    key rho_G;
    scalarmultBase(rho_G, rho_i);
    addKeys(out.commitment, Q_i, rho_G);
    out.blinding = rho_i;

    // W_i = amount * f_i in the frozen 128-bit governance domain.
    out.weight = governance_weight_t(amount) * governance_weight_t(age_factor);
    if (out.weight > governance_w_max())
        return false;

    return true;
}

} // namespace cryptonote