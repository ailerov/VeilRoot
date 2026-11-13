// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#ifdef VEILROOT_ENABLE_CL

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"

namespace cryptonote {
namespace dao {

struct dao_cl_reshare_params
{
    unsigned int                        n_old = 0;
    unsigned int                        t_old = 0;
    unsigned int                        n_new = 0;
    unsigned int                        t_new = 0;
    std::vector<unsigned int>           old_contributors;
    size_t                              soundness_bytes = 16;
};

// In-process reshare driver. Requires:
//   - old_players[k]   constructed with (n_old, t_old, k), DKG-complete
//                      (keygen_extract already called on each)
//   - new_players[j]   constructed with (n_new, t_new, j), fresh
//                      (no shares, no pk)
// After success, each new_players[j] holds a share of the same
// aggregate secret as old committee, public key matches old pk, and
// decrypt_partial / verify / combine work unchanged on the new
// instances.
//
// Rejection semantics: returns false if any step throws. On false the
// state of new_players is undefined and callers must discard them.
bool dao_cl_reshare_inproc(
    const BICYCL::CL_HSMqk& CL,
    const std::vector<std::unique_ptr<BICYCL::CL_Threshold_Static>>& old_players,
    const std::vector<std::unique_ptr<BICYCL::CL_Threshold_Static>>& new_players,
    const dao_cl_reshare_params& params,
    BICYCL::RandGen& randgen,
    std::string* error_out = nullptr);

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
