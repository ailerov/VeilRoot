// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "governance/dao_crypto_backend.h"
#include "governance/dao_dkg.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

namespace cryptonote {
namespace dao {

struct cl_dkg_config
{
    // The class group every committee member shares. Constructed once
    // per ceremony from the proposal's activation record; the same
    // instance is passed to every committee member's runner.
    std::shared_ptr<BICYCL::CL_HSMqk> cl;

    uint32_t committee_size     = 0;
    uint32_t threshold_internal = 0;   // CL t_, i.e. threshold - 1
    std::vector<crypto::public_key> member_ids;
    crypto::hash proposal_id{};
    uint32_t local_party_id     = 0;   // 1..committee_size
    size_t   soundness_bytes    = 32;
    uint32_t phase_timeout_seconds = 120;

    // Optional test seed for deterministic per-party randomness. The
    // caller must supply a distinct seed for each committee member.
    // Zero means seed from the OS.
    uint64_t test_seed = 0;
};

struct cl_dkg_result
{
    bool ok = false;
    cl_key_context ctx;
};

class cl_dkg_p2p_runner
{
public:
    cl_dkg_p2p_runner(const cl_dkg_config& cfg,
                      std::unique_ptr<dkg_transport> transport);
    ~cl_dkg_p2p_runner();

    cl_dkg_p2p_runner(const cl_dkg_p2p_runner&) = delete;
    cl_dkg_p2p_runner& operator=(const cl_dkg_p2p_runner&) = delete;

    bool start();
    void stop();

    // Blocks until the ceremony finishes or timeout_s elapses (0 means
    // wait indefinitely). Returns out.ok.
    bool wait(cl_dkg_result& out, uint32_t timeout_s = 0);

    bool running()  const;
    bool finished() const;
    uint32_t local_party_id() const;

private:
    struct impl;
    std::unique_ptr<impl> p_;
};

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
