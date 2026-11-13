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

struct cl_reshare_config
{
    std::shared_ptr<BICYCL::CL_HSMqk> cl;

    // Key-lifetime interpolation scale. Same value old and new
    // committees must use; passed to the underlying player.
    std::vector<uint8_t> D_signed;

    uint32_t old_n            = 0;
    uint32_t old_t_internal   = 0;
    std::vector<uint32_t> old_contributors;  // 0-based, sorted

    uint32_t new_n            = 0;
    uint32_t new_t_internal   = 0;

    bool     is_old_contributor = false;
    uint32_t old_local_id       = 0;

    bool     is_new_member = false;
    uint32_t new_local_id  = 0;

    // The public key being preserved, wire form of the QFI.
    std::vector<uint8_t> old_pk_qfi;

    // Old verification values, one per old committee member. Wire form
    // produced by cl_dkg_serialize_gammas().
    std::vector<uint8_t> old_gammas_serialized;

    // This node's old share, wire form of serialize_secret_share().
    // Required only when is_old_contributor is true.
    std::vector<uint8_t> old_share_bytes;

    uint32_t     soundness_bytes      = 32;
    uint32_t     phase_timeout_seconds = 180;
    uint64_t     test_seed            = 0;
    crypto::hash proposal_id{};
};

struct cl_reshare_result
{
    bool ok = false;

    // This node's new share, wire form of serialize_secret_share().
    std::vector<uint8_t> new_share_bytes;

    // New aggregate verification values.
    std::vector<uint8_t> new_gammas_serialized;
    std::vector<uint32_t> qualified_ids;

    // Must equal the config's old_pk_qfi on success.
    std::vector<uint8_t> pk_qfi;
};

class cl_reshare_p2p_runner
{
public:
    cl_reshare_p2p_runner(const cl_reshare_config& cfg,
                          std::unique_ptr<dkg_transport> transport);
    ~cl_reshare_p2p_runner();

    cl_reshare_p2p_runner(const cl_reshare_p2p_runner&) = delete;
    cl_reshare_p2p_runner& operator=(const cl_reshare_p2p_runner&) = delete;

    bool start();
    void stop();
    bool wait(cl_reshare_result& out, uint32_t timeout_s = 0);

    bool running()  const;
    bool finished() const;

private:
    struct impl;
    std::unique_ptr<impl> p_;
};

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
