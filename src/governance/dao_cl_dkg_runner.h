// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

// Some system headers in this translation unit define a
// setbit(a,i) macro that collides with the bicycl function of
// the same name. Neutralize it here, before bicycl headers are
// pulled in by any include below.
#ifdef setbit
#undef setbit
#endif


#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
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
    crypto::hash attempt_id{};  // deterministic identity for this retry
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
    uint64_t selection_height = 0;
    crypto::hash attempt_id{};
    cl_key_context ctx;

    // Populated when ok == false. Identifies the stage that failed and,
    // for library exceptions, the wrapped message. Read only after the
    // runner's wait() has observed completion.
    std::string failure_stage;
    std::string failure_reason;

    // This node's secret share, encoded by serialize_secret_share() on
    // the wrapped player. Persist to the node's local store; never to
    // consensus state.
    std::vector<uint8_t> local_secret_share;

    // Public verification values, one per qualified player. Canonical
    // encoding; consensus-visible and bound to the share-set record.
    std::vector<uint8_t> gammas_serialized;

    // Qualified player identifiers (0-based internal ids), sorted.
    std::vector<uint32_t> qualified_ids;
};

// Simple dkg_transport adapter for the CL runner in production. Uses
// the same envelope layout as dkg_p2p_transport_local: broadcasts go
// out unchanged, recipient-targeted messages are sent through the
// caller-supplied send_to callback (which is expected to encrypt them).
// Inbound messages are delivered by Blockchain::handle_dao_v2_dkg_msg
// via deliver().
class cl_dkg_p2p_transport final : public dkg_transport
{
public:
    cl_dkg_p2p_transport(
        std::vector<crypto::public_key> members,
        std::function<bool(const crypto::public_key&,
                           const std::string&)> send_to,
        std::function<bool(const std::string&)> broadcast);

    bool send(const dkg_msg& m) override;
    bool recv(dkg_msg& m) override;
    bool try_recv(dkg_msg& m) override;
    void deliver(const dkg_msg& m) override;
    void shutdown() override;

private:
    std::vector<crypto::public_key> members_;
    std::function<bool(const crypto::public_key&,
                       const std::string&)> send_to_;
    std::function<bool(const std::string&)>    broadcast_;
    std::mutex               mu_;
    std::condition_variable  cv_;
    std::queue<dkg_msg>      queue_;
    bool                     stopped_ = false;
};

class cl_dkg_p2p_runner
{
public:
    cl_dkg_p2p_runner(const cl_dkg_config& cfg,
                      std::unique_ptr<dkg_transport> transport);
    cl_dkg_p2p_runner(const cl_dkg_config& cfg,
                      std::shared_ptr<dkg_transport> transport);
    ~cl_dkg_p2p_runner();

    cl_dkg_p2p_runner(const cl_dkg_p2p_runner&) = delete;
    cl_dkg_p2p_runner& operator=(const cl_dkg_p2p_runner&) = delete;

    bool start();
    void stop();

    // Deliver an inbound envelope to the local runner. Thread-safe.
    void on_message(const dkg_msg& m);

    // Blocks until the ceremony finishes or timeout_s elapses (0 means
    // wait indefinitely). Returns true on retrieval, false on timeout.
    // Inspect out.ok for protocol success.
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
