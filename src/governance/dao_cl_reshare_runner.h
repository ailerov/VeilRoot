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

    // Reshare session binding. All nodes in one reshare attempt must
    // agree on this value; every CL reshare payload carries it and
    // messages from other sessions are silently dropped. Derived by
    // dao_cl_reshare_compute_session_id() from the fields below.
    crypto::hash session_id{};

    // Old-generation identifiers used both in the session derivation
    // and in the resulting share-set record.
    uint64_t             old_share_set_id = 0;
    std::vector<uint8_t> old_committee_id_hash;  // 32 bytes
    std::vector<uint8_t> new_committee_id_hash;  // 32 bytes

    // Qualified CL ids of the OLD committee, sorted, 0-based. Must be a
    // subset of the old Gamma map's keys. The runner restores against
    // this set, not all_old. The selected old_contributors must be a
    // subset.
    std::vector<uint32_t> old_qualified_ids;

    uint32_t     soundness_bytes      = 32;
    uint32_t     phase_timeout_seconds = 180;
    uint64_t     test_seed            = 0;
    crypto::hash proposal_id{};
};

// Compute the reshare session id from the fields that identify one
// reshare attempt. Domain-separated, deterministic, identical on every
// node. Empty on malformed inputs.
crypto::hash dao_cl_reshare_compute_session_id(
    const crypto::hash& proposal_id,
    uint64_t old_share_set_id,
    const std::vector<uint8_t>& old_committee_id_hash,
    const std::vector<uint8_t>& new_committee_id_hash,
    const std::vector<uint32_t>& sorted_old_contributors);

struct cl_reshare_result
{
    bool ok = false;

    // True when this node is a member of the NEW committee and has a
    // new local share to persist. False for old-only contributors:
    // they can complete successfully without producing a new share.
    bool has_local_new_share = false;

    // This node's new share, wire form of serialize_secret_share().
    // Populated only when has_local_new_share is true.
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

    // Session identity this runner is bound to.
    crypto::hash session_id() const;

    // Deliver an inbound dkg_msg to the runner. Mirrors the CL DKG
    // runner's interface: validates the outer envelope and forwards to
    // the underlying transport, which queues it for the worker. The
    // caller (Blockchain ingress) is responsible for authenticated
    // sender-identity checks.
    void on_message(const dkg_msg& m);

    // Count of unique accepted public dealer contributions. For
    // reshare-runner test coverage; not used in production.
    size_t contribution_count_for_test() const;

private:
    struct impl;
    std::unique_ptr<impl> p_;
};

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
