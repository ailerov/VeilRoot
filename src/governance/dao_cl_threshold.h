// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#ifdef VEILROOT_ENABLE_CL

#include <cstdint>
#include <memory>
#include <vector>

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"

#include "governance/dao_cl_party.h"

namespace cryptonote {
namespace dao {

// In-process orchestration of a t+1-of-n Threshold-CL committee over
// one CL class group. Holds n CLCommitteeParty objects, one per
// simulated node. Public surface unchanged from before the party
// refactor; existing tests exercise this class.
//
// The single-party class CLCommitteeParty is what a production
// node's P2P runner holds. CLCommittee uses the exact same party
// implementation for its in-process simulation, so the harness and
// the runtime cannot diverge cryptographically.
class CLCommittee
{
public:
    CLCommittee(std::shared_ptr<BICYCL::CL_HSMqk> cl,
                unsigned int n,
                unsigned int t,
                size_t soundness_bits);

    bool run_keygen_inproc(BICYCL::RandGen& randgen);

    const BICYCL::CL_HSMqk::PublicKey& public_key() const;

    bool serialize_public_params(std::vector<uint8_t>& out) const;

    bool ciphertext_from_bytes(const std::vector<uint8_t>& in,
                               BICYCL::CL_HSMqk::CipherText& out) const;

    bool ciphertext_to_bytes(const BICYCL::CL_HSMqk::CipherText& in,
                             std::vector<uint8_t>& out) const;

    bool partial_decrypt(unsigned int i,
                         const BICYCL::CL_HSMqk::CipherText& ct,
                         BICYCL::RandGen& randgen);

    const BICYCL::CL_Threshold_Static::PartialDecryption&
        partial_dec_for_test(unsigned int i) const;

    void add_partial_dec(
        unsigned int i, unsigned int j,
        const BICYCL::CL_Threshold_Static::PartialDecryption& pd);

    bool verify_partials(unsigned int i, BICYCL::RandGen& randgen);

    bool combine(unsigned int i,
                 BICYCL::CL_HSMqk::ClearText& out,
                 const BICYCL::CL_HSMqk::CipherText& ct);

    unsigned int n() const { return n_; }
    unsigned int t_plus_1() const { return t_ + 1; }

private:
    std::shared_ptr<BICYCL::CL_HSMqk> cl_;
    unsigned int n_;
    unsigned int t_;
    size_t soundness_bits_;
    bool keygen_done_ = false;
    std::vector<std::unique_ptr<CLCommitteeParty>> parties_;
};

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
