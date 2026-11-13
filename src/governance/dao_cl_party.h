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

namespace cryptonote {
namespace dao {

// One node's participation in a Threshold-CL keygen or reshare.
// Wraps exactly one BICYCL::CL_Threshold_Static and exposes the
// protocol stages a real node drives: dealing, receiving peer
// commitments/proofs/shares, verify, extract, then partial
// decryption and combination.
//
// The in-process CLCommittee holds n of these for test harnesses.
// The P2P runner holds exactly one per node. Same cryptographic
// code path either way — this class is the single-node execution
// context, not a parallel BICYCL implementation.
class CLCommitteeParty
{
public:
    // Fresh-keygen constructor: uses BICYCL's default D = n!.
    CLCommitteeParty(std::shared_ptr<BICYCL::CL_HSMqk> cl,
                     unsigned int n,
                     unsigned int t,
                     unsigned int local_id,
                     size_t soundness_bytes);

    // Explicit-D constructor: required when joining an existing key
    // via reshare. D is the key lifetime interpolation scale, not
    // the new committee's factorial.
    CLCommitteeParty(std::shared_ptr<BICYCL::CL_HSMqk> cl,
                     unsigned int n,
                     unsigned int t,
                     unsigned int local_id,
                     size_t soundness_bytes,
                     const BICYCL::Mpz& D);

    unsigned int local_id() const { return local_id_; }

    // Interpolation scale Delta. Fixed at key generation time
    // (default n!), immutable for the key lifetime. Required by the
    // reshare path and by the key context record.
    const BICYCL::Mpz& interpolation_scale() const;
    unsigned int committee_size() const { return n_; }
    unsigned int threshold() const { return t_ + 1; }

    // ---- Keygen stages ----
    // Deal this party's VSS polynomial. Caller must then distribute
    // keygen_commitments() and keygen_batch_proof() to every peer,
    // and keygen_y_k(peer_id) to that specific peer.
    bool keygen_dealing(BICYCL::RandGen& randgen);

    const std::vector<BICYCL::QFI>& keygen_commitments() const;
    const BICYCL::CL_HSMqk_Batch_Dlog_AoK& keygen_batch_proof() const;
    const BICYCL::Mpz& keygen_y_k(unsigned int recipient_id) const;

    bool keygen_add_commitments(unsigned int sender_id,
                                const std::vector<BICYCL::QFI>& C);
    bool keygen_add_proof(unsigned int sender_id,
                          const BICYCL::CL_HSMqk_Batch_Dlog_AoK& proof);
    bool keygen_add_share(unsigned int sender_id,
                          const BICYCL::Mpz& y);

    bool keygen_check_verify_all();
    bool keygen_extract();
    bool keygen_done() const { return keygen_done_; }

    // ---- Post-keygen ----
    const BICYCL::CL_HSMqk::PublicKey& public_key() const;

    // ---- Decryption stages ----
    bool partial_decrypt(const BICYCL::CL_HSMqk::CipherText& ct,
                         BICYCL::RandGen& randgen);

    const BICYCL::CL_Threshold_Static::PartialDecryption&
        partial() const;

    void add_partial_dec(
        unsigned int sender_id,
        const BICYCL::CL_Threshold_Static::PartialDecryption& pd);

    bool verify_partials(BICYCL::RandGen& randgen);

    bool combine(BICYCL::CL_HSMqk::ClearText& out,
                 const BICYCL::CL_HSMqk::CipherText& ct);

private:
    std::shared_ptr<BICYCL::CL_HSMqk> cl_;
    unsigned int n_;
    unsigned int t_;
    unsigned int local_id_;
    size_t soundness_bytes_;
    bool keygen_done_ = false;
    std::unique_ptr<BICYCL::CL_Threshold_Static> player_;
};

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
