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

// In-process orchestration of a t+1-of-n Threshold-CL committee over
// one CL class group. Wraps BICYCL's CL_Threshold_Static so the
// ceremony can be driven synchronously; a networked deployment drives
// the same stages over p2p.
class CLCommittee
{
public:
    CLCommittee(std::shared_ptr<BICYCL::CL_HSMqk> cl,
                unsigned int n,
                unsigned int t,
                size_t soundness_bits);

    // Run the keygen ceremony in-process. All n players participate.
    // After success, public_key() is valid and all players hold shares.
    bool run_keygen_inproc(BICYCL::RandGen& randgen);

    const BICYCL::CL_HSMqk::PublicKey& public_key() const;

    // Serialized (q, k, p, pk) wire, matching the format consumed by
    // DaoEncryptionBackend::deserialize_modulus. Returned bytes can be
    // handed to a freshly constructed backend to encrypt ballots under
    // the committee's shared public key.
    bool serialize_public_params(std::vector<uint8_t>& out) const;

    // Parse a wire-format ciphertext (QFI(c1) || QFI(c2)) into a
    // CL_HSMqk::CipherText under this committee's class group.
    bool ciphertext_from_bytes(const std::vector<uint8_t>& in,
                               BICYCL::CL_HSMqk::CipherText& out) const;

    // Serialize a CL_HSMqk::CipherText into the same wire format.
    bool ciphertext_to_bytes(const BICYCL::CL_HSMqk::CipherText& in,
                             std::vector<uint8_t>& out) const;

    // Partial decryption: player `i` produces its share plus proof.
    bool partial_decrypt(unsigned int i,
                         const BICYCL::CL_HSMqk::CipherText& ct,
                         BICYCL::RandGen& randgen);

    // Expose player i's most recent partial decryption for exchange.
    const BICYCL::CL_Threshold_Static::PartialDecryption&
        partial_dec_for_test(unsigned int i) const;

    // Distribute player j's partial decryption to player i.
    void add_partial_dec(
        unsigned int i, unsigned int j,
        const BICYCL::CL_Threshold_Static::PartialDecryption& pd);

    // Player i verifies all collected partial decryptions for the
    // ciphertext it last called partial_decrypt on.
    bool verify_partials(unsigned int i, BICYCL::RandGen& randgen);

    // Player i combines its collected partials to recover the plaintext.
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
    std::vector<std::unique_ptr<BICYCL::CL_Threshold_Static>> players_;
};

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
