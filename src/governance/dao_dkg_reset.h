// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Dynamic tally-share transition (Reset).
//
// Reference:
//   Klinger, Wüller, Traverso, Meyer,
//   "Hierarchical and dynamic threshold Paillier cryptosystem
//    without trusted dealer", 2021,
//   using the Reset procedure of the underlying dynamic and verifiable
//   hierarchical secret sharing construction (Cryptology ePrint
//   Archive 2017/724, §Reset).
//
// The Reset keeps the Paillier private key exactly, changes only the
// shareholder access structure, and never reconstructs the private key.
//
// ====================================================================
// MAPPING PREREQUISITE — IMPLEMENTATION NOT YET WRITTEN
// ====================================================================
//
// The .cpp below is a stub returning false. Before it can be
// implemented, the following VeilRoot-specific values must be mapped
// onto the paper's representation:
//
//   VeilRoot state                    paper object
//   ----------------------------      ---------------------------------
//   integer share f(i)                sigma_i = f(x_i)
//   polynomial degree t = T - 1       paper degree d
//   Delta = 16!                       VeilRoot normalisation. Reset
//                                     preserves f(0), so Delta is
//                                     unchanged by Reset. Existing
//                                     dao_threshold_partial_decrypt,
//                                     dao_threshold_combine, and
//                                     dao_threshold_finalize run
//                                     unchanged on the new shares.
//   theta_prime                       public normalisation parameter.
//                                     Unchanged by Reset.
//   VSS group (P, P', g, h)           Pedersen commitment group used
//                                     for subshare verification.
//   V_K, V_K_i                        partial-decryption verification
//                                     keys. Refreshed per committee.
//   SK_i = N*F1(i) - theta_tilde      local private share consumed by
//                                     Reset as input. Never transmitted
//                                     except as encrypted, recipient-
//                                     targeted subshare payloads.
//
// The exact subshare polynomial construction, the Lagrange/Birkhoff
// coefficients, the commitment/witness data, and the new-share
// verification relation will be transcribed from Protocol 3.3 (Add)
// and Protocol 3.4 (Reset) of the Klinger paper, or equivalently from
// the Reset procedure of eprint 2017/724. They are NOT inferred from
// summary prose. No implementation lines exist below the public API
// until that transcription is present.
//
// ====================================================================

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "governance/dao_paillier.h"
#include "governance/dao_tally_key.h"

namespace cryptonote {
namespace dao {

struct dao_dkg_reset_config
{
    uint32_t old_epoch = 0;
    uint32_t new_epoch = 0;

    uint32_t old_threshold = 0;
    uint32_t new_threshold = 0;

    std::vector<crypto::public_key> old_members;
    std::vector<crypto::public_key> new_members;

    crypto::hash key_id{};
    crypto::hash old_committee_id{};
    crypto::hash new_committee_id{};
};

struct dao_dkg_reset_result
{
    bool ok = false;

    uint32_t new_epoch     = 0;
    uint32_t new_threshold = 0;

    crypto::hash transcript_hash{};
    crypto::hash new_committee_id{};

    // New local share for THIS node in the new committee, in the same
    // signed big-endian encoding as dkg_result::local_secret_share.
    // Empty if this node is not a member of new_members.
    std::vector<uint8_t> local_share;

    // Per-new-member verification material, in the same order as
    // cfg.new_members. Feeds the new share session's V_K_i.
    std::vector<std::vector<uint8_t>> new_verification_keys;
};

// Consume only the local old share. Never a reconstructed secret.
// `public_key` is the stable bootstrap Paillier public key; its VSS
// group parameters drive the Pedersen subshare verification.
bool dao_dkg_reset(
    const dao_dkg_reset_config& cfg,
    const std::vector<uint8_t>& local_old_share,
    const dao_tally_public_key_record& public_key,
    dao_dkg_reset_result& result);

} // namespace dao
} // namespace cryptonote
