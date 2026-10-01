// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// V2 final tally. A tally certificate is a self-contained, independently
// verifiable object that carries:
//   - the three aggregate ciphertexts (E_W, E_S, E_B),
//   - the partial decryptions published by a threshold-sized subset of
//     the epoch's committee,
//   - the corresponding partial-decryption proofs.
//
// Verification recombines the shares per Nishide-Sakurai, recovers
// (W_total, S_total, B_total), and evaluates the final governance rule:
//
//   quorum_met   = B_total >= floor(10 * circulating / 100)
//   majority_met = YES_weight > NO_weight
//   passed       = quorum_met && majority_met
//
// B (participation coins) governs quorum. W and S (voting weight) govern
// majority. The two quantities are never substituted for one another.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crypto/hash.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_supply.h"

namespace cryptonote {
namespace dao {

// Hash that binds a certificate to the exact (E_W, E_S, E_B) tuple it
// decrypts. Uses SHA-256 over "VeilRoot-DAO-TALLY-CIPHERTEXTS-V1",
// version, and the three 512-byte ciphertexts.
crypto::hash dao_aggregate_ciphertext_hash(
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B);

// A partial-decryption set for one aggregate. Member indices and
// partials must be the same length and in the same order. Each entry
// corresponds to one member of the epoch's committee.
struct dao_partial_set
{
    std::vector<uint32_t>                    member_indices;
    std::vector<std::vector<uint8_t>>        partials;   // 512 bytes each
    std::vector<dao_partial_decryption_proof> proofs;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

struct dao_tally_certificate
{
    crypto::hash         proposal_id;
    uint64_t             vote_end_height = 0;
    uint32_t             tally_key_epoch = 0;
    crypto::hash         aggregate_ciphertext_hash;

    dao_partial_set      W;
    dao_partial_set      S;
    dao_partial_set      B;

    // Recovered plaintexts. S_total is signed.
    dao_u128             W_total    = 0;
    bool                 s_negative = false;
    dao_u128             S_abs      = 0;
    dao_u128             B_total    = 0;

    // Evaluated governance result. Always recomputed on verification.
    dao_u128             YES_weight       = 0;
    dao_u128             NO_weight        = 0;
    dao_u128             quorum_threshold = 0;
    bool                 quorum_met       = false;
    bool                 majority_met     = false;
    bool                 passed           = false;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

// Pure evaluation helper. Independent of cryptography so it can be
// tested directly. circulating_supply_at_vote_end is read from
// supply_history[vote_end_height].
//
// Returns false on any structural violation (e.g. quorum_percent
// out of range, or B_total > circulating which would indicate a
// corrupt certificate).
bool dao_evaluate_v2_tally(
    const dao_u128& yes_weight,
    const dao_u128& no_weight,
    const dao_u128& participation_coins,
    const dao_u128& circulating_supply_at_vote_end,
    uint32_t        quorum_percent,
    dao_u128&       quorum_threshold_out,
    bool&           quorum_met_out,
    bool&           majority_met_out,
    bool&           passed_out);

// Build a certificate from a set of partial decryptions. The member
// indices must all be in 1..key_rec.committee_size and must be distinct.
// Each set must have at least key_rec.threshold entries. The proofs
// must be valid; this function verifies them before accepting.
//
// Also computes the aggregate ciphertext hash and fills the plaintext
// recovery fields. The governance evaluation fields are left zero; call
// dao_verify_tally_certificate to recompute them.
bool dao_build_tally_certificate(
    const dao_tally_key_record& key_rec,
    const crypto::hash& proposal_id,
    uint64_t vote_end_height,
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B,
    const dao_partial_set& W_set,
    const dao_partial_set& S_set,
    const dao_partial_set& B_set,
    dao_tally_certificate& cert_out);

// Fully verify a certificate against a key record and the historical
// supply snapshot at the proposal's voting-end height.
//
// Checks, in order:
//   1. proposal_id, vote_end_height, tally_key_epoch match the inputs.
//   2. aggregate_ciphertext_hash matches SHA-256 over E_W, E_S, E_B.
//   3. Every partial set has >= key_rec.threshold entries.
//   4. Every member index is in 1..committee_size and unique.
//   5. Every partial-decryption proof verifies against key_rec.V,
//      key_rec.V_K_i[member-1], and the corresponding ciphertext.
//   6. Threshold recombination recovers W_total, S_total, B_total.
//   7. Recovered totals match the plaintext fields in the certificate.
//   8. Governance evaluation against the supply snapshot succeeds.
//
// Returns false on any failure. On success, cert_out's governance
// evaluation fields are overwritten with the recomputed values.
bool dao_verify_tally_certificate(
    const dao_tally_key_record& key_rec,
    const dao_supply_snapshot&  supply_at_vote_end,
    uint32_t                    quorum_percent,
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B,
    dao_tally_certificate&      cert);

} // namespace dao
} // namespace cryptonote
