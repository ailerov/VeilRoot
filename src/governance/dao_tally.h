// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// V2 final tally. A tally certificate is a self-contained, independently
// verifiable object that carries:
//   - the three aggregate ciphertexts (E_W, E_S, E_B),
//   - the partial decryptions published by a threshold-sized subset of
//     the tally committee,
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
// corresponds to one member of the tally committee.
struct dao_partial_set
{
    std::vector<uint32_t>                    member_indices;
    std::vector<std::vector<uint8_t>>        partials;   // 512 bytes each
    std::vector<dao_partial_decryption_proof> proofs;

    // CL partial decryptions. Each entry is the canonical output of
    // dao_cl_partial_decryption_serialize(): QFI(w) || SCALAR(u) ||
    // QFI(R1) || QFI(R2). Parallel to member_indices. Populated only
    // on the CL path; the Paillier serialize()/deserialize() leave
    // this empty.
    std::vector<std::vector<uint8_t>>        cl_partials;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);

    // CL wire form. Emits a discriminator tag so a CL-format set is
    // never mistaken for the Paillier layout, and both formats can be
    // distinguished by a reader that has not yet been upgraded.
    //   u8 format_tag (0x02 = CL)
    //   u32 count
    //   { u32 member_index || u32 len || partial }  per entry
    static constexpr inline uint8_t CL_FORMAT_TAG = 0x02;
    static constexpr inline uint32_t CL_PARTIAL_MAX_BYTES = 16384;

    bool serialize_cl(std::vector<uint8_t>& out) const;
    bool deserialize_cl(const std::vector<uint8_t>& in);
};

struct dao_tally_certificate
{
    static constexpr uint8_t WIRE_VERSION    = 6;
    static constexpr uint8_t WIRE_VERSION_CL = 7;

    crypto::hash         proposal_id;
    uint64_t             vote_end_height = 0;
    std::vector<uint8_t> key_id;  // 32 bytes; binds to stable tally key
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

    // --- v6: reshare evidence ---
    // All zero / empty means the committee equals the acceptance-time
    // committee and partials verify against key_rec.V_K_i with
    // key_rec.threshold (v5-equivalent behaviour).
    //
    // When per_event_share_set_id != 0, the cert claims a reshare
    // occurred. The evidence is verified against these fields
    // instead of key_rec's; certs whose evidence does not verify
    // are rejected.
    uint64_t                              per_event_share_set_id = 0;
    uint32_t                              threshold              = 0;
    std::vector<std::vector<uint8_t>>     member_pubkeys;   // 32 bytes each
    std::vector<std::vector<uint8_t>>     per_event_VK_i;   // PAILLIER_CT_BYTES each
    uint64_t                              base_share_set_id = 0;
    std::vector<std::vector<uint8_t>>     contributions;
    std::vector<uint32_t>                 contributor_indices;
    std::vector<std::vector<uint8_t>>     contributor_vk;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

// The final V2 governance outcome for a proposal. Written
// automatically by the automatic tally state machine when the
// committee threshold has been reached. This is consensus state, not
// a user-submitted object.
struct dao_v2_outcome_record
{
    static constexpr uint8_t WIRE_VERSION = 3;

    crypto::hash         proposal_id;
    uint64_t             vote_end_height = 0;
    std::vector<uint8_t> key_id;  // 32 bytes; stable tally key
    crypto::hash         aggregate_ciphertext_hash;

    dao_u128     yes_weight          = 0;
    dao_u128     no_weight           = 0;
    dao_u128     participation_coins = 0;
    dao_u128     quorum_threshold    = 0;

    bool         quorum_met    = false;
    bool         majority_met  = false;
    bool         passed        = false;

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

// Canonical bootstrap share set derived from the key record. Used as
// the current share set until resharing writes a new one. In this set,
// share-set positions are identical to bootstrap DKG indices.
// Deterministic per-key share-set id. Bootstrap (default) uses 1;
// per-proposal keys derive a stable uint32 from key_id. Reserved: 0
// (none), 1 (bootstrap).
uint32_t share_set_id_for_key_id(const std::vector<uint8_t>& key_id);

// Build a tally certificate. The key record must carry a CL key
// context. The share set must be a CL share set (v3) with a Gamma map
// and a qualified-id list, matching the key record's key_id. Partial
// sets must be CL form (cl_partials populated).
bool dao_build_tally_certificate(
    const dao_tally_key_record& key_rec,
    const dao_share_set_record& share_set,
    const crypto::hash& proposal_id,
    uint64_t vote_end_height,
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B,
    const dao_partial_set& W_set,
    const dao_partial_set& S_set,
    const dao_partial_set& B_set,
    dao_tally_certificate& cert_out);

// Verify a tally certificate. Mirrors the builder's checks and
// re-derives the recovered totals from the partial decryptions.
bool dao_verify_tally_certificate(
    const dao_tally_key_record& key_rec,
    const dao_share_set_record& share_set,
    const dao_supply_snapshot&  supply_at_vote_end,
    uint32_t                    quorum_percent,
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B,
    dao_tally_certificate&      cert);

} // namespace dao
} // namespace cryptonote
