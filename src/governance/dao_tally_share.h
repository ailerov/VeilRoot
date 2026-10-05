// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One committee member's partial decryptions of the current aggregate
// for a single proposal. Exchanged over the P2P layer between nodes,
// exactly like the V1 NOTIFY_DECRYPTION_SHARE message. It is NOT a
// transaction, NOT block state, and NOT user-submitted.
//
// The share binds to the exact aggregate via aggregate_ciphertext_hash:
// if the aggregate changes (a new vote lands before finalization, or a
// reorg reverts one), all shares for the old aggregate become unusable.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.h"
#include "governance/dao_dkg.h"

namespace cryptonote {
namespace dao {

struct dao_v2_tally_share
{
    uint8_t      version = 1;
    crypto::hash proposal_id;
    uint64_t     vote_end_height = 0;

    // Stable Paillier public-key epoch the aggregate was encrypted
    // under. Set at proposal submission; never changes.
    uint32_t     tally_key_epoch = 0;

    // Share-session identity. Names the temporary tally committee
    // that produced this share. Multiple proposals ending at the same
    // height share a session (and therefore a share_epoch). A share
    // from an earlier session is rejected even if its key_epoch
    // matches.
    uint32_t     share_epoch = 0;

    crypto::hash aggregate_ciphertext_hash;

    uint32_t             member_index = 0;   // 1..committee_size

    std::vector<uint8_t> partial_W;          // 512 bytes
    std::vector<uint8_t> partial_S;          // 512 bytes
    std::vector<uint8_t> partial_B;          // 512 bytes

    dao_partial_decryption_proof proof_W;
    dao_partial_decryption_proof proof_S;
    dao_partial_decryption_proof proof_B;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

} // namespace dao
} // namespace cryptonote
