// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Per-proposal tally session. Written at the proposal's voting end,
// after the committee has been selected deterministically from the
// canonical eligible-node state at that height.
//
// Public consensus state. No private share material.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"

namespace cryptonote {
namespace dao {

struct dao_tally_session
{
    uint32_t                          version = 1;

    // Bootstrap DKG key epoch the proposal's votes were encrypted
    // under. Not a per-proposal key. Every proposal in a DAO shares
    // the same bootstrap key epoch.
    uint32_t                          share_epoch = 0;

    crypto::hash                      proposal_id;
    crypto::hash                      public_key_id;

    uint64_t                          selection_height = 0;
    uint64_t                          vote_end_height  = 0;

    uint32_t                          committee_size = 0;
    uint32_t                          threshold      = 0;
    uint32_t                          t              = 0;

    crypto::hash                      committee_id_hash;

    // Ordered members of the TEMPORARY tally committee. Selected
    // deterministically at the proposal's voting end from the
    // bootstrap DKG shareholder set, filtered by current eligibility.
    // Temporary protocol role; not a permanent committee. Every
    // listed member already holds a bootstrap DKG share.
    std::vector<crypto::public_key>   committee_members;

    // For each entry in committee_members, the 1-based index of the
    // same node within the bootstrap key record's committee_members.
    // This is the index used to look up the node's bootstrap DKG
    // share and the V_K_i recorded in the key epoch. It is not the
    // position inside the temporary committee.
    std::vector<uint32_t>             committee_global_indices;

    bool                              tally_complete = false;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

} // namespace dao
} // namespace cryptonote
