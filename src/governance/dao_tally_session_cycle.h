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
    // canonical eligible-node state. Disjoint from the bootstrap
    // shareholder set that owns the key epoch.
    std::vector<crypto::public_key>   committee_members;

    // Members of the share-holder set that owns the PREVIOUS share
    // epoch. For the first session of a key epoch this is the
    // bootstrap DKG shareholder set. For every later session it is
    // the committee of the immediately preceding session. Used to
    // authenticate reshare_ready / reshare_commit / reshare_share
    // senders against their claimed 1-based old_member_id.
    std::vector<crypto::public_key>   prev_committee_members;

    // share_epoch of the previous session this one resets from.
    // 0 means the bootstrap DKG: the old share is read from
    // dao_local_share[bootstrap_key_epoch, bootstrap_id].
    // Non-zero means the previous dynamic session's share is read
    // from dao_local_dynamic_share[prev_share_epoch].
    uint32_t                          prev_share_epoch = 0;

    // Per-member verification keys for the temporary committee, one
    // per committee_members entry, in the same order. Derived after
    // the Reset produces SK'_j for each member:
    //   committee_V_K_i[i] = V_K^(Delta * SK'_j)
    // The bootstrap record's V_K_i are for a different set and must
    // not be used to verify partial decryptions from this committee.
    std::vector<std::vector<uint8_t>> committee_V_K_i;

    bool                              resharing_complete = false;
    bool                              tally_complete     = false;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

} // namespace dao
} // namespace cryptonote
