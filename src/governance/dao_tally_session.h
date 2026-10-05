// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Dynamic tally committee record.
//
// A committee is selected deterministically at a proposal's voting end
// from the eligible-node state. Its secret shares are derived from the
// stable Paillier key (see dao_tally_key.h) by dynamic threshold
// resharing; the secret itself is never reconstructed. The committee
// disbands after tally.
//
// This record is public. It carries no private share material.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.h"
#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

struct dao_tally_committee_record
{
    uint32_t                          version        = 1;
    uint32_t                          share_epoch    = 0;
    uint32_t                          committee_size = 0;
    uint32_t                          threshold      = 0;
    uint32_t                          t              = 0;

    std::vector<uint8_t>              public_key_id;      // 32 bytes
    std::vector<uint8_t>              committee_id_hash;  // 32 bytes

    // Ordered committee member public keys, 32 bytes each. Same shape as
    // dao_tally_key_record::committee_members.
    std::vector<std::vector<uint8_t>> committee_members;

    std::vector<std::vector<uint8_t>> V_K_i;   // one per member, 512 bytes each

    uint64_t                          selection_height  = 0;
    uint64_t                          activation_height = 0;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

} // namespace dao
} // namespace cryptonote
