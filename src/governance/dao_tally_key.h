// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Stable public tally key record.
//
// The long-lived Paillier public key generated once by the bootstrap
// DKG. It never changes. Every ballot is encrypted under this key.
// The tally committee selected at each proposal's voting end is a
// separate object (see dao_tally_session.h) and is not part of this
// record.
//
// The existing dao_tally_key_record remains on the wire. This split
// representation is additive; no existing byte layout is changed.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.h"
#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

struct dao_tally_public_key_record
{
    uint32_t             version   = 1;
    uint32_t             key_epoch = 0;

    std::vector<uint8_t> delta;   // 32 bytes, canonical big-endian
    std::vector<uint8_t> N;       // 256 bytes
    std::vector<uint8_t> G;       // 256 bytes, canonical big-endian (N+1)
    std::vector<uint8_t> theta;   // 256 bytes, canonical big-endian
    std::vector<uint8_t> V;       // 512 bytes, verification base

    // VSS group public parameters. These belong to the key system, not
    // to any particular committee, so they live here rather than on the
    // committee record.
    std::vector<uint8_t> vss_P;
    std::vector<uint8_t> vss_P_prime;
    std::vector<uint8_t> vss_g;
    std::vector<uint8_t> vss_h;

    // Deterministic hash of this complete public record.
    std::vector<uint8_t> key_id;               // 32 bytes

    // Bootstrap DKG transcript hash.
    std::vector<uint8_t> dkg_transcript_hash;  // 32 bytes

    uint64_t             activation_height = 0;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

} // namespace dao
} // namespace cryptonote
