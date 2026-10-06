// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reset transcript. Records the public wire messages of a single Reset
// session and, for private messages, a hash of their encrypted
// envelope. The plaintext of a private message is never recorded.
//
// The finalized transcript is bound into the tally session so that a
// partial decryption generated in one Reset cannot be replayed into
// another. Two nodes that observed the same message set, in any order,
// derive the same transcript hash.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_reset.h"

namespace cryptonote {
namespace dao {

class dao_dkg_reset_transcript
{
public:
    // Public message: canonical serialized bytes are recorded.
    void append_public(const dkg_msg& msg);

    // Private message: only SHA256(domain || canonical serialized
    // encrypted envelope) is recorded. The caller must pass the
    // encrypted envelope, not the plaintext.
    void append_private(const dkg_msg& encrypted_msg);

    // Finalize the transcript hash over the sorted message set.
    void hash(
        const dao_dkg_reset_config& cfg,
        const crypto::hash& proposal_id,
        std::vector<uint8_t>& out) const;

private:
    struct entry
    {
        uint32_t             sender_id = 0;
        uint32_t             recipient_id = 0;
        uint8_t              type = 0;
        uint64_t             sequence = 0;
        bool                 private_leaf = false;
        std::vector<uint8_t> canonical;
    };

    std::vector<entry> entries_;
};

} // namespace dao
} // namespace cryptonote
