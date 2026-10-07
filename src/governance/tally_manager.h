// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Automatic V2 tally engine. Mirrors the V1 handle_decryption_share /
// finalize_tally pattern: committee members publish threshold shares
// over the P2P layer, every node validates them, and once the epoch
// threshold is reached the outcome is combined and written to
// consensus state automatically. No user action, no transaction, no
// external submitter.

#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "crypto/hash.h"
#include "governance/dao_dkg.h"
#include "governance/dao_tally.h"
#include "governance/dao_tally_share.h"
#include "governance/governance_params.h"

namespace cryptonote {

class TallyManager {
public:
    TallyManager(BlockchainDB& db, const governance_params& params);

    // Called by Blockchain::handle_dao_v2_tally_share after a share has
    // been structurally validated and stored. Attempts to combine and
    // write the outcome if the threshold has been reached.
    //
    // Returns true if the proposal is now finalized (either by this
    // call or previously).
    bool try_finalize(
        const crypto::hash& proposal_id,
        const std::map<crypto::public_key, dao::dao_v2_tally_share>& shares,
        uint64_t current_height);

    // Produce this node's own partial decryptions for a proposal from
    // its locally persisted bootstrap DKG share. `global_member_index`
    // is this node's 1-based index within the key record's bootstrap
    // shareholder set. Returns false if this node has no share for
    // that index. The caller broadcasts the returned share over P2P.
    bool produce_local_share(
        const crypto::hash& proposal_id,
        const dao::dao_tally_key_record& key_rec,
        uint32_t global_member_index,
        dao::dao_v2_tally_share& share_out);

private:
    BlockchainDB& m_db;
    const governance_params& m_params;
};

} // namespace cryptonote
