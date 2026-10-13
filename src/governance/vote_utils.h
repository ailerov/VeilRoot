// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <vector>
#include <crypto/hash.h>
#include <cryptonote_basic/cryptonote_basic.h>

namespace cryptonote {

// Check if a transaction is a legacy (V1) input-based DAO vote.
bool is_vote_tx(const transaction& tx);

// Check if a transaction is a DAO V2 vote transaction.
// A V2 vote is a zero-input, zero-output transaction with
// tx.version == TX_VERSION_DAO_VOTE carrying exactly one
// governance_object::vote_v2 payload. This is a shape classifier;
// cryptographic verification lives in VoteProofVerifier.
bool is_dao_v2_vote_tx(const transaction& tx);

// Hard ceiling on the tx.extra field of a V2 vote. Enforced on
// mempool admission and on block validation.
constexpr size_t DAO_VOTE_V2_MAX_EXTRA_BYTES = 128 * 1024;

// Check if a transaction is an eligibility transaction
bool is_eligible_tx(const transaction& tx);

// Check if a transaction is a non‑consuming governance transaction
bool is_non_consuming_tx(const transaction& tx);

// Parse the DAO vote metadata from tx_extra
bool parse_vote_extra(const std::vector<uint8_t>& extra,
                      crypto::hash& proposal_id,
                      uint8_t& direction,
                      uint64_t& weight,
                      uint64_t& amount);

} // namespace cryptonote