// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Stable public tally key record.
//
// The long-lived Paillier public key generated once by the bootstrap
// DKG. It never changes. Every ballot is encrypted under this key.
// The tally committee selected at each proposal's voting end is a
// separate object (see dao_tally_session_cycle.h) and is not part of this
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
} // namespace dao
} // namespace cryptonote
