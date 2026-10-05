// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_dkg_reset.h"

namespace cryptonote {
namespace dao {

bool dao_dkg_reset(
    const dao_dkg_reset_config& cfg,
    const std::vector<uint8_t>& local_old_share,
    const dao_tally_public_key_record& public_key,
    dao_dkg_reset_result& result)
{
    (void)cfg;
    (void)local_old_share;
    (void)public_key;
    result = dao_dkg_reset_result{};
    return false;
}

} // namespace dao
} // namespace cryptonote
