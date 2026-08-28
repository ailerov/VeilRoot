// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include "governance_db.h"

namespace cryptonote {

class ParameterManager
{
public:
    ParameterManager(GovernanceDB& db);

    bool process_block(uint64_t height);
    bool rollback_block(uint64_t height);

    uint64_t get_parameter(governance_parameter param, uint64_t height) const;
    void add_parameter_record(const parameter_record& rec);

private:
    GovernanceDB& m_db;
};

} // namespace cryptonote