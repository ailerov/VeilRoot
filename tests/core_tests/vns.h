// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include "chaingen.h"

struct vns_protocol_tests : public test_chain_unit_base
{
    vns_protocol_tests();
    bool generate(std::vector<test_event_entry>& events) const;
    bool run_all(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);

private:
    cryptonote::account_base m_miner_account;
};