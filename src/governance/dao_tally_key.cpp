// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_tally_key.h"

#include <cstring>

namespace cryptonote {
namespace dao {

namespace {

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

void push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

bool pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out)
{
    if (off + 4 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= uint32_t(v[off++]) << (8 * i);
    return true;
}

bool pull_u64(const std::vector<uint8_t>& v, size_t& off, uint64_t& out)
{
    if (off + 8 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= uint64_t(v[off++]) << (8 * i);
    return true;
}

void push_bytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

bool pull_bytes(const std::vector<uint8_t>& v, size_t& off, std::vector<uint8_t>& out)
{
    uint32_t n = 0;
    if (!pull_u32(v, off, n)) return false;
    if (off + n > v.size()) return false;
    out.assign(v.begin() + off, v.begin() + off + n);
    off += n;
    return true;
}

bool pull_fixed(const std::vector<uint8_t>& v, size_t& off, size_t n,
                std::vector<uint8_t>& dest)
{
    if (off + n > v.size()) return false;
    dest.assign(v.begin() + off, v.begin() + off + n);
    off += n;
    return true;
}

} // anonymous namespace

// --------------------------------------------------------------------
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// dao_tally_committee_record
// --------------------------------------------------------------------

} // namespace dao
} // namespace cryptonote
