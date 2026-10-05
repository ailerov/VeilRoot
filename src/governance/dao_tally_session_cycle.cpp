// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_tally_session_cycle.h"

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

} // anonymous namespace

bool dao_tally_session::serialize(std::vector<uint8_t>& out) const
{
    if (committee_members.size() != committee_size) return false;

    out.clear();
    push_u32(out, version);
    push_u32(out, share_epoch);
    out.insert(out.end(), proposal_id.data,
               proposal_id.data + sizeof(proposal_id.data));
    out.insert(out.end(), public_key_id.data,
               public_key_id.data + sizeof(public_key_id.data));
    push_u64(out, selection_height);
    push_u64(out, vote_end_height);
    push_u32(out, committee_size);
    push_u32(out, threshold);
    push_u32(out, t);
    out.insert(out.end(), committee_id_hash.data,
               committee_id_hash.data + sizeof(committee_id_hash.data));
    for (const auto& m : committee_members)
        out.insert(out.end(), m.data, m.data + sizeof(m.data));
    out.push_back(resharing_complete ? 1 : 0);
    out.push_back(tally_complete ? 1 : 0);
    return true;
}

bool dao_tally_session::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0, se = 0, cs = 0, th = 0, tt = 0;
    if (!pull_u32(in, off, v))  return false;
    if (!pull_u32(in, off, se)) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(proposal_id.data, in.data() + off, 32); off += 32;
    if (off + 32 > in.size()) return false;
    std::memcpy(public_key_id.data, in.data() + off, 32); off += 32;
    if (!pull_u64(in, off, selection_height)) return false;
    if (!pull_u64(in, off, vote_end_height))  return false;
    if (!pull_u32(in, off, cs)) return false;
    if (!pull_u32(in, off, th)) return false;
    if (!pull_u32(in, off, tt)) return false;
    if (cs == 0 || cs > 64) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(committee_id_hash.data, in.data() + off, 32); off += 32;

    committee_members.assign(cs, {});
    for (uint32_t i = 0; i < cs; ++i) {
        if (off + 32 > in.size()) return false;
        std::memcpy(committee_members[i].data, in.data() + off, 32);
        off += 32;
    }

    if (off + 2 > in.size()) return false;
    resharing_complete = (in[off++] != 0);
    tally_complete     = (in[off++] != 0);
    if (off != in.size()) return false;

    version        = v;
    share_epoch    = se;
    committee_size = cs;
    threshold      = th;
    t              = tt;
    return true;
}

} // namespace dao
} // namespace cryptonote
