// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_tally_share.h"

#include <cstring>

namespace cryptonote {
namespace dao {

namespace {

void push_u8(std::vector<uint8_t>& v, uint8_t x) { v.push_back(x); }

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back(uint8_t((x >> (8*i)) & 0xff));
}

void push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t((x >> (8*i)) & 0xff));
}

void push_vec(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, uint32_t(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

bool pull_u8(const std::vector<uint8_t>& v, size_t& off, uint8_t& out)
{
    if (off + 1 > v.size()) return false;
    out = v[off++];
    return true;
}

bool pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out)
{
    if (off + 4 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= uint32_t(v[off++]) << (8*i);
    return true;
}

bool pull_u64(const std::vector<uint8_t>& v, size_t& off, uint64_t& out)
{
    if (off + 8 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= uint64_t(v[off++]) << (8*i);
    return true;
}

bool pull_vec(const std::vector<uint8_t>& v, size_t& off,
              std::vector<uint8_t>& b)
{
    uint32_t n = 0;
    if (!pull_u32(v, off, n)) return false;
    if (off + n > v.size()) return false;
    b.assign(v.begin() + off, v.begin() + off + n);
    off += n;
    return true;
}

void push_proof(std::vector<uint8_t>& v,
                const dao_partial_decryption_proof& p)
{
    push_u32(v, p.member_index);
    push_vec(v, p.E);
    push_vec(v, p.Z);
}

bool pull_proof(const std::vector<uint8_t>& v, size_t& off,
                dao_partial_decryption_proof& p)
{
    if (!pull_u32(v, off, p.member_index)) return false;
    if (!pull_vec(v, off, p.E)) return false;
    if (!pull_vec(v, off, p.Z)) return false;
    return true;
}

} // anonymous namespace

bool dao_v2_tally_share::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    push_u8(out, version);
    out.insert(out.end(), proposal_id.data, proposal_id.data + 32);
    push_u64(out, vote_end_height);
    push_u32(out, tally_key_epoch);
    push_u32(out, share_epoch);
    out.insert(out.end(), reset_transcript_hash.data,
               reset_transcript_hash.data + 32);
    out.insert(out.end(), aggregate_ciphertext_hash.data,
               aggregate_ciphertext_hash.data + 32);
    push_u32(out, member_index);
    push_vec(out, partial_W);
    push_vec(out, partial_S);
    push_vec(out, partial_B);
    push_proof(out, proof_W);
    push_proof(out, proof_S);
    push_proof(out, proof_B);
    return true;
}

bool dao_v2_tally_share::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (!pull_u8(in, off, version)) return false;
    if (in.size() < off + 32) return false;
    std::memcpy(proposal_id.data, in.data() + off, 32); off += 32;
    if (!pull_u64(in, off, vote_end_height)) return false;
    if (!pull_u32(in, off, tally_key_epoch)) return false;
    if (!pull_u32(in, off, share_epoch)) return false;
    if (in.size() < off + 32) return false;
    std::memcpy(reset_transcript_hash.data, in.data() + off, 32); off += 32;
    if (in.size() < off + 32) return false;
    std::memcpy(aggregate_ciphertext_hash.data, in.data() + off, 32); off += 32;
    if (!pull_u32(in, off, member_index)) return false;
    if (!pull_vec(in, off, partial_W)) return false;
    if (!pull_vec(in, off, partial_S)) return false;
    if (!pull_vec(in, off, partial_B)) return false;
    if (!pull_proof(in, off, proof_W)) return false;
    if (!pull_proof(in, off, proof_S)) return false;
    if (!pull_proof(in, off, proof_B)) return false;
    return off == in.size();
}

} // namespace dao
} // namespace cryptonote
