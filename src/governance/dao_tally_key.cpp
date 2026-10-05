// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_tally_key.h"
#include "governance/dao_tally_session.h"

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
// dao_tally_public_key_record
// --------------------------------------------------------------------

bool dao_tally_public_key_record::serialize(std::vector<uint8_t>& out) const
{
    if (delta.size() != 32)                       return false;
    if (N.size()     != PAILLIER_MODULUS_BYTES)   return false;
    if (G.size()     != PAILLIER_MODULUS_BYTES)   return false;
    if (theta.size() != PAILLIER_MODULUS_BYTES)   return false;
    if (V.size()     != PAILLIER_CT_BYTES)        return false;
    if (key_id.size()              != 32)         return false;
    if (dkg_transcript_hash.size() != 32)         return false;

    out.clear();
    push_u32(out, version);
    push_u32(out, key_epoch);
    push_bytes(out, delta);
    push_bytes(out, N);
    push_bytes(out, G);
    push_bytes(out, theta);
    push_bytes(out, V);
    push_bytes(out, vss_P);
    push_bytes(out, vss_P_prime);
    push_bytes(out, vss_g);
    push_bytes(out, vss_h);
    out.insert(out.end(), key_id.begin(), key_id.end());
    out.insert(out.end(), dkg_transcript_hash.begin(), dkg_transcript_hash.end());
    push_u64(out, activation_height);
    return true;
}

bool dao_tally_public_key_record::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0, e = 0;
    if (!pull_u32(in, off, v)) return false;
    if (!pull_u32(in, off, e)) return false;
    if (!pull_bytes(in, off, delta)) return false;
    if (!pull_bytes(in, off, N)) return false;
    if (!pull_bytes(in, off, G)) return false;
    if (!pull_bytes(in, off, theta)) return false;
    if (!pull_bytes(in, off, V)) return false;
    if (!pull_bytes(in, off, vss_P)) return false;
    if (!pull_bytes(in, off, vss_P_prime)) return false;
    if (!pull_bytes(in, off, vss_g)) return false;
    if (!pull_bytes(in, off, vss_h)) return false;
    if (!pull_fixed(in, off, 32, key_id)) return false;
    if (!pull_fixed(in, off, 32, dkg_transcript_hash)) return false;
    if (!pull_u64(in, off, activation_height)) return false;
    if (off != in.size()) return false;

    version   = v;
    key_epoch = e;
    return true;
}

// --------------------------------------------------------------------
// dao_tally_committee_record
// --------------------------------------------------------------------

bool dao_tally_committee_record::serialize(std::vector<uint8_t>& out) const
{
    if (public_key_id.size()     != 32) return false;
    if (committee_id_hash.size() != 32) return false;
    if (committee_members.size() != committee_size) return false;
    for (const auto& m : committee_members)
        if (m.size() != 32) return false;
    if (V_K_i.size() != committee_size) return false;
    for (const auto& vk : V_K_i)
        if (vk.size() != PAILLIER_CT_BYTES) return false;

    out.clear();
    push_u32(out, version);
    push_u32(out, share_epoch);
    push_u32(out, committee_size);
    push_u32(out, threshold);
    push_u32(out, t);
    out.insert(out.end(), public_key_id.begin(), public_key_id.end());
    out.insert(out.end(), committee_id_hash.begin(), committee_id_hash.end());
    for (const auto& m : committee_members)
        out.insert(out.end(), m.begin(), m.end());
    for (const auto& vk : V_K_i)
        out.insert(out.end(), vk.begin(), vk.end());
    push_u64(out, selection_height);
    push_u64(out, activation_height);
    return true;
}

bool dao_tally_committee_record::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0, se = 0, cs = 0, th = 0, tt = 0;
    if (!pull_u32(in, off, v))  return false;
    if (!pull_u32(in, off, se)) return false;
    if (!pull_u32(in, off, cs)) return false;
    if (!pull_u32(in, off, th)) return false;
    if (!pull_u32(in, off, tt)) return false;
    if (cs == 0 || cs > 64) return false;

    if (!pull_fixed(in, off, 32, public_key_id)) return false;
    if (!pull_fixed(in, off, 32, committee_id_hash)) return false;

    committee_members.assign(cs, {});
    for (uint32_t i = 0; i < cs; ++i) {
        if (!pull_fixed(in, off, 32, committee_members[i])) return false;
    }

    V_K_i.assign(cs, {});
    for (uint32_t i = 0; i < cs; ++i) {
        if (!pull_fixed(in, off, PAILLIER_CT_BYTES, V_K_i[i])) return false;
    }

    if (!pull_u64(in, off, selection_height))  return false;
    if (!pull_u64(in, off, activation_height)) return false;
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
