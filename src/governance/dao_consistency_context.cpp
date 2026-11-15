// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_consistency_context.h"

#include <openssl/sha.h>

namespace cryptonote {
namespace dao {

namespace {

void tx_push_u8(std::vector<uint8_t>& v, uint8_t x) { v.push_back(x); }

void tx_push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back(uint8_t((x >> (8*i)) & 0xff));
}

void tx_push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t((x >> (8*i)) & 0xff));
}

void tx_push_bytes(std::vector<uint8_t>& v, const uint8_t* p, size_t n)
{
    v.insert(v.end(), p, p + n);
}

bool tx_validate(const dao_vote_transcript_input& in)
{
    // Ciphertext fields are scheme-specific: 512-byte fixed for the
    // Paillier encoding, variable-length QFI wire for CL. Bound both
    // extremes and reject only empty.
    constexpr size_t CT_MAX = 16384;
    if (in.E_W.empty() || in.E_W.size() > CT_MAX) return false;
    if (in.E_S.empty() || in.E_S.size() > CT_MAX) return false;
    if (in.E_B.empty() || in.E_B.size() > CT_MAX) return false;

    const size_t n = in.key_offsets.size();
    if (in.absolute_indices.size() != n) return false;
    if (in.P.size()                != n) return false;
    if (in.C.size()                != n) return false;
    if (in.output_heights.size()   != n) return false;
    if (in.age_factors.size()      != n) return false;
    if (in.nullifiers.size()       != n) return false;
    if (in.balance_commitments.size() != n) return false;
    if (n > 0xffffffffu) return false;

    for (size_t i = 0; i < n; ++i) {
        const size_t m = in.absolute_indices[i].size();
        if (in.P[i].size()              != m) return false;
        if (in.C[i].size()              != m) return false;
        if (in.output_heights[i].size() != m) return false;
        if (in.age_factors[i].size()    != m) return false;
        if (in.key_offsets[i].size() > 0xffffffffu) return false;
        if (m > 0xffffffffu) return false;
    }
    return true;
}

} // anonymous namespace

std::vector<uint8_t> dao_vote_input_transcript(
    const dao_vote_transcript_input& in)
{
    static const char DOMAIN[] = "VeilRoot-DAO-VOTE-INPUT-V2";
    constexpr size_t DOMAIN_LEN = sizeof(DOMAIN) - 1;

    if (!tx_validate(in)) return {};

    std::vector<uint8_t> out;
    out.reserve(DOMAIN_LEN + 1 + 1 + 32 + 24 + 32 + 4
                + 32 + 32 + 512 + 512);

    tx_push_bytes(out, reinterpret_cast<const uint8_t*>(DOMAIN), DOMAIN_LEN);
    tx_push_u8 (out, 0);
    tx_push_u8 (out, in.version);
    tx_push_bytes(out, reinterpret_cast<const uint8_t*>(in.proposal_id.data), 32);
    tx_push_u64(out, in.proposal_submission_height);
    tx_push_u64(out, in.vote_height);
    tx_push_bytes(out, reinterpret_cast<const uint8_t*>(in.tally_key_id.data), 32);

    tx_push_u32(out, uint32_t(in.key_offsets.size()));

    for (size_t i = 0; i < in.key_offsets.size(); ++i) {
        tx_push_u32(out, uint32_t(in.key_offsets[i].size()));
        for (uint64_t k : in.key_offsets[i]) tx_push_u64(out, k);

        const size_t m = in.absolute_indices[i].size();
        tx_push_u32(out, uint32_t(m));
        for (size_t j = 0; j < m; ++j) {
            tx_push_u64(out, in.absolute_indices[i][j]);
            tx_push_u64(out, in.output_heights[i][j]);
            tx_push_bytes(out, in.P[i][j].bytes, 32);
            tx_push_bytes(out, in.C[i][j].bytes, 32);
            tx_push_u8 (out, in.age_factors[i][j]);
        }
        tx_push_bytes(out, reinterpret_cast<const uint8_t*>(in.nullifiers[i].data), 32);
        tx_push_bytes(out, in.balance_commitments[i].bytes, 32);
    }

    tx_push_bytes(out, in.C_W.bytes, 32);
    tx_push_bytes(out, in.C_S.bytes, 32);
    tx_push_bytes(out, in.C_B.bytes, 32);
    auto push_vec_into = [&](const std::vector<uint8_t>& v) {
        tx_push_u32(out, static_cast<uint32_t>(v.size()));
        if (!v.empty()) tx_push_bytes(out, v.data(), v.size());
    };
    push_vec_into(in.E_W);
    push_vec_into(in.E_S);
    push_vec_into(in.E_B);

    unsigned char digest[32];
    SHA256(out.data(), out.size(), digest);
    return std::vector<uint8_t>(digest, digest + 32);
}

} // namespace dao
} // namespace cryptonote
