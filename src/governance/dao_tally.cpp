// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_tally.h"

#ifdef VEILROOT_ENABLE_CL
#include "governance/dao_cl_ballot.h"
#include "governance/dao_cl_consistency.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_tally_wire.h"
#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"
#endif

#include <cstring>

#include <openssl/sha.h>

#include "governance/dao_threshold.h"
#include "governance/dao_reshare_vss.h"
#include "governance/dao_reshare_pipeline.h"
#include "misc_log_ex.h"

namespace cryptonote {
namespace dao {

namespace {

struct CtxGuard {
    BN_CTX* ctx;
    CtxGuard() : ctx(BN_CTX_new()) {}
    ~CtxGuard() { if (ctx) BN_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
    bool ok() const { return ctx != nullptr; }
};

void push_u8(std::vector<uint8_t>& v, uint8_t x) { v.push_back(x); }

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back(uint8_t((x >> (8*i)) & 0xff));
}

void push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t((x >> (8*i)) & 0xff));
}

void push_u128(std::vector<uint8_t>& v, const dao_u128& x)
{
    for (int i = 15; i >= 0; --i)
        v.push_back(uint8_t((x >> (8*i)) & 0xff));
}

bool pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out)
{
    if (off + 4 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i)
        out |= uint32_t(v[off++]) << (8*i);
    return true;
}

bool pull_u64(const std::vector<uint8_t>& v, size_t& off, uint64_t& out)
{
    if (off + 8 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
        out |= uint64_t(v[off++]) << (8*i);
    return true;
}

bool pull_u128(const std::vector<uint8_t>& v, size_t& off, dao_u128& out)
{
    if (off + 16 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 16; ++i)
        out = (out << 8) | dao_u128(v[off++]);
    return true;
}

void push_vec(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, uint32_t(b.size()));
    v.insert(v.end(), b.begin(), b.end());
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

// BIGNUM -> canonical 512-byte big-endian.
void bn_to_fixed_512(const BIGNUM* b, std::vector<uint8_t>& out)
{
    out.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(b, out.data(), PAILLIER_CT_BYTES);
}

// Reduce a BIGNUM modulo N, decode signed Paillier plaintext.
//   m <= N/2  -> S = m >= 0
//   m >  N/2  -> S = m - N < 0
bool decode_signed(const BIGNUM* m, const BIGNUM* N,
                   bool& negative, dao_u128& magnitude)
{
    if (!m || !N) return false;
    if (BN_is_negative(m) || BN_is_negative(N)) return false;
    BIGNUM* half = BN_new();
    if (!half) return false;
    BN_rshift1(half, N);
    CtxGuard g;
    bool result = false;
    if (BN_cmp(m, half) <= 0) {
        negative = false;
        if (BN_num_bits(m) <= 128) {
            const int nbytes = BN_num_bytes(m);
            std::vector<uint8_t> buf(nbytes);
            BN_bn2bin(m, buf.data());
            magnitude = 0;
            for (uint8_t x : buf) magnitude = (magnitude << 8) | dao_u128(x);
            result = true;
        }
    } else {
        negative = true;
        BIGNUM* neg = BN_new();
        if (neg) {
            BN_sub(neg, N, m);
            if (BN_num_bits(neg) <= 128) {
                const int nbytes = BN_num_bytes(neg);
                std::vector<uint8_t> buf(nbytes);
                BN_bn2bin(neg, buf.data());
                magnitude = 0;
                for (uint8_t x : buf) magnitude = (magnitude << 8) | dao_u128(x);
                result = true;
            }
            BN_free(neg);
        }
    }
    BN_free(half);
    return result;
}

// Non-negative decode. Rejects negatives and values wider than 128 bits.
bool bn_to_u128(const BIGNUM* b, dao_u128& out)
{
    if (!b) return false;
    if (BN_is_negative(b)) return false;
    if (BN_num_bits(b) > 128) return false;
    const int nbytes = BN_num_bytes(b);
    std::vector<uint8_t> buf(nbytes);
    BN_bn2bin(b, buf.data());
    out = 0;
    for (uint8_t x : buf) out = (out << 8) | dao_u128(x);
    return true;
}

} // anonymous namespace

#ifdef VEILROOT_DAO_DKG_TESTING
// Test-only wrappers so decoder rejection behaviour can be tested
// directly. See tests/unit_tests/dao_tally.cpp.
bool dao_test_bn_to_u128(const BIGNUM* b, dao_u128& out) {
    return bn_to_u128(b, out);
}
bool dao_test_decode_signed(const BIGNUM* m, const BIGNUM* N,
                            bool& negative, dao_u128& magnitude) {
    return decode_signed(m, N, negative, magnitude);
}
#endif

// ------------------------------------------------------------------
// Aggregate ciphertext hash
// ------------------------------------------------------------------

crypto::hash dao_aggregate_ciphertext_hash(
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B)
{
    // Scheme-agnostic, canonical, length-framed hash of the ordered
    // (E_W, E_S, E_B) byte strings. Length framing prevents
    // concatenation-ambiguity collisions across variable-length CL
    // ciphertext wires. Empty per-channel input is invalid and
    // returns the all-zero sentinel.
    crypto::hash h{};
    if (E_W.empty() || E_S.empty() || E_B.empty()) return h;

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-TALLY-CIPHERTEXTS-V2";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    buf.push_back(2);  // version
    auto push_len = [&](const std::vector<uint8_t>& v) {
        const uint32_t n = static_cast<uint32_t>(v.size());
        buf.push_back(uint8_t((n >> 24) & 0xff));
        buf.push_back(uint8_t((n >> 16) & 0xff));
        buf.push_back(uint8_t((n >>  8) & 0xff));
        buf.push_back(uint8_t( n        & 0xff));
        buf.insert(buf.end(), v.begin(), v.end());
    };
    push_len(E_W);
    push_len(E_S);
    push_len(E_B);
    SHA256(buf.data(), buf.size(),
           reinterpret_cast<unsigned char*>(h.data));
    return h;
}

// ------------------------------------------------------------------
// dao_partial_set
// ------------------------------------------------------------------

bool dao_partial_set::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    if (member_indices.size() != partials.size()) return false;
    if (proofs.size() != partials.size()) return false;

    if (member_indices.size() > DAO_DKG_MAX_COMMITTEE_SIZE) return false;

    push_u32(out, uint32_t(member_indices.size()));
    for (size_t i = 0; i < member_indices.size(); ++i) {
        if (partials[i].size() != PAILLIER_CT_BYTES) return false;
        if (proofs[i].E.size() != 32) return false;
        if (proofs[i].Z.size() != DAO_DKG_PARTIAL_PROOF_Z_BYTES)
            return false;
        push_u32(out, member_indices[i]);
        push_vec(out, partials[i]);
        push_u32(out, proofs[i].member_index);
        push_vec(out, proofs[i].E);
        push_vec(out, proofs[i].Z);
    }
    return true;
}

bool dao_partial_set::deserialize(const std::vector<uint8_t>& in)
{
    member_indices.clear();
    partials.clear();
    proofs.clear();

    size_t off = 0;
    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t idx = 0;
        std::vector<uint8_t> p, e, z;
        uint32_t proof_idx = 0;
        if (!pull_u32(in, off, idx)) return false;
        if (!pull_vec(in, off, p)) return false;
        if (p.size() != PAILLIER_CT_BYTES) return false;
        if (!pull_u32(in, off, proof_idx)) return false;
        if (!pull_vec(in, off, e)) return false;
        if (e.size() != 32) return false;
        if (!pull_vec(in, off, z)) return false;
        if (z.size() != DAO_DKG_PARTIAL_PROOF_Z_BYTES) return false;
        member_indices.push_back(idx);
        partials.push_back(std::move(p));
        dao_partial_decryption_proof pr;
        pr.member_index = proof_idx;
        pr.E = std::move(e);
        pr.Z = std::move(z);
        proofs.push_back(std::move(pr));
    }
    return off == in.size();
}

// ------------------------------------------------------------------
// dao_partial_set :: CL form
// ------------------------------------------------------------------

bool dao_partial_set::serialize_cl(std::vector<uint8_t>& out) const
{
    out.clear();
    if (member_indices.size() != cl_partials.size()) return false;
    if (member_indices.size() > DAO_DKG_MAX_COMMITTEE_SIZE) return false;

    out.push_back(CL_FORMAT_TAG);
    push_u32(out, static_cast<uint32_t>(member_indices.size()));
    for (size_t i = 0; i < member_indices.size(); ++i) {
        if (cl_partials[i].empty()) return false;
        if (cl_partials[i].size() > CL_PARTIAL_MAX_BYTES) return false;
        push_u32(out, member_indices[i]);
        push_vec(out, cl_partials[i]);
    }
    return true;
}

bool dao_partial_set::deserialize_cl(const std::vector<uint8_t>& in)
{
    member_indices.clear();
    partials.clear();
    proofs.clear();
    cl_partials.clear();

    if (in.empty()) return false;
    size_t off = 0;
    if (in[off++] != CL_FORMAT_TAG) return false;
    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t idx = 0;
        std::vector<uint8_t> p;
        if (!pull_u32(in, off, idx)) return false;
        if (!pull_vec(in, off, p)) return false;
        if (p.empty() || p.size() > CL_PARTIAL_MAX_BYTES) return false;
        member_indices.push_back(idx);
        cl_partials.push_back(std::move(p));
    }
    return off == in.size();
}

// ------------------------------------------------------------------
// dao_tally_certificate
// ------------------------------------------------------------------

bool dao_tally_certificate::serialize(std::vector<uint8_t>& out) const
{
    // CL certs are emitted as v7 and their partial sets are CL form.
    const bool is_cl =
        !W.cl_partials.empty() || !S.cl_partials.empty() || !B.cl_partials.empty();
    if (is_cl) {
        out.clear();
        push_u8(out, WIRE_VERSION_CL);
        out.insert(out.end(), proposal_id.data, proposal_id.data + 32);
        push_u64(out, vote_end_height);
        push_vec(out, key_id);
        out.insert(out.end(), aggregate_ciphertext_hash.data,
                   aggregate_ciphertext_hash.data + 32);
        std::vector<uint8_t> w, s, b;
        if (!W.serialize_cl(w)) return false;
        if (!S.serialize_cl(s)) return false;
        if (!B.serialize_cl(b)) return false;
        push_vec(out, w);
        push_vec(out, s);
        push_vec(out, b);
        push_u128(out, W_total);
        push_u8(out, s_negative ? 1 : 0);
        push_u128(out, S_abs);
        push_u128(out, B_total);
        push_u128(out, YES_weight);
        push_u128(out, NO_weight);
        push_u128(out, quorum_threshold);
        push_u8(out, quorum_met ? 1 : 0);
        push_u8(out, majority_met ? 1 : 0);
        push_u8(out, passed ? 1 : 0);
        return true;
    }

    out.clear();
    push_u8(out, WIRE_VERSION);
    out.insert(out.end(), proposal_id.data,
               proposal_id.data + sizeof(proposal_id.data));
    push_u64(out, vote_end_height);
    push_vec(out, key_id);
    out.insert(out.end(), aggregate_ciphertext_hash.data,
               aggregate_ciphertext_hash.data + 32);

    std::vector<uint8_t> w, s, b;
    if (!W.serialize(w)) return false;
    if (!S.serialize(s)) return false;
    if (!B.serialize(b)) return false;
    push_vec(out, w);
    push_vec(out, s);
    push_vec(out, b);

    push_u128(out, W_total);
    push_u8(out, s_negative ? 1 : 0);
    push_u128(out, S_abs);
    push_u128(out, B_total);

    push_u128(out, YES_weight);
    push_u128(out, NO_weight);
    push_u128(out, quorum_threshold);
    push_u8(out, quorum_met ? 1 : 0);
    push_u8(out, majority_met ? 1 : 0);
    push_u8(out, passed ? 1 : 0);

    // v6 fields
    push_u64(out, per_event_share_set_id);
    push_u32(out, threshold);
    push_u32(out, static_cast<uint32_t>(member_pubkeys.size()));
    for (const auto& m : member_pubkeys) push_vec(out, m);
    push_u32(out, static_cast<uint32_t>(per_event_VK_i.size()));
    for (const auto& v : per_event_VK_i) push_vec(out, v);
    push_u64(out, base_share_set_id);
    push_u32(out, static_cast<uint32_t>(contributions.size()));
    for (const auto& c : contributions) push_vec(out, c);
    push_u32(out, static_cast<uint32_t>(contributor_indices.size()));
    for (uint32_t i : contributor_indices) push_u32(out, i);
    push_u32(out, static_cast<uint32_t>(contributor_vk.size()));
    for (const auto& v : contributor_vk) push_vec(out, v);
    return true;
}

bool dao_tally_certificate::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (in.size() < 1) return false;
    if (in[0] == WIRE_VERSION_CL) {
        // CL wire form.
        off = 1;
        if (off + 32 + 8 + 4 > in.size()) return false;
        std::memcpy(proposal_id.data, in.data() + off, 32); off += 32;
        if (!pull_u64(in, off, vote_end_height)) return false;
        if (!pull_vec(in, off, key_id)) return false;
        if (key_id.size() != 32) return false;
        if (off + 32 > in.size()) return false;
        std::memcpy(aggregate_ciphertext_hash.data,
                    in.data() + off, 32); off += 32;
        std::vector<uint8_t> w, s, b;
        if (!pull_vec(in, off, w)) return false;
        if (!pull_vec(in, off, s)) return false;
        if (!pull_vec(in, off, b)) return false;
        if (!W.deserialize_cl(w)) return false;
        if (!S.deserialize_cl(s)) return false;
        if (!B.deserialize_cl(b)) return false;
        if (!pull_u128(in, off, W_total)) return false;
        if (off + 1 > in.size()) return false;
        s_negative = (in[off++] != 0);
        if (!pull_u128(in, off, S_abs)) return false;
        if (!pull_u128(in, off, B_total)) return false;
        if (!pull_u128(in, off, YES_weight)) return false;
        if (!pull_u128(in, off, NO_weight)) return false;
        if (!pull_u128(in, off, quorum_threshold)) return false;
        if (off + 3 > in.size()) return false;
        quorum_met   = (in[off++] != 0);
        majority_met = (in[off++] != 0);
        passed       = (in[off++] != 0);
        return off == in.size();
    }

    if (in.size() < 1 + 32 + 8 + 32) return false;
    if (in[off++] != WIRE_VERSION) return false;
    std::memcpy(proposal_id.data, in.data() + off, 32); off += 32;
    if (!pull_u64(in, off, vote_end_height)) return false;
    if (!pull_vec(in, off, key_id)) return false;
    std::memcpy(aggregate_ciphertext_hash.data, in.data() + off, 32); off += 32;

    std::vector<uint8_t> w, s, b;
    if (!pull_vec(in, off, w)) return false;
    if (!pull_vec(in, off, s)) return false;
    if (!pull_vec(in, off, b)) return false;
    if (!W.deserialize(w)) return false;
    if (!S.deserialize(s)) return false;
    if (!B.deserialize(b)) return false;

    if (!pull_u128(in, off, W_total)) return false;
    if (off + 1 > in.size()) return false;
    s_negative = (in[off++] != 0);
    if (!pull_u128(in, off, S_abs)) return false;
    if (!pull_u128(in, off, B_total)) return false;

    if (!pull_u128(in, off, YES_weight)) return false;
    if (!pull_u128(in, off, NO_weight)) return false;
    if (!pull_u128(in, off, quorum_threshold)) return false;
    if (off + 3 > in.size()) return false;
    quorum_met   = (in[off++] != 0);
    majority_met = (in[off++] != 0);
    passed       = (in[off++] != 0);

    // v6 fields
    if (!pull_u64(in, off, per_event_share_set_id)) return false;
    if (!pull_u32(in, off, threshold)) return false;

    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    member_pubkeys.clear(); member_pubkeys.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<uint8_t> v;
        if (!pull_vec(in, off, v)) return false;
        if (v.size() != 32) return false;
        member_pubkeys.push_back(std::move(v));
    }

    if (!pull_u32(in, off, n)) return false;
    if (n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    per_event_VK_i.clear(); per_event_VK_i.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<uint8_t> v;
        if (!pull_vec(in, off, v)) return false;
        per_event_VK_i.push_back(std::move(v));
    }

    if (!pull_u64(in, off, base_share_set_id)) return false;

    if (!pull_u32(in, off, n)) return false;
    if (n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    contributions.clear(); contributions.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<uint8_t> v;
        if (!pull_vec(in, off, v)) return false;
        contributions.push_back(std::move(v));
    }

    if (!pull_u32(in, off, n)) return false;
    if (n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    contributor_indices.clear(); contributor_indices.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t x;
        if (!pull_u32(in, off, x)) return false;
        contributor_indices.push_back(x);
    }

    if (!pull_u32(in, off, n)) return false;
    if (n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    contributor_vk.clear(); contributor_vk.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<uint8_t> v;
        if (!pull_vec(in, off, v)) return false;
        contributor_vk.push_back(std::move(v));
    }

    return off == in.size();
}

// ------------------------------------------------------------------
// dao_v2_outcome_record
// ------------------------------------------------------------------

bool dao_v2_outcome_record::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    push_u8(out, WIRE_VERSION);
    out.insert(out.end(), proposal_id.data, proposal_id.data + 32);
    push_u64(out, vote_end_height);
    push_vec(out, key_id);
    out.insert(out.end(), aggregate_ciphertext_hash.data,
               aggregate_ciphertext_hash.data + 32);
    push_u128(out, yes_weight);
    push_u128(out, no_weight);
    push_u128(out, participation_coins);
    push_u128(out, quorum_threshold);
    push_u8(out, quorum_met ? 1 : 0);
    push_u8(out, majority_met ? 1 : 0);
    push_u8(out, passed ? 1 : 0);
    return true;
}

bool dao_v2_outcome_record::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (in.size() < 1 + 32 + 8 + 32) return false;
    if (in[off++] != WIRE_VERSION) return false;
    std::memcpy(proposal_id.data, in.data() + off, 32); off += 32;
    if (!pull_u64(in, off, vote_end_height)) return false;
    if (!pull_vec(in, off, key_id)) return false;
    std::memcpy(aggregate_ciphertext_hash.data, in.data() + off, 32); off += 32;
    if (!pull_u128(in, off, yes_weight)) return false;
    if (!pull_u128(in, off, no_weight)) return false;
    if (!pull_u128(in, off, participation_coins)) return false;
    if (!pull_u128(in, off, quorum_threshold)) return false;
    if (off + 3 > in.size()) return false;
    quorum_met   = (in[off++] != 0);
    majority_met = (in[off++] != 0);
    passed       = (in[off++] != 0);
    return off == in.size();
}

// ------------------------------------------------------------------
// dao_evaluate_v2_tally
// ------------------------------------------------------------------

bool dao_evaluate_v2_tally(
    const dao_u128& yes_weight,
    const dao_u128& no_weight,
    const dao_u128& participation_coins,
    const dao_u128& circulating_supply_at_vote_end,
    uint32_t        quorum_percent,
    dao_u128&       quorum_threshold_out,
    bool&           quorum_met_out,
    bool&           majority_met_out,
    bool&           passed_out)
{
    if (quorum_percent > 100) return false;

    quorum_threshold_out =
        (circulating_supply_at_vote_end * quorum_percent) / 100;

    quorum_met_out   = (participation_coins >= quorum_threshold_out);
    majority_met_out = (yes_weight > no_weight);
    passed_out       = quorum_met_out && majority_met_out;
    return true;
}

// ------------------------------------------------------------------
// valid_share_set and bootstrap synthesis
// ------------------------------------------------------------------

namespace {

bool valid_share_set(const dao_tally_key_record& key_rec,
                     const dao_share_set_record& share_set)
{
    if (share_set.version != 1) return false;
    if (share_set.share_set_id == 0) return false;
    if (share_set.threshold == 0) return false;
    if (share_set.threshold > share_set.committee_members.size()) return false;
    if (share_set.committee_members.empty()) return false;
    if (share_set.committee_members.size() > DAO_DKG_MAX_COMMITTEE_SIZE)
        return false;
    if (share_set.VK_i.size() != share_set.committee_members.size())
        return false;
    if (share_set.key_id.size() != key_rec.key_id.size()) return false;
    if (share_set.key_id != key_rec.key_id) return false;
    if (share_set.committee_id_hash.size() != 32) return false;

    for (size_t i = 0; i < share_set.committee_members.size(); ++i) {
        if (share_set.committee_members[i].size() != 32) return false;
        if (share_set.VK_i[i].size() != PAILLIER_CT_BYTES) return false;
        for (size_t j = 0; j < i; ++j) {
            if (share_set.committee_members[i] ==
                share_set.committee_members[j])
                return false;
        }
    }
    return true;
}

} // namespace

uint32_t share_set_id_for_key_id(const std::vector<uint8_t>& key_id)
{
    if (key_id.size() != 32) return 0;
    std::vector<uint8_t> buf(key_id.begin(), key_id.end());
    const char* tag = "share_set_id";
    buf.insert(buf.end(), tag, tag + 13);
    crypto::hash h{};
    crypto::cn_fast_hash(buf.data(), buf.size(), h);
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(h.data[i]) << (8*i);
    v &= 0xFFFFFFFEu;   // force even
    if (v < 2) v = 2;   // reserve 0 and 1
    return v;
}

bool dao_synthesize_bootstrap_share_set(
    const dao_tally_key_record& key_rec,
    dao_share_set_record& out,
    uint64_t share_set_id)
{
    if (key_rec.V_K_i.size() != key_rec.committee_size) return false;
    if (key_rec.committee_members.size() != key_rec.committee_size)
        return false;
    if (key_rec.key_id.size() != 32) return false;

    out = dao_share_set_record{};
    out.version      = 1;
    out.share_set_id = share_set_id;
    out.height       = key_rec.activation_height;
    out.threshold    = key_rec.threshold;
    out.key_id       = key_rec.key_id;
    out.committee_members = key_rec.committee_members;
    out.VK_i         = key_rec.V_K_i;
    out.committee_id_hash.assign(32, 0);
    SHA256(reinterpret_cast<const unsigned char*>(key_rec.committee_id_hash.data()),
           32, out.committee_id_hash.data());
    return true;
}

// ------------------------------------------------------------------
// dao_build_tally_certificate
// ------------------------------------------------------------------



// ------------------------------------------------------------------
// dao_verify_tally_certificate
// ------------------------------------------------------------------



#ifdef VEILROOT_ENABLE_CL

namespace {

bool mpz_to_dao_u128(const BICYCL::Mpz& m, dao_u128& out)
{
    if (m.sgn() < 0) return false;
    auto be = static_cast<std::vector<unsigned char>>(m);
    if (be.size() > 16) return false;
    out = 0;
    for (unsigned char b : be) {
        out <<= 8;
        out |= b;
    }
    return true;
}

// Centre-decode a signed aggregate weight S in Z_q into (negative, |S|).
bool decode_signed_cl(const BICYCL::Mpz& m, const BICYCL::Mpz& q,
                      bool& negative, dao_u128& magnitude)
{
    BICYCL::Mpz centred;
    if (!dao::dao_cl_decode_signed_plaintext(m, q, centred)) return false;
    negative = centred.sgn() < 0;
    BICYCL::Mpz abs_m;
    BICYCL::Mpz::abs(abs_m, centred);
    return mpz_to_dao_u128(abs_m, magnitude);
}

bool deserialize_gammas(const dao_share_set_record& share_set,
                        const BICYCL::Mpz& expected_disc,
                        BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI>& out)
{
    if (share_set.cl_gammas_serialized.empty()) return false;
    return dao::cl_dkg_deserialize_gammas(
        share_set.cl_gammas_serialized, expected_disc, out);
}

bool check_cl_partial_set(
    const dao_partial_set& s,
    const BICYCL::CL_HSMqk& cl,
    const BICYCL::CL_HSMqk::CipherText& ct,
    const BICYCL::Mpz& D,
    const BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI>& gammas,
    uint32_t threshold,
    uint32_t n)
{
    if (s.member_indices.size() != s.cl_partials.size()) return false;
    if (s.member_indices.size() < threshold) return false;
    std::set<uint32_t> seen;
    for (size_t i = 0; i < s.member_indices.size(); ++i) {
        uint32_t m = s.member_indices[i];
        if (m >= n) return false;
        if (!seen.insert(m).second) return false;
        auto it = gammas.find(m);
        if (it == gammas.end()) return false;
        if (!dao::dao_cl_partial_decryption_verify(
                cl, ct, D, it->second, s.cl_partials[i]))
            return false;
    }
    return true;
}

} // anonymous namespace

bool dao_build_tally_certificate(
    const dao_tally_key_record& key_rec,
    const dao_share_set_record& share_set,
    const crypto::hash& proposal_id,
    uint64_t vote_end_height,
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B,
    const dao_partial_set& W_set,
    const dao_partial_set& S_set,
    const dao_partial_set& B_set,
    dao_tally_certificate& cert_out)
{
    if (key_rec.cl_modulus.empty()) return false;
    if (key_rec.key_id.size() != 32) return false;
    if (share_set.key_id != key_rec.key_id) return false;
    if (share_set.threshold == 0) return false;
    if (share_set.committee_members.empty()) return false;
    if (share_set.threshold > share_set.committee_members.size()) return false;

    dao::dao_cl_proposal_key key;
    if (!dao::dao_cl_load_proposal_key(key_rec.cl_modulus, key)) return false;
    if (!dao::dao_cl_check_ballot_modulus(*key.cl)) return false;

    BICYCL::CL_HSMqk::CipherText ct_W, ct_S, ct_B;
    if (!dao::dao_cl_ciphertext_from_wire(*key.cl, E_W, ct_W)) return false;
    if (!dao::dao_cl_ciphertext_from_wire(*key.cl, E_S, ct_S)) return false;
    if (!dao::dao_cl_ciphertext_from_wire(*key.cl, E_B, ct_B)) return false;

    BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI> gammas;
    if (!deserialize_gammas(share_set, key.cl->Cl_G().discriminant(), gammas))
        return false;

    BICYCL::CL_Threshold_Static::ParticipantsSet qualified;
    for (uint32_t q : share_set.qualified_ids) qualified.insert(q);

    const uint32_t n = static_cast<uint32_t>(share_set.committee_members.size());
    if (!check_cl_partial_set(W_set, *key.cl, ct_W, key.D, gammas,
                              share_set.threshold, n)) return false;
    if (!check_cl_partial_set(S_set, *key.cl, ct_S, key.D, gammas,
                              share_set.threshold, n)) return false;
    if (!check_cl_partial_set(B_set, *key.cl, ct_B, key.D, gammas,
                              share_set.threshold, n)) return false;

    BICYCL::Mpz mW, mS, mB;
    if (!dao::dao_cl_partial_decryption_combine(
            *key.cl, *key.pk, ct_W, key.D,
            W_set.member_indices, W_set.cl_partials, gammas, qualified, mW))
        return false;
    if (!dao::dao_cl_partial_decryption_combine(
            *key.cl, *key.pk, ct_S, key.D,
            S_set.member_indices, S_set.cl_partials, gammas, qualified, mS))
        return false;
    if (!dao::dao_cl_partial_decryption_combine(
            *key.cl, *key.pk, ct_B, key.D,
            B_set.member_indices, B_set.cl_partials, gammas, qualified, mB))
        return false;

    cert_out = dao_tally_certificate{};
    cert_out.proposal_id = proposal_id;
    cert_out.vote_end_height = vote_end_height;
    cert_out.key_id = key_rec.key_id;
    cert_out.aggregate_ciphertext_hash =
        dao_aggregate_ciphertext_hash(E_W, E_S, E_B);
    cert_out.W = W_set;
    cert_out.S = S_set;
    cert_out.B = B_set;

    if (!mpz_to_dao_u128(mW, cert_out.W_total)) return false;
    if (!mpz_to_dao_u128(mB, cert_out.B_total)) return false;
    if (!decode_signed_cl(mS, key.cl->q(),
                          cert_out.s_negative, cert_out.S_abs)) return false;

    return true;
}

bool dao_verify_tally_certificate(
    const dao_tally_key_record& key_rec,
    const dao_share_set_record& share_set,
    const dao_supply_snapshot&  supply_at_vote_end,
    uint32_t                    quorum_percent,
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B,
    dao_tally_certificate&      cert)
{
    if (key_rec.key_id.size() != 32) return false;
    if (cert.key_id.size() != 32) return false;
    if (std::memcmp(cert.key_id.data(), key_rec.key_id.data(), 32) != 0)
        return false;
    if (cert.vote_end_height != supply_at_vote_end.height) return false;

    dao_tally_certificate recomputed;
    if (!dao_build_tally_certificate(
            key_rec, share_set, cert.proposal_id, cert.vote_end_height,
            E_W, E_S, E_B, cert.W, cert.S, cert.B, recomputed))
        return false;

    if (recomputed.W_total    != cert.W_total)    return false;
    if (recomputed.s_negative != cert.s_negative) return false;
    if (recomputed.S_abs      != cert.S_abs)      return false;
    if (recomputed.B_total    != cert.B_total)    return false;
    if (recomputed.aggregate_ciphertext_hash != cert.aggregate_ciphertext_hash)
        return false;

    const dao_u128 W_rec     = recomputed.W_total;
    const dao_u128 S_abs_rec = recomputed.S_abs;
    const dao_u128 B_rec     = recomputed.B_total;

    if (B_rec > supply_at_vote_end.circulating) return false;

    const dao_u128 W_MAX =
        dao_u128(240000000ULL) * dao_u128(1000000000000ULL);
    if (W_rec > W_MAX) return false;
    if (S_abs_rec > W_rec) return false;
    if (((W_rec + S_abs_rec) & 1) != 0) return false;

    dao_u128 YES = cert.s_negative
        ? (W_rec - S_abs_rec) / 2
        : (W_rec + S_abs_rec) / 2;
    dao_u128 NO  = W_rec - YES;

    dao_u128 qthresh = 0;
    bool qmet = false, mmet = false, passed = false;
    if (!dao_evaluate_v2_tally(YES, NO, B_rec,
                               supply_at_vote_end.circulating,
                               quorum_percent,
                               qthresh, qmet, mmet, passed))
        return false;

    cert.YES_weight       = YES;
    cert.NO_weight        = NO;
    cert.quorum_threshold = qthresh;
    cert.quorum_met       = qmet;
    cert.majority_met     = mmet;
    cert.passed           = passed;
    return true;
}

#endif // VEILROOT_ENABLE_CL
#ifndef VEILROOT_ENABLE_CL
bool dao_build_tally_certificate(
    const dao_tally_key_record&, const dao_share_set_record&,
    const crypto::hash&, uint64_t,
    const std::vector<uint8_t>&, const std::vector<uint8_t>&,
    const std::vector<uint8_t>&,
    const dao_partial_set&, const dao_partial_set&, const dao_partial_set&,
    dao_tally_certificate&)
{ return false; }
bool dao_verify_tally_certificate(
    const dao_tally_key_record&, const dao_share_set_record&,
    const dao_supply_snapshot&, uint32_t,
    const std::vector<uint8_t>&, const std::vector<uint8_t>&,
    const std::vector<uint8_t>&,
    dao_tally_certificate&)
{ return false; }
#endif

} // namespace dao
} // namespace cryptonote
