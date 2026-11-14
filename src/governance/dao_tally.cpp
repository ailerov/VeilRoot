// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_tally.h"

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
    crypto::hash h{};
    if (E_W.size() != PAILLIER_CT_BYTES) return h;
    if (E_S.size() != PAILLIER_CT_BYTES) return h;
    if (E_B.size() != PAILLIER_CT_BYTES) return h;

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-TALLY-CIPHERTEXTS-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    buf.push_back(1);
    buf.insert(buf.end(), E_W.begin(), E_W.end());
    buf.insert(buf.end(), E_S.begin(), E_S.end());
    buf.insert(buf.end(), E_B.begin(), E_B.end());
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

bool dao_build_tally_certificate(
    const dao_tally_key_record& key_rec,
    const crypto::hash& proposal_id,
    uint64_t vote_end_height,
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& E_B,
    const dao_partial_set& W_set,
    const dao_partial_set& S_set,
    const dao_partial_set& B_set,
    dao_tally_certificate& cert_out,
    const dao_share_set_record* event_share_set)
{
    if (E_W.size() != PAILLIER_CT_BYTES) return false;
    if (E_S.size() != PAILLIER_CT_BYTES) return false;
    if (E_B.size() != PAILLIER_CT_BYTES) return false;
    if (key_rec.key_id.size() != 32) return false;
    if (key_rec.committee_members.empty()) return false;
    if (key_rec.threshold == 0) return false;
    if (key_rec.V_K_i.size() != key_rec.committee_members.size()) return false;

    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(key_rec.N)) return false;

    // Decide evidence mode.
    bool use_evidence = false;
    uint32_t threshold = key_rec.threshold;
    std::vector<std::vector<uint8_t>> vk_i;
    std::vector<std::vector<uint8_t>> member_pubkeys;

    if (event_share_set != nullptr &&
        event_share_set->key_id.size() == 32 &&
        std::memcmp(event_share_set->key_id.data(),
                    key_rec.key_id.data(), 32) == 0 &&
        !event_share_set->contributions.empty() &&
        event_share_set->contributions.size()
            == event_share_set->contributor_indices.size() &&
        event_share_set->contributions.size()
            == event_share_set->contributor_vk.size()) {
        use_evidence  = true;
        threshold     = event_share_set->threshold;
        vk_i          = event_share_set->VK_i;
        member_pubkeys = event_share_set->committee_members;
    } else {
        vk_i          = key_rec.V_K_i;
        for (const auto& m : key_rec.committee_members)
            member_pubkeys.push_back(m);
    }

    const uint32_t n = static_cast<uint32_t>(vk_i.size());
    if (n == 0) return false;
    if (threshold == 0 || threshold > n) return false;

    auto check_set = [&](const dao_partial_set& s,
                         const std::vector<uint8_t>& c) -> bool {
        if (s.member_indices.size() != s.partials.size()) return false;
        if (s.proofs.size() != s.partials.size()) return false;
        if (s.member_indices.size() < threshold) return false;
        std::vector<uint32_t> seen;
        for (size_t i = 0; i < s.member_indices.size(); ++i) {
            uint32_t m = s.member_indices[i];
            if (m < 1 || m > n) return false;
            for (uint32_t q : seen) if (q == m) return false;
            seen.push_back(m);
            if (s.partials[i].size() != PAILLIER_CT_BYTES) return false;
            if (s.proofs[i].member_index != m) return false;
            if (!dao_partial_decryption_verify(
                    pk, key_rec.V, vk_i[m-1], m,
                    c, s.partials[i], s.proofs[i]))
                return false;
        }
        return true;
    };

    if (!check_set(W_set, E_W)) return false;
    if (!check_set(S_set, E_S)) return false;
    if (!check_set(B_set, E_B)) return false;

    cert_out = dao_tally_certificate{};
    cert_out.proposal_id = proposal_id;
    cert_out.vote_end_height = vote_end_height;
    cert_out.key_id = key_rec.key_id;
    cert_out.aggregate_ciphertext_hash =
        dao_aggregate_ciphertext_hash(E_W, E_S, E_B);
    cert_out.W = W_set;
    cert_out.S = S_set;
    cert_out.B = B_set;

    if (use_evidence) {
        cert_out.per_event_share_set_id = event_share_set->share_set_id;
        cert_out.threshold              = threshold;
        cert_out.member_pubkeys         = member_pubkeys;
        cert_out.per_event_VK_i         = vk_i;
        cert_out.base_share_set_id      = event_share_set->base_share_set_id;
        cert_out.contributions          = event_share_set->contributions;
        cert_out.contributor_indices    = event_share_set->contributor_indices;
        cert_out.contributor_vk         = event_share_set->contributor_vk;
    }

    BIGNUM* theta = BN_bin2bn(key_rec.theta.data(),
                              static_cast<int>(key_rec.theta.size()),
                              nullptr);
    if (!theta) return false;

    auto recover = [&](const dao_partial_set& s,
                       const std::vector<uint8_t>& c,
                       BIGNUM* m_out) -> bool {
        std::vector<uint8_t> C;
        if (!dao_threshold_combine(pk, s.member_indices, s.partials,
                                   threshold, C))
            return false;
        return dao_threshold_finalize(pk, C, theta, m_out);
    };

    BIGNUM* mW = BN_new();
    BIGNUM* mS = BN_new();
    BIGNUM* mB = BN_new();
    bool ok = recover(W_set, E_W, mW) &&
              recover(S_set, E_S, mS) &&
              recover(B_set, E_B, mB);
    if (ok) {
        if (!bn_to_u128(mW, cert_out.W_total) ||
            !decode_signed(mS, pk.N(), cert_out.s_negative, cert_out.S_abs) ||
            !bn_to_u128(mB, cert_out.B_total)) {
            ok = false;
        }
    }
    BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta);
    return ok;
}

// ------------------------------------------------------------------
// dao_verify_tally_certificate
// ------------------------------------------------------------------

bool dao_verify_tally_certificate(
    const dao_tally_key_record& key_rec,
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

    if (key_rec.committee_members.empty()) return false;
    if (key_rec.threshold == 0) return false;
    if (key_rec.V_K_i.size() != key_rec.committee_members.size())
        return false;
    if (cert.vote_end_height != supply_at_vote_end.height) return false;

    // Paillier public key. Needed both for reshare-evidence verification
    // and for partial-decryption verification below.
    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(key_rec.N)) return false;

    // Effective committee/threshold/VK_i depends on whether this cert
    // carries v6 reshare evidence.
    uint32_t effective_threshold = key_rec.threshold;
    std::vector<std::vector<uint8_t>> effective_vk_i = key_rec.V_K_i;

    if (cert.per_event_share_set_id != 0) {
        // Verify reshare evidence end-to-end, self-contained: no LMDB
        // lookup, no trust in cert claims beyond what can be re-derived.

        if (cert.contributions.empty() ||
            cert.contributions.size() != cert.contributor_indices.size() ||
            cert.contributions.size() != cert.contributor_vk.size())
            return false;
        if (cert.member_pubkeys.empty() ||
            cert.member_pubkeys.size() != cert.per_event_VK_i.size())
            return false;
        if (cert.threshold == 0 ||
            cert.threshold > cert.per_event_VK_i.size())
            return false;
        for (const auto& v : cert.per_event_VK_i)
            if (v.size() != PAILLIER_CT_BYTES) return false;

        // Reconstruct the VSS group.
        dao_vss_group grp;
        if (key_rec.vss_P.empty() || key_rec.vss_P_prime.empty() ||
            key_rec.vss_g.empty() || key_rec.vss_h.empty())
            return false;
        grp.P = BN_bin2bn(key_rec.vss_P.data(),
                          static_cast<int>(key_rec.vss_P.size()), nullptr);
        grp.P_prime = BN_bin2bn(key_rec.vss_P_prime.data(),
                                static_cast<int>(key_rec.vss_P_prime.size()),
                                nullptr);
        grp.g = BN_bin2bn(key_rec.vss_g.data(),
                          static_cast<int>(key_rec.vss_g.size()), nullptr);
        grp.h = BN_bin2bn(key_rec.vss_h.data(),
                          static_cast<int>(key_rec.vss_h.size()), nullptr);
        struct GrpGuard {
            dao_vss_group& g;
            ~GrpGuard() {
                if (g.P) BN_free(g.P);
                if (g.P_prime) BN_free(g.P_prime);
                if (g.g) BN_free(g.g);
                if (g.h) BN_free(g.h);
                g.P = g.P_prime = g.g = g.h = nullptr;
            }
        } grp_guard{grp};
        if (!grp.valid()) return false;

        std::vector<dao_reshare_contribution> contribs;
        contribs.reserve(cert.contributions.size());
        for (size_t i = 0; i < cert.contributions.size(); ++i) {
            dao_reshare_contribution c;
            if (!dao_reshare_deserialize_public(cert.contributions[i], c))
                return false;
            // Contributor's declared index must match the cert.
            if (c.contributor_index != cert.contributor_indices[i])
                return false;
            // The contribution's link_ctx must be bound to the base
            // VK_i the cert claims for this contributor.
            if (c.link_ctx.VK_i.size() != PAILLIER_CT_BYTES) return false;
            if (cert.contributor_vk[i].size() != PAILLIER_CT_BYTES)
                return false;
            if (std::memcmp(c.link_ctx.VK_i.data(),
                            cert.contributor_vk[i].data(),
                            PAILLIER_CT_BYTES) != 0)
                return false;
            // Reject if the link_ctx V was swapped out.
            if (c.link_ctx.V.size() != key_rec.V.size()) return false;
            if (std::memcmp(c.link_ctx.V.data(), key_rec.V.data(),
                            key_rec.V.size()) != 0)
                return false;
            if (!dao_reshare_vss_verify_public(
                    pk, grp, key_rec.V,
                    c.link_ctx, c.link_proof, c.commits, c.coeff_proofs))
                return false;
            contribs.push_back(std::move(c));
        }

        // Recompute VK_i from contributions and compare to cert.
        std::vector<uint32_t> new_indices;
        for (size_t i = 0; i < cert.member_pubkeys.size(); ++i)
            new_indices.push_back(static_cast<uint32_t>(i + 1));
        std::vector<std::vector<uint8_t>> recomputed_vks;
        if (!dao_reshare_compute_all_vks(pk, key_rec.V, contribs,
                                          new_indices, recomputed_vks))
            return false;
        if (recomputed_vks.size() != cert.per_event_VK_i.size())
            return false;
        for (size_t i = 0; i < recomputed_vks.size(); ++i) {
            if (recomputed_vks[i].size() != PAILLIER_CT_BYTES) return false;
            if (std::memcmp(recomputed_vks[i].data(),
                            cert.per_event_VK_i[i].data(),
                            PAILLIER_CT_BYTES) != 0)
                return false;
        }

        effective_threshold = cert.threshold;
        effective_vk_i      = cert.per_event_VK_i;
    }

    if (E_W.size() != PAILLIER_CT_BYTES) return false;
    if (E_S.size() != PAILLIER_CT_BYTES) return false;
    if (E_B.size() != PAILLIER_CT_BYTES) return false;

    const crypto::hash h = dao_aggregate_ciphertext_hash(E_W, E_S, E_B);
    if (memcmp(h.data, cert.aggregate_ciphertext_hash.data, 32) != 0)
        return false;


    const uint32_t n = static_cast<uint32_t>(
        effective_vk_i.size());

    auto verify_set = [&](const dao_partial_set& s,
                          const std::vector<uint8_t>& c) -> bool {
        if (s.member_indices.size() != s.partials.size()) return false;
        if (s.proofs.size() != s.partials.size()) return false;
        if (s.member_indices.size() < effective_threshold) return false;
        std::vector<uint32_t> seen;
        for (size_t i = 0; i < s.member_indices.size(); ++i) {
            uint32_t m = s.member_indices[i];
            if (m < 1 || m > n) return false;
            for (uint32_t q : seen) if (q == m) return false;
            seen.push_back(m);
            if (s.partials[i].size() != PAILLIER_CT_BYTES) return false;
            if (s.proofs[i].member_index != m) return false;
            if (!dao_partial_decryption_verify(
                    pk, key_rec.V, effective_vk_i[m-1], m,
                    c, s.partials[i], s.proofs[i]))
                return false;
        }
        return true;
    };

    if (!verify_set(cert.W, E_W)) return false;
    if (!verify_set(cert.S, E_S)) return false;
    if (!verify_set(cert.B, E_B)) return false;

    BIGNUM* theta = BN_bin2bn(key_rec.theta.data(),
                              static_cast<int>(key_rec.theta.size()),
                              nullptr);
    if (!theta) return false;

    auto recover = [&](const dao_partial_set& s,
                       const std::vector<uint8_t>& c,
                       BIGNUM* m_out) -> bool {
        std::vector<uint8_t> C;
        if (!dao_threshold_combine(pk, s.member_indices, s.partials,
                                   effective_threshold, C))
            return false;
        return dao_threshold_finalize(pk, C, theta, m_out);
    };

    BIGNUM* mW = BN_new();
    BIGNUM* mS = BN_new();
    BIGNUM* mB = BN_new();
    bool ok = recover(cert.W, E_W, mW) &&
              recover(cert.S, E_S, mS) &&
              recover(cert.B, E_B, mB);
    if (!ok) {
        BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta);
        return false;
    }

    dao_u128 W_rec = 0, S_abs_rec = 0, B_rec = 0;
    bool s_neg_rec = false;
    if (!bn_to_u128(mW, W_rec) ||
        !decode_signed(mS, pk.N(), s_neg_rec, S_abs_rec) ||
        !bn_to_u128(mB, B_rec)) {
        BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta);
        return false;
    }

    if (W_rec != cert.W_total) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (s_neg_rec != cert.s_negative) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (S_abs_rec != cert.S_abs) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (B_rec != cert.B_total) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (B_rec > supply_at_vote_end.circulating) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }

    const dao_u128 W_MAX =
        dao_u128(240000000ULL) * dao_u128(1000000000000ULL);
    if (W_rec > W_MAX) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (S_abs_rec > W_rec) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (((W_rec + S_abs_rec) & 1) != 0) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }

    dao_u128 YES = cert.s_negative
        ? (W_rec - S_abs_rec) / 2
        : (W_rec + S_abs_rec) / 2;
    dao_u128 NO  = W_rec - YES;

    dao_u128 qthresh = 0;
    bool qmet = false, mmet = false, passed = false;
    if (!dao_evaluate_v2_tally(YES, NO, B_rec,
                               supply_at_vote_end.circulating,
                               quorum_percent,
                               qthresh, qmet, mmet, passed)) {
        BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta);
        return false;
    }

    cert.YES_weight       = YES;
    cert.NO_weight        = NO;
    cert.quorum_threshold = qthresh;
    cert.quorum_met       = qmet;
    cert.majority_met     = mmet;
    cert.passed           = passed;

    BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta);
    return true;
}

} // namespace dao
} // namespace cryptonote
