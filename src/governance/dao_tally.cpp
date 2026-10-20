// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_tally.h"

#include <cstring>

#include <openssl/sha.h>

#include "governance/dao_threshold.h"

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
void decode_signed(const BIGNUM* m, const BIGNUM* N,
                   bool& negative, dao_u128& magnitude)
{
    BIGNUM* half = BN_new();
    BN_rshift1(half, N);
    CtxGuard g;
    if (BN_cmp(m, half) <= 0) {
        negative = false;
        magnitude = 0;
        for (int i = BN_num_bytes(m) - 1; i >= 0; --i) {
            magnitude = (magnitude << 8) | dao_u128(BN_is_bit_set(m, i*8) ? 1 : 0);
        }
        // simpler: convert via bytes
        const int nbytes = BN_num_bytes(m);
        std::vector<uint8_t> buf(nbytes);
        BN_bn2bin(m, buf.data());
        magnitude = 0;
        for (uint8_t x : buf) magnitude = (magnitude << 8) | dao_u128(x);
    } else {
        negative = true;
        BIGNUM* neg = BN_new();
        BN_sub(neg, N, m);           // magnitude = N - m
        const int nbytes = BN_num_bytes(neg);
        std::vector<uint8_t> buf(nbytes);
        BN_bn2bin(neg, buf.data());
        magnitude = 0;
        for (uint8_t x : buf) magnitude = (magnitude << 8) | dao_u128(x);
        BN_free(neg);
    }
    BN_free(half);
}

// Non-negative decode.
dao_u128 bn_to_u128(const BIGNUM* b)
{
    const int nbytes = BN_num_bytes(b);
    std::vector<uint8_t> buf(nbytes);
    BN_bn2bin(b, buf.data());
    dao_u128 out = 0;
    for (uint8_t x : buf) out = (out << 8) | dao_u128(x);
    return out;
}

} // anonymous namespace

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

bool dao_synthesize_bootstrap_share_set(
    const dao_tally_key_record& key_rec,
    dao_share_set_record& out)
{
    if (key_rec.V_K_i.size() != key_rec.committee_size) return false;
    if (key_rec.committee_members.size() != key_rec.committee_size)
        return false;
    if (key_rec.key_id.size() != 32) return false;

    out = dao_share_set_record{};
    out.version      = 1;
    out.share_set_id = 1;
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
    dao_tally_certificate& cert_out)
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

    const uint32_t n = static_cast<uint32_t>(
        key_rec.committee_members.size());

    auto check_set = [&](const dao_partial_set& s,
                         const std::vector<uint8_t>& c) -> bool {
        if (s.member_indices.size() != s.partials.size()) return false;
        if (s.proofs.size() != s.partials.size()) return false;
        if (s.member_indices.size() < key_rec.threshold) return false;
        std::vector<uint32_t> seen;
        for (size_t i = 0; i < s.member_indices.size(); ++i) {
            uint32_t m = s.member_indices[i];
            if (m < 1 || m > n) return false;
            for (uint32_t q : seen) if (q == m) return false;
            seen.push_back(m);
            if (s.partials[i].size() != PAILLIER_CT_BYTES) return false;
            if (s.proofs[i].member_index != m) return false;
            if (!dao_partial_decryption_verify(
                    pk, key_rec.V, key_rec.V_K_i[m-1], m,
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

    BIGNUM* theta = BN_bin2bn(key_rec.theta.data(),
                              static_cast<int>(key_rec.theta.size()),
                              nullptr);
    if (!theta) return false;

    auto recover = [&](const dao_partial_set& s,
                       const std::vector<uint8_t>& c,
                       BIGNUM* m_out) -> bool {
        std::vector<uint8_t> C;
        if (!dao_threshold_combine(pk, s.member_indices, s.partials,
                                   key_rec.threshold, C))
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
        cert_out.W_total = bn_to_u128(mW);
        decode_signed(mS, pk.N(), cert_out.s_negative, cert_out.S_abs);
        cert_out.B_total = bn_to_u128(mB);
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

    if (E_W.size() != PAILLIER_CT_BYTES) return false;
    if (E_S.size() != PAILLIER_CT_BYTES) return false;
    if (E_B.size() != PAILLIER_CT_BYTES) return false;

    const crypto::hash h = dao_aggregate_ciphertext_hash(E_W, E_S, E_B);
    if (memcmp(h.data, cert.aggregate_ciphertext_hash.data, 32) != 0)
        return false;

    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(key_rec.N)) return false;

    const uint32_t n = static_cast<uint32_t>(
        key_rec.committee_members.size());

    auto verify_set = [&](const dao_partial_set& s,
                          const std::vector<uint8_t>& c) -> bool {
        if (s.member_indices.size() != s.partials.size()) return false;
        if (s.proofs.size() != s.partials.size()) return false;
        if (s.member_indices.size() < key_rec.threshold) return false;
        std::vector<uint32_t> seen;
        for (size_t i = 0; i < s.member_indices.size(); ++i) {
            uint32_t m = s.member_indices[i];
            if (m < 1 || m > n) return false;
            for (uint32_t q : seen) if (q == m) return false;
            seen.push_back(m);
            if (s.partials[i].size() != PAILLIER_CT_BYTES) return false;
            if (s.proofs[i].member_index != m) return false;
            if (!dao_partial_decryption_verify(
                    pk, key_rec.V, key_rec.V_K_i[m-1], m,
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
                                   key_rec.threshold, C))
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

    dao_u128 W_rec = bn_to_u128(mW);
    bool s_neg_rec = false;
    dao_u128 S_abs_rec = 0;
    decode_signed(mS, pk.N(), s_neg_rec, S_abs_rec);
    dao_u128 B_rec = bn_to_u128(mB);

    if (W_rec != cert.W_total) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (s_neg_rec != cert.s_negative) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (S_abs_rec != cert.S_abs) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }
    if (B_rec != cert.B_total) { BN_free(mW); BN_free(mS); BN_free(mB); BN_free(theta); return false; }

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
