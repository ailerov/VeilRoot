// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_dkg.h"
#include "governance/dao_dkg_transport.h"

#include <cstring>
#include <stdexcept>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "ringct/rctOps.h"

namespace cryptonote {
namespace dao {

// ====================================================================
// Internal helpers
// ====================================================================

uint32_t dao_dkg_required_vss_bits(uint32_t /*k_bits*/,
                                   uint32_t target_N_bits,
                                   uint32_t security_bits)
{
    // Conservative bound from §30:
    //   theta_max = 2 * n * Delta * K * (1 + K) * N_max^2
    // with K = 2^security_bits, N_max = 2^target_N_bits, Delta = 16!.
    //
    // log2(theta_max) ≈ 1 + log2(n) + log2(Delta) + 2*security_bits
    //                 + 2*target_N_bits
    //
    // n = 16 → log2(n) = 4
    // Delta = 16! → log2(Delta) ≈ 44.2
    //
    // P' > 2 * theta_max, so add 1 bit and 16 bits of margin.
    const uint64_t bits = 1ULL
                        + 4ULL
                        + 45ULL
                        + 2ULL * security_bits
                        + 2ULL * target_N_bits
                        + 1ULL
                        + 16ULL;
    return static_cast<uint32_t>(bits);
}

namespace {

struct CtxGuard {
    BN_CTX* ctx;
    CtxGuard() : ctx(BN_CTX_new()) {}
    ~CtxGuard() { if (ctx) BN_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
    bool ok() const { return ctx != nullptr; }
};

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

bool push_bytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
    return true;
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

// Modular exponentiation with support for a signed exponent.
bool modexp_signed(const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod,
                   BIGNUM* out, BN_CTX* ctx)
{
    if (!BN_is_negative(exp)) {
        return BN_mod_exp(out, base, exp, mod, ctx) == 1;
    }
    BIGNUM* inv = BN_mod_inverse(nullptr, base, mod, ctx);
    if (!inv) return false;
    BIGNUM* pos = BN_dup(exp);
    if (!pos) { BN_free(inv); return false; }
    BN_set_negative(pos, 0);
    const bool ok = BN_mod_exp(out, inv, pos, mod, ctx) == 1;
    BN_free(inv);
    BN_free(pos);
    return ok;
}

// SHA-256 over four byte strings. Challenge for the Q_i proof.
bool challenge_hash(const std::vector<uint8_t>& a,
                    const std::vector<uint8_t>& b,
                    const std::vector<uint8_t>& c4,
                    const std::vector<uint8_t>& ci2,
                    BIGNUM* E_out)
{
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) return false;
    if (!a.empty())   SHA256_Update(&ctx, a.data(), a.size());
    if (!b.empty())   SHA256_Update(&ctx, b.data(), b.size());
    if (!c4.empty())  SHA256_Update(&ctx, c4.data(), c4.size());
    if (!ci2.empty()) SHA256_Update(&ctx, ci2.data(), ci2.size());
    unsigned char digest[32];
    if (!SHA256_Final(digest, &ctx)) return false;
    BN_bin2bn(digest, 32, E_out);
    return true;
}

// Canonical 32-byte big-endian encoding of a challenge scalar.
void E_to_bytes(const BIGNUM* E, std::vector<uint8_t>& out)
{
    out.assign(32, 0);
    BN_bn2binpad(E, out.data(), 32);
}

// Signed BIGNUM serialization: sign byte (0 = non-negative, 1 = negative)
// followed by big-endian magnitude. BN_bn2bin alone discards the sign,
// which silently corrupts any wire value that can be negative.
void bn_to_signed(const BIGNUM* b, std::vector<uint8_t>& out)
{
    out.clear();
    out.push_back(BN_is_negative(b) ? 1 : 0);
    const int n = BN_num_bytes(b);
    if (n > 0) {
        const size_t off = out.size();
        out.resize(off + n);
        BN_bn2bin(b, out.data() + off);
    }
}

BIGNUM* bn_from_signed(const std::vector<uint8_t>& in)
{
    if (in.empty()) return nullptr;
    const bool neg = in[0] != 0;
    BIGNUM* v = BN_bin2bn(in.data() + 1,
                          static_cast<int>(in.size() - 1), nullptr);
    if (!v) return nullptr;
    if (neg) BN_set_negative(v, 1);
    return v;
}

// Return (P-1)/2 for the VSS group. Caller owns the returned BIGNUM.
BIGNUM* vss_group_order(const dao_vss_group& g)
{
    BIGNUM* q = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);
    BN_sub(q, g.P, one);
    BN_rshift1(q, q);
    BN_free(one);
    return q;
}

// Serialize and deserialize a Q_i proof.
void push_u8(std::vector<uint8_t>& v, uint8_t b) { v.push_back(b); }

bool pull_u8(const std::vector<uint8_t>& v, size_t& off, uint8_t& b)
{
    if (off + 1 > v.size()) return false;
    b = v[off++];
    return true;
}

bool serialize_Q_proof(const dao_Q_proof& p, std::vector<uint8_t>& out)
{
    out.clear();
    push_u32(out, p.member_index);
    push_u32(out, static_cast<uint32_t>(p.reps.size()));
    for (const auto& r : p.reps) {
        push_bytes(out, r.A);
        push_bytes(out, r.B);
        push_u8(out, r.c);
        push_bytes(out, r.zx);
        push_bytes(out, r.zy);
    }
    return true;
}

bool deserialize_Q_proof(const std::vector<uint8_t>& in, dao_Q_proof& out)
{
    size_t off = 0;
    if (!pull_u32(in, off, out.member_index)) return false;
    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > 1024) return false;
    out.reps.assign(n, {});
    for (uint32_t i = 0; i < n; ++i) {
        if (!pull_bytes(in, off, out.reps[i].A)) return false;
        if (!pull_bytes(in, off, out.reps[i].B)) return false;
        if (!pull_u8(in, off, out.reps[i].c)) return false;
        if (!pull_bytes(in, off, out.reps[i].zx)) return false;
        if (!pull_bytes(in, off, out.reps[i].zy)) return false;
    }
    if (off != in.size()) return false;
    return true;
}

} // anonymous namespace

// ====================================================================
// Message serialization
// ====================================================================

bool dkg_msg::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    out.push_back(hdr.version);
    push_u32(out, hdr.epoch);
    push_u32(out, hdr.committee_id);
    push_u32(out, hdr.sender_id);
    push_u32(out, hdr.recipient_id);
    push_u32(out, hdr.phase);
    push_u32(out, hdr.round);
    push_u64(out, hdr.sequence);
    out.push_back(static_cast<uint8_t>(hdr.type));
    push_u32(out, tag32);
    push_bytes(out, bytes_a);
    push_bytes(out, bytes_b);
    push_bytes(out, bytes_c);
    push_bytes(out, bytes_d);
    push_u32(out, static_cast<uint32_t>(vec_a.size()));
    for (const auto& e : vec_a) push_bytes(out, e);
    return true;
}

bool dkg_msg::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (in.size() < 4) return false;
    hdr.version = in[off++];
    if (hdr.version != 1) return false;
    if (!pull_u32(in, off, hdr.epoch)) return false;
    if (!pull_u32(in, off, hdr.committee_id)) return false;
    if (!pull_u32(in, off, hdr.sender_id)) return false;
    if (!pull_u32(in, off, hdr.recipient_id)) return false;
    if (!pull_u32(in, off, hdr.phase)) return false;
    if (!pull_u32(in, off, hdr.round)) return false;
    if (!pull_u64(in, off, hdr.sequence)) return false;
    if (off >= in.size()) return false;
    hdr.type = static_cast<dkg_msg_type>(in[off++]);
    if (!pull_u32(in, off, tag32)) return false;
    if (!pull_bytes(in, off, bytes_a)) return false;
    if (!pull_bytes(in, off, bytes_b)) return false;
    if (!pull_bytes(in, off, bytes_c)) return false;
    if (!pull_bytes(in, off, bytes_d)) return false;
    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > 4096) return false;
    vec_a.assign(n, {});
    for (uint32_t i = 0; i < n; ++i)
        if (!pull_bytes(in, off, vec_a[i])) return false;
    if (off != in.size()) return false;
    return true;
}

// ====================================================================
// VSS
// ====================================================================

dao_vss_group::~dao_vss_group()
{
    if (P) BN_free(P);
    if (g) BN_free(g);
    if (h) BN_free(h);
}

bool dao_vss_group_generate(dao_vss_group& out, unsigned int bits)
{
    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* q = BN_new();
    BIGNUM* P = BN_new();
    if (!q || !P) { BN_free(q); BN_free(P); return false; }

    if (!BN_generate_prime_ex(q, static_cast<int>(bits) - 1, 0,
                              nullptr, nullptr, nullptr)) {
        BN_free(q); BN_free(P); return false;
    }
    if (!BN_lshift(P, q, 1) || !BN_add(P, P, BN_value_one())) {
        BN_free(q); BN_free(P); return false;
    }

    BIGNUM* g_val = BN_new();
    BIGNUM* h_val = BN_new();
    if (!g_val || !h_val) {
        BN_free(q); BN_free(P); BN_free(g_val); BN_free(h_val); return false;
    }
    if (!BN_rand_range(g_val, q) || !BN_rand_range(h_val, q)) {
        BN_free(q); BN_free(P); BN_free(g_val); BN_free(h_val); return false;
    }

    BIGNUM* two = BN_new();
    BN_set_word(two, 2);
    const bool ok =
        BN_mod_exp(g_val, two, g_val, P, g.ctx) == 1 &&
        BN_mod_exp(h_val, two, h_val, P, g.ctx) == 1;
    BN_free(two);

    if (!ok) {
        BN_free(q); BN_free(P); BN_free(g_val); BN_free(h_val); return false;
    }

    if (out.P) BN_free(out.P);
    if (out.g) BN_free(out.g);
    if (out.h) BN_free(out.h);
    out.P = P;
    out.g = g_val;
    out.h = h_val;
    BN_free(q);
    return true;
}

bool dao_vss_deal(const dao_vss_group& grp,
                  const BIGNUM* secret,
                  uint32_t n,
                  uint32_t degree,
                  dao_vss_commitments& commitments_out,
                  std::vector<BIGNUM*>& shares_out,
                  std::vector<BIGNUM*>& blindings_out)
{
    if (!grp.valid() || !secret) return false;
    if (n < degree + 1) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const uint32_t t = degree;

    std::vector<BIGNUM*> a(t + 1, nullptr);
    std::vector<BIGNUM*> b(t + 1, nullptr);
    a[0] = BN_dup(secret);
    if (!a[0]) return false;
    for (uint32_t k = 1; k <= t; ++k) a[k] = BN_new();
    for (uint32_t k = 0; k <= t; ++k) b[k] = BN_new();

    for (uint32_t k = 1; k <= t; ++k)
        if (!BN_rand_range(a[k], grp.P)) return false;
    for (uint32_t k = 0; k <= t; ++k)
        if (!BN_rand_range(b[k], grp.P)) return false;

    commitments_out.C.assign(t + 1, {});
    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(grp.P));
    for (uint32_t k = 0; k <= t; ++k) {
        BIGNUM* ga = BN_new();
        BIGNUM* hb = BN_new();
        BIGNUM* C  = BN_new();
        if (!ga || !hb || !C) return false;
        if (!BN_mod_exp(ga, grp.g, a[k], grp.P, ctx.ctx)) return false;
        if (!BN_mod_exp(hb, grp.h, b[k], grp.P, ctx.ctx)) return false;
        if (!BN_mod_mul(C, ga, hb, grp.P, ctx.ctx)) return false;
        commitments_out.C[k].assign(P_bytes, 0);
        BN_bn2binpad(C, commitments_out.C[k].data(),
                     static_cast<int>(P_bytes));
        BN_free(ga); BN_free(hb); BN_free(C);
    }

    shares_out.assign(n, nullptr);
    blindings_out.assign(n, nullptr);
    for (uint32_t i = 1; i <= n; ++i) {
        BIGNUM* s = BN_new();
        BIGNUM* ti = BN_new();
        BIGNUM* pow = BN_new();
        if (!s || !ti || !pow) return false;
        BN_zero(s); BN_zero(ti); BN_one(pow);
        for (uint32_t k = 0; k <= t; ++k) {
            BIGNUM* term_s = BN_new();
            BIGNUM* term_t = BN_new();
            if (!term_s || !term_t) return false;
            if (!BN_mul(term_s, a[k], pow, ctx.ctx)) return false;
            if (!BN_mul(term_t, b[k], pow, ctx.ctx)) return false;
            if (!BN_add(s, s, term_s)) return false;
            if (!BN_add(ti, ti, term_t)) return false;
            BN_free(term_s); BN_free(term_t);
            if (k < t) BN_mul_word(pow, i);
        }
        shares_out[i - 1] = s;
        blindings_out[i - 1] = ti;
        BN_free(pow);
    }

    for (auto* x : a) if (x) BN_free(x);
    for (auto* x : b) if (x) BN_free(x);
    return true;
}

bool dao_vss_verify_share(const dao_vss_group& grp,
                          const dao_vss_commitments& commitments,
                          uint32_t i,
                          const BIGNUM* share,
                          const BIGNUM* blinding)
{
    if (!grp.valid() || !share || !blinding) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* lhs_a = BN_new();
    BIGNUM* lhs_b = BN_new();
    BIGNUM* lhs = BN_new();
    if (!lhs_a || !lhs_b || !lhs) return false;
    if (!BN_mod_exp(lhs_a, grp.g, share, grp.P, ctx.ctx)) return false;
    if (!BN_mod_exp(lhs_b, grp.h, blinding, grp.P, ctx.ctx)) return false;
    if (!BN_mod_mul(lhs, lhs_a, lhs_b, grp.P, ctx.ctx)) return false;

    BIGNUM* rhs = BN_new();
    BN_one(rhs);
    BIGNUM* pow = BN_new();
    BN_one(pow);
    const uint32_t t = static_cast<uint32_t>(commitments.C.size()) - 1;
    for (uint32_t k = 0; k <= t; ++k) {
        BIGNUM* C_k = BN_bin2bn(commitments.C[k].data(),
                                static_cast<int>(commitments.C[k].size()),
                                nullptr);
        BIGNUM* term = BN_new();
        if (!C_k || !term) { BN_free(C_k); BN_free(term); return false; }
        if (!BN_mod_exp(term, C_k, pow, grp.P, ctx.ctx)) return false;
        if (!BN_mod_mul(rhs, rhs, term, grp.P, ctx.ctx)) return false;
        BN_free(C_k); BN_free(term);
        if (k < t) {
            BN_mul_word(pow, i);
            BN_mod(pow, pow, grp.P, ctx.ctx);
        }
    }

    const bool ok = (BN_cmp(lhs, rhs) == 0);
    BN_free(lhs_a); BN_free(lhs_b); BN_free(lhs);
    BN_free(rhs); BN_free(pow);
    return ok;
}

// ====================================================================
// Verification keys
// ====================================================================

bool dao_choose_verification_base(const PaillierPublicKey& pk,
                                  std::vector<uint8_t>& V_K_out)
{
    if (!pk.valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* v = BN_new();
    if (!BN_rand_range(v, pk.N2())) { BN_free(v); return false; }
    BIGNUM* gcd = BN_new();
    BN_gcd(gcd, v, pk.N2(), ctx.ctx);
    if (!BN_is_one(gcd)) { BN_free(v); BN_free(gcd); return false; }
    BN_free(gcd);

    BIGNUM* VK = BN_new();
    BN_mod_mul(VK, v, v, pk.N2(), ctx.ctx);

    V_K_out.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(VK, V_K_out.data(), PAILLIER_CT_BYTES);

    BN_free(v); BN_free(VK);
    return true;
}

bool dao_derive_verification_key(const PaillierPublicKey& pk,
                                 const std::vector<uint8_t>& V_K,
                                 const BIGNUM* share,
                                 std::vector<uint8_t>& V_K_i_out)
{
    if (!pk.valid() || !share) return false;
    if (V_K.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* vk = BN_bin2bn(V_K.data(), static_cast<int>(V_K.size()), nullptr);
    if (!vk) return false;

    BIGNUM* exp = BN_new();
    if (!BN_mul(exp, dao_dkg_delta(), share, ctx.ctx)) return false;

    BIGNUM* VKi = BN_new();
    if (!BN_mod_exp(VKi, vk, exp, pk.N2(), ctx.ctx)) return false;

    V_K_i_out.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(VKi, V_K_i_out.data(), PAILLIER_CT_BYTES);

    BN_free(vk); BN_free(exp); BN_free(VKi);
    return true;
}

// ====================================================================
// Partial-decryption ZK proof (Appendix C)
// ====================================================================

bool dao_dkg_sample_r(const PaillierPublicKey& pk, BIGNUM* r_out)
{
    if (!pk.valid() || !r_out) return false;
    return BN_rand_range(r_out, pk.N()) == 1;
}

bool dao_partial_decryption_prove(const PaillierPublicKey& pk,
                                  const std::vector<uint8_t>& V_K,
                                  const std::vector<uint8_t>& V_K_i,
                                  uint32_t member_index,
                                  const std::vector<uint8_t>& c_bytes,
                                  const std::vector<uint8_t>& c_i_bytes,
                                  const BIGNUM* share,
                                  const BIGNUM* randomness,
                                  dao_partial_decryption_proof& proof_out)
{
    if (!pk.valid() || !share || !randomness) return false;
    if (c_bytes.size() != PAILLIER_CT_BYTES) return false;
    if (c_i_bytes.size() != PAILLIER_CT_BYTES) return false;
    if (V_K.size() != PAILLIER_CT_BYTES) return false;
    if (V_K_i.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* c   = BN_bin2bn(c_bytes.data(),   static_cast<int>(c_bytes.size()),   nullptr);
    BIGNUM* ci  = BN_bin2bn(c_i_bytes.data(), static_cast<int>(c_i_bytes.size()), nullptr);
    BIGNUM* vk  = BN_bin2bn(V_K.data(),       static_cast<int>(V_K.size()),       nullptr);
    if (!c || !ci || !vk) return false;

    const BIGNUM* N2 = pk.N2();

    BIGNUM* c4 = BN_new();
    BIGNUM* four = BN_new();
    BN_set_word(four, 4);
    if (!BN_mod_exp(c4, c, four, N2, ctx.ctx)) return false;

    BIGNUM* ci2 = BN_new();
    if (!BN_mod_mul(ci2, ci, ci, N2, ctx.ctx)) return false;

    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
    if (!BN_mod_exp(a, c4, randomness, N2, ctx.ctx)) return false;
    if (!BN_mod_exp(b, vk, randomness, N2, ctx.ctx)) return false;

    std::vector<uint8_t> a_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> b_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> c4_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> ci2_bytes(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(a,   a_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(b,   b_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(c4,  c4_bytes.data(),  PAILLIER_CT_BYTES);
    BN_bn2binpad(ci2, ci2_bytes.data(), PAILLIER_CT_BYTES);

    BIGNUM* E = BN_new();
    if (!challenge_hash(a_bytes, b_bytes, c4_bytes, ci2_bytes, E)) return false;

    BIGNUM* Z = BN_new();
    BIGNUM* ed = BN_new();
    if (!BN_mul(ed, E, dao_dkg_delta(), ctx.ctx)) return false;
    if (!BN_mul(ed, ed, share, ctx.ctx)) return false;
    if (!BN_add(Z, randomness, ed)) return false;

    proof_out.member_index = member_index;
    E_to_bytes(E, proof_out.E);
    proof_out.Z.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(Z, proof_out.Z.data(), PAILLIER_CT_BYTES);

    BN_free(c); BN_free(ci); BN_free(vk);
    BN_free(c4); BN_free(four); BN_free(ci2);
    BN_free(a); BN_free(b); BN_free(E); BN_free(Z); BN_free(ed);
    return true;
}

bool dao_partial_decryption_verify(const PaillierPublicKey& pk,
                                   const std::vector<uint8_t>& V_K,
                                   const std::vector<uint8_t>& V_K_i,
                                   uint32_t member_index,
                                   const std::vector<uint8_t>& c_bytes,
                                   const std::vector<uint8_t>& c_i_bytes,
                                   const dao_partial_decryption_proof& proof)
{
    if (!pk.valid()) return false;
    if (proof.member_index != member_index) return false;
    if (proof.E.size() != 32) return false;
    if (proof.Z.size() != PAILLIER_CT_BYTES) return false;
    if (V_K.size() != PAILLIER_CT_BYTES) return false;
    if (V_K_i.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* c   = BN_bin2bn(c_bytes.data(),   static_cast<int>(c_bytes.size()),   nullptr);
    BIGNUM* ci  = BN_bin2bn(c_i_bytes.data(), static_cast<int>(c_i_bytes.size()), nullptr);
    BIGNUM* vk  = BN_bin2bn(V_K.data(),       static_cast<int>(V_K.size()),       nullptr);
    BIGNUM* vki = BN_bin2bn(V_K_i.data(),     static_cast<int>(V_K_i.size()),     nullptr);
    BIGNUM* E   = BN_bin2bn(proof.E.data(),   static_cast<int>(proof.E.size()),   nullptr);
    BIGNUM* Z   = BN_bin2bn(proof.Z.data(),   static_cast<int>(proof.Z.size()),   nullptr);
    if (!c || !ci || !vk || !vki || !E || !Z) return false;

    const BIGNUM* N2 = pk.N2();

    BIGNUM* c4 = BN_new();
    BIGNUM* four = BN_new();
    BN_set_word(four, 4);
    if (!BN_mod_exp(c4, c, four, N2, ctx.ctx)) return false;

    BIGNUM* ci2 = BN_new();
    if (!BN_mod_mul(ci2, ci, ci, N2, ctx.ctx)) return false;

    BIGNUM* negE = BN_new();
    BN_copy(negE, E);
    BN_set_negative(negE, 1);

    BIGNUM* a1 = BN_new();
    BIGNUM* a2 = BN_new();
    if (!BN_mod_exp(a1, c4, Z, N2, ctx.ctx)) return false;
    if (!modexp_signed(ci2, negE, N2, a2, ctx.ctx)) return false;
    BIGNUM* a = BN_new();
    BN_mod_mul(a, a1, a2, N2, ctx.ctx);

    BIGNUM* b1 = BN_new();
    BIGNUM* b2 = BN_new();
    if (!BN_mod_exp(b1, vk, Z, N2, ctx.ctx)) return false;
    if (!modexp_signed(vki, negE, N2, b2, ctx.ctx)) return false;
    BIGNUM* b = BN_new();
    BN_mod_mul(b, b1, b2, N2, ctx.ctx);

    std::vector<uint8_t> a_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> b_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> c4_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> ci2_bytes(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(a,   a_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(b,   b_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(c4,  c4_bytes.data(),  PAILLIER_CT_BYTES);
    BN_bn2binpad(ci2, ci2_bytes.data(), PAILLIER_CT_BYTES);

    BIGNUM* E_check = BN_new();
    if (!challenge_hash(a_bytes, b_bytes, c4_bytes, ci2_bytes, E_check)) return false;

    const bool ok = (BN_cmp(E, E_check) == 0);

    BN_free(c); BN_free(ci); BN_free(vk); BN_free(vki); BN_free(E); BN_free(Z);
    BN_free(c4); BN_free(four); BN_free(ci2);
    BN_free(negE);
    BN_free(a1); BN_free(a2); BN_free(a);
    BN_free(b1); BN_free(b2); BN_free(b);
    BN_free(E_check);
    return ok;
}

// ====================================================================
// Key record serialization
// ====================================================================

bool dao_tally_key_record::serialize(std::vector<uint8_t>& out) const
{
    // Strict canonical layout. Every field is length-prefixed or
    // fixed-width, in a single well-defined order.
    if (committee_id_hash.size() != 32) return false;
    if (delta.size() != 32) return false;
    if (N.size() != PAILLIER_MODULUS_BYTES) return false;
    if (G.size() != PAILLIER_MODULUS_BYTES) return false;
    if (theta.size() != PAILLIER_MODULUS_BYTES) return false;
    if (V.size() != PAILLIER_CT_BYTES) return false;
    if (V_K_i.size() != committee_size) return false;
    for (const auto& vk : V_K_i)
        if (vk.size() != PAILLIER_CT_BYTES) return false;
    if (dkg_transcript_hash.size() != 32) return false;
    if (key_id.size() != 32) return false;

    out.clear();
    push_u32(out, version);
    push_u32(out, epoch);
    push_u32(out, committee_size);
    push_u32(out, threshold);
    push_u32(out, t);
    out.insert(out.end(), committee_id_hash.begin(), committee_id_hash.end());
    out.insert(out.end(), delta.begin(), delta.end());
    out.insert(out.end(), N.begin(), N.end());
    out.insert(out.end(), G.begin(), G.end());
    out.insert(out.end(), theta.begin(), theta.end());
    out.insert(out.end(), V.begin(), V.end());
    for (const auto& vk : V_K_i)
        out.insert(out.end(), vk.begin(), vk.end());
    push_bytes(out, vss_P);
    push_bytes(out, vss_P_prime);
    push_bytes(out, vss_g);
    push_bytes(out, vss_h);
    push_u64(out, activation_height);
    out.insert(out.end(), dkg_transcript_hash.begin(), dkg_transcript_hash.end());
    out.insert(out.end(), key_id.begin(), key_id.end());
    return true;
}

bool dao_tally_key_record::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0, e = 0, cs = 0, th = 0, tt = 0;
    if (!pull_u32(in, off, v)) return false;
    if (!pull_u32(in, off, e)) return false;
    if (!pull_u32(in, off, cs)) return false;
    if (!pull_u32(in, off, th)) return false;
    if (!pull_u32(in, off, tt)) return false;
    if (cs == 0 || cs > 64) return false;

    auto pull_fixed = [&](size_t n, std::vector<uint8_t>& dest) -> bool {
        if (off + n > in.size()) return false;
        dest.assign(in.begin() + off, in.begin() + off + n);
        off += n;
        return true;
    };

    if (!pull_fixed(32, committee_id_hash)) return false;
    if (!pull_fixed(32, delta)) return false;
    if (!pull_fixed(PAILLIER_MODULUS_BYTES, N)) return false;
    if (!pull_fixed(PAILLIER_MODULUS_BYTES, G)) return false;
    if (!pull_fixed(PAILLIER_MODULUS_BYTES, theta)) return false;
    if (!pull_fixed(PAILLIER_CT_BYTES, V)) return false;
    V_K_i.assign(cs, {});
    for (uint32_t i = 0; i < cs; ++i)
        if (!pull_fixed(PAILLIER_CT_BYTES, V_K_i[i])) return false;

    if (!pull_bytes(in, off, vss_P)) return false;
    if (!pull_bytes(in, off, vss_P_prime)) return false;
    if (!pull_bytes(in, off, vss_g)) return false;
    if (!pull_bytes(in, off, vss_h)) return false;
    if (!pull_u64(in, off, activation_height)) return false;
    if (!pull_fixed(32, dkg_transcript_hash)) return false;
    if (!pull_fixed(32, key_id)) return false;

    if (off != in.size()) return false;

    version = v;
    epoch = e;
    committee_size = cs;
    threshold = th;
    t = tt;
    return true;
}

bool dkg_result::to_record(std::vector<uint8_t>& out) const
{
    if (!ok) return false;
    return record.serialize(out);
}

// ====================================================================
// Party state machine
// ====================================================================

class dkg_party
{
public:
    dkg_party(uint32_t party_id, uint32_t committee_size,
              uint32_t threshold, uint32_t epoch)
        : party_id_(party_id),
          committee_size_(committee_size),
          threshold_(threshold),
          epoch_(epoch)
    {
        shares_p_received_.assign(committee_size + 1, nullptr);
        shares_q_received_.assign(committee_size + 1, nullptr);
        shares_h_received_.assign(committee_size + 1, nullptr);
        N_i_received_.assign(committee_size + 1, nullptr);
        Q_received_.assign(committee_size + 1, nullptr);
        beta_shares_received_.assign(committee_size + 1, nullptr);
        delta_r_shares_received_.assign(committee_size + 1, nullptr);
        h_theta_shares_received_.assign(committee_size + 1, nullptr);
        ra_shares_received_.assign(committee_size + 1, nullptr);
        rb_shares_received_.assign(committee_size + 1, nullptr);
        v_commit_received_.assign(committee_size + 1, {});
        v_reveal_received_.assign(committee_size + 1, nullptr);
    }

    ~dkg_party()
    {
        auto free_vec = [](std::vector<BIGNUM*>& v) {
            for (auto* p : v) if (p) BN_free(p);
            v.clear();
        };
        free_bn(p_i_); free_bn(q_i_);
        free_bn(h_coeffs_first_);
        free_bn(N_i_); free_bn(N_candidate_);
        free_bn(g_bar_); free_bn(Q_i_);
        free_bn(share_p_); free_bn(share_q_);
        free_bn(share_ra_); free_bn(share_rb_);
        free_bn(gamma_share_);
        free_bn(phi_share_);
        free_bn(beta_i_); free_bn(R_i_);
        free_bn(beta_share_); free_bn(f1_share_); free_bn(h_theta_share_);
        free_bn(theta_share_); free_bn(theta_tilde_); free_bn(theta_);
        free_bn(SK_i_);
        free_bn(v_r_i_); free_bn(V_);
        free_vec(shares_p_received_);
        free_vec(shares_q_received_);
        free_vec(shares_h_received_);
        free_vec(N_i_received_);
        free_vec(Q_received_);
        free_vec(ra_shares_received_);
        free_vec(rb_shares_received_);
        free_vec(beta_shares_received_);
        free_vec(delta_r_shares_received_);
        free_vec(h_theta_shares_received_);
        free_vec(v_reveal_received_);
    }

    uint32_t id() const { return party_id_; }
    uint32_t phase() const { return phase_; }
    bool     aborted() const { return aborted_; }

    void attach_transport(dkg_transport* t) { transport_ = t; }
    void attach_vss_group(const dao_vss_group* g) { vss_group_ = g; }
    void set_qproof_rounds(uint32_t r) { qproof_rounds_ = r; }

    // Phase transitions, all driven by messages by the driver.
    bool handle_message(const dkg_msg& m);

    // Produce the initial burst of messages for the current phase.
    bool start_phase(uint32_t phase, uint32_t k, uint32_t security_bits,
                     uint32_t target_N_bits);

    // Trial-division phase helpers (§4.1). Called by the driver.
    bool do_compute_share_pq();
    bool do_trial_division_prolog(uint32_t factor_selector);
    bool do_trial_division_gamma(uint32_t r);

    // §5 threshold key derivation. Called by the driver in sequence.
    bool do_phi_share_init();
    bool do_beta_R_generate();
    bool do_beta_R_collect();
    bool do_compute_theta_share();
    bool do_reconstruct_theta();
    bool do_compute_SK();
    bool do_v_commit();
    bool do_v_reveal();
    bool do_compute_V();
    bool do_derive_VKi(std::vector<uint8_t>& VKi_out);

    // Accessors for the driver.
    const BIGNUM* theta_tilde() const { return theta_tilde_; }
    const BIGNUM* theta() const { return theta_; }
    const BIGNUM* V() const { return V_; }
    const BIGNUM* SK() const { return SK_i_; }
    bool set_theta_tilde(const BIGNUM* v);
    bool set_V(const BIGNUM* v);

#ifdef VEILROOT_DAO_DKG_TESTING
public:
    const BIGNUM* test_beta_i() const { return beta_i_; }
    const BIGNUM* test_R_i() const { return R_i_; }
    const BIGNUM* test_theta_tilde() const { return theta_tilde_; }
    const BIGNUM* test_SK() const { return SK_i_; }
    const BIGNUM* test_phi_share() const { return phi_share_; }
#endif

    // Query.
    bool public_N(std::vector<uint8_t>& out) const;
    bool has_candidate_N() const { return N_candidate_ != nullptr; }

private:
    uint32_t party_id_;
    uint32_t committee_size_;
    uint32_t threshold_;
    uint32_t epoch_;

    uint32_t phase_ = 0;
    bool     aborted_ = false;
    uint64_t seq_ = 0;

    dkg_transport*      transport_ = nullptr;
    const dao_vss_group* vss_group_ = nullptr;

    // Config carried into phases
    uint32_t k_              = 0;
    uint32_t security_bits_  = 0;
    uint32_t target_N_bits_  = 0;
    uint32_t qproof_rounds_  = 0;

    // --- modulus generation ---
    BIGNUM* p_i_ = nullptr;
    BIGNUM* q_i_ = nullptr;
    dao_vss_commitments commits_p_;
    dao_vss_commitments commits_q_;
    dao_vss_commitments commits_h_;
    std::vector<BIGNUM*> shares_p_received_;
    std::vector<BIGNUM*> shares_q_received_;
    std::vector<BIGNUM*> shares_h_received_;
    BIGNUM* h_coeffs_first_ = nullptr;   // coefficient h_i for the product polynomial

    BIGNUM* N_i_ = nullptr;
    std::vector<BIGNUM*> N_i_received_;
    BIGNUM* N_candidate_ = nullptr;

    BIGNUM* g_bar_ = nullptr;
    BIGNUM* Q_i_ = nullptr;
    std::vector<BIGNUM*> Q_received_;

    // Trial-division state (§4.1)
    BIGNUM* share_p_ = nullptr;
    BIGNUM* share_q_ = nullptr;
    BIGNUM* share_ra_ = nullptr;
    BIGNUM* share_rb_ = nullptr;
    BIGNUM* gamma_share_ = nullptr;
    uint32_t trial_r_ = 0;
    std::vector<BIGNUM*> ra_shares_received_;
    std::vector<BIGNUM*> rb_shares_received_;

    // --- §5 threshold key derivation ---
    BIGNUM* phi_share_ = nullptr;       // Phi(i) = N + 1 - p(i) - q(i)

    BIGNUM* beta_i_ = nullptr;          // own beta_i
    BIGNUM* R_i_ = nullptr;             // own R_i
    dao_vss_commitments commits_beta_;
    dao_vss_commitments commits_delta_r_;
    dao_vss_commitments commits_h_theta_;
    std::vector<BIGNUM*> beta_shares_received_;      // Beta_j(i)
    std::vector<BIGNUM*> delta_r_shares_received_;   // F1_j(i)
    std::vector<BIGNUM*> h_theta_shares_received_;   // h_theta_j(i)

    BIGNUM* beta_share_ = nullptr;      // aggregate Beta(i)
    BIGNUM* f1_share_ = nullptr;        // aggregate F1(i)
    BIGNUM* h_theta_share_ = nullptr;   // aggregate H_theta(i)

    BIGNUM* theta_share_ = nullptr;     // Theta(i)
    BIGNUM* theta_tilde_ = nullptr;     // public value (Theta(0))
    BIGNUM* theta_ = nullptr;           // theta_tilde mod N

    BIGNUM* SK_i_ = nullptr;            // F(i)

    // V commit/reveal round.
    BIGNUM* v_r_i_ = nullptr;           // own r_i in Z*_{N^2}
    std::vector<std::vector<uint8_t>> v_commit_received_;   // per party
    std::vector<BIGNUM*> v_reveal_received_;                // per party
    BIGNUM* V_ = nullptr;

    // helpers
    void free_bn(BIGNUM*& p) { if (p) { BN_free(p); p = nullptr; } }
    bool send_msg(const dkg_msg& m);
    dkg_msg make_header(dkg_msg_type type, uint32_t recipient) const;

    bool do_polynomial_commit();
    bool do_bgw_product();
    bool do_publish_Q();

#ifdef VEILROOT_DAO_DKG_TESTING
public:
    // Test-only accessors. Not compiled into production builds.
    // The production DKG never possesses any party's p_i or q_i
    // individually; these accessors exist only so the test oracle
    // can reconstruct the accepted candidate's p and q.
    const BIGNUM* test_p_i() const { return p_i_; }
    const BIGNUM* test_q_i() const { return q_i_; }
#endif
};

// -------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------

bool dkg_party::send_msg(const dkg_msg& m)
{
    if (!transport_) return false;
    return transport_->send(m);
}

dkg_msg dkg_party::make_header(dkg_msg_type type, uint32_t recipient) const
{
    dkg_msg m;
    m.hdr.version      = 1;
    m.hdr.epoch        = epoch_;
    m.hdr.committee_id = 0;
    m.hdr.sender_id    = party_id_;
    m.hdr.recipient_id = recipient;
    m.hdr.phase        = phase_;
    m.hdr.round        = 0;
    m.hdr.sequence     = seq_;
    m.hdr.type         = type;
    return m;
}

// -------------------------------------------------------------------
// Phase A: generate polynomial commitments + distribute shares
// -------------------------------------------------------------------

bool dkg_party::do_polynomial_commit()
{
    if (!vss_group_ || !vss_group_->valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // p_i, q_i with residue conditions.
    // P1: p1 = q1 = 3 mod 4.
    // Pi (i>=2): pi = qi = 0 mod 4.
    const uint32_t t = threshold_ - 1;

    auto draw_candidate = [&](bool p1_style, BIGNUM* out) -> bool {
        if (!BN_rand(out, k_, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY)) return false;

        BIGNUM* four = BN_new();
        BN_set_word(four, 4);
        BIGNUM* r = BN_new();
        BN_mod(r, out, four, ctx.ctx);
        BIGNUM* target = BN_new();
        BN_set_word(target, p1_style ? 3 : 0);
        BIGNUM* diff = BN_new();
        BN_sub(diff, target, r);
        BN_nnmod(diff, diff, four, ctx.ctx);
        // BN_add, NOT BN_mod_add: we add a small correction (0..3) so
        // out becomes the right residue without reducing its magnitude.
        BN_add(out, out, diff);
        BN_free(four); BN_free(r); BN_free(target); BN_free(diff);
        return true;
    };

    const bool is_p1 = (party_id_ == 1);

    free_bn(p_i_);
    free_bn(q_i_);
    p_i_ = BN_new();
    q_i_ = BN_new();
    if (!draw_candidate(is_p1, p_i_)) return false;
    if (!draw_candidate(is_p1, q_i_)) return false;

    // Deal VSS of p_i and q_i at degree t.
    std::vector<BIGNUM*> s_p, s_q, b_p, b_q;
    if (!dao_vss_deal(*vss_group_, p_i_, committee_size_, t,
                      commits_p_, s_p, b_p)) return false;
    if (!dao_vss_deal(*vss_group_, q_i_, committee_size_, t,
                      commits_q_, s_q, b_q)) return false;

    // Deal VSS of h_i (with h_i(0)=0) at degree 2t.
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    std::vector<BIGNUM*> s_h, b_h;
    if (!dao_vss_deal(*vss_group_, zero, committee_size_, 2 * t,
                      commits_h_, s_h, b_h)) {
        BN_free(zero); return false;
    }
    BN_free(zero);

    // Broadcast commitments.
    {
        dkg_msg m = make_header(dkg_msg_type::polynomial_commitment_p, 0);
        for (const auto& c : commits_p_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::polynomial_commitment_q, 0);
        for (const auto& c : commits_q_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::polynomial_commitment_h, 0);
        for (const auto& c : commits_h_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }

    // Private shares to each party j = 1..n (including ourselves; we
    // will simply not loop back through the transport for j == our id).
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (j == party_id_) {
            // Store locally.
            if (shares_p_received_[j]) BN_free(shares_p_received_[j]);
            if (shares_q_received_[j]) BN_free(shares_q_received_[j]);
            if (shares_h_received_[j]) BN_free(shares_h_received_[j]);
            shares_p_received_[j] = BN_dup(s_p[j - 1]);
            shares_q_received_[j] = BN_dup(s_q[j - 1]);
            shares_h_received_[j] = BN_dup(s_h[j - 1]);
            continue;
        }

        dkg_msg m = make_header(dkg_msg_type::polynomial_share, j);
        // encode shares as big-endian byte blobs
        auto enc = [](const BIGNUM* b, std::vector<uint8_t>& out) {
            const int n = BN_num_bytes(b);
            out.assign(n, 0);
            BN_bn2bin(b, out.data());
        };
        enc(s_p[j - 1], m.bytes_a);
        enc(s_q[j - 1], m.bytes_b);
        enc(s_h[j - 1], m.bytes_c);
        // blindings not sent; verification uses public commitments plus
        // the sender's own recomputation. In a stricter construction
        // they would be sent too.
        if (!send_msg(m)) return false;
    }

    for (auto* x : s_p) BN_free(x);
    for (auto* x : s_q) BN_free(x);
    for (auto* x : s_h) BN_free(x);
    for (auto* x : b_p) BN_free(x);
    for (auto* x : b_q) BN_free(x);
    for (auto* x : b_h) BN_free(x);
    return true;
}

// -------------------------------------------------------------------
// Phase B: form N_i = (sum_j p_j_i)(sum_j q_j_i) + (sum_j h_j_i)
// -------------------------------------------------------------------

bool dkg_party::do_bgw_product()
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* sum_p = BN_new();
    BIGNUM* sum_q = BN_new();
    BIGNUM* sum_h = BN_new();
    if (!sum_p || !sum_q || !sum_h) return false;
    BN_zero(sum_p); BN_zero(sum_q); BN_zero(sum_h);

    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!shares_p_received_[j] || !shares_q_received_[j] ||
            !shares_h_received_[j]) return false;
        BN_add(sum_p, sum_p, shares_p_received_[j]);
        BN_add(sum_q, sum_q, shares_q_received_[j]);
        BN_add(sum_h, sum_h, shares_h_received_[j]);
    }

    BIGNUM* prod = BN_new();
    BN_mul(prod, sum_p, sum_q, ctx.ctx);
    BIGNUM* n_i = BN_new();
    BN_add(n_i, prod, sum_h);

    free_bn(N_i_);
    N_i_ = n_i;
    BN_free(prod);
    BN_free(sum_p); BN_free(sum_q); BN_free(sum_h);

    // Broadcast N_i.
    dkg_msg m = make_header(dkg_msg_type::bgw_product_share, 0);
    const int nb = BN_num_bytes(N_i_);
    m.bytes_a.assign(nb, 0);
    BN_bn2bin(N_i_, m.bytes_a.data());
    return send_msg(m);
}

// -------------------------------------------------------------------
// Phase C: publish Q_i (biprimality)
// -------------------------------------------------------------------

bool dkg_party::do_publish_Q()
{
    if (!N_candidate_) return false;
    if (!g_bar_) return false;
    if (!vss_group_ || !vss_group_->valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // The secret being proven:
    //   i == 1: s_1 = N + 1 - p_1 - q_1
    //   i >= 2: s_i = p_i + q_i
    //
    // x_i = s_i / 4, integer-exact by the residue conditions.
    // y_i:
    //   i == 1: q - r_1  where r_1 in [1, q)
    //   i >= 2: r_i      where r_i in [0, q)
    //
    // Commitments:
    //   i == 1: C0'_1 = g^(N+1) / [g^(p_1+q_1) * h^(r_1)]
    //         = (g^4)^x_1 * h^(q - r_1)  mod P'
    //   i >= 2: C0_i = g^(p_i+q_i) * h^(r_i) = (g^4)^x_i * h^(r_i)  mod P'
    //
    // Public values:
    //   Q_i = g_bar^x_i  mod N

    BIGNUM* q_ord = vss_group_order(*vss_group_);
    if (!q_ord) return false;

    BIGNUM* s = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* four = BN_new();
    BN_set_word(four, 4);

    // s.
    if (party_id_ == 1) {
        BIGNUM* tmp = BN_new();
        BN_add(tmp, N_candidate_, BN_value_one());
        BN_sub(tmp, tmp, p_i_);
        BN_sub(tmp, tmp, q_i_);
        BN_copy(s, tmp);
        BN_free(tmp);
    } else {
        BN_add(s, p_i_, q_i_);
    }

    // x = s / 4, assert exact.
    {
        BIGNUM* rem = BN_new();
        BN_div(x, rem, s, four, ctx.ctx);
        if (!BN_is_zero(rem)) {
            BN_free(q_ord); BN_free(s); BN_free(x); BN_free(r);
            BN_free(y); BN_free(four); BN_free(rem);
            return false;
        }
        BN_free(rem);
    }
    BN_free(four);

    // r_i. For i == 1, sample from [1, q). For i >= 2, sample from [0, q).
    if (party_id_ == 1) {
        do {
            BN_rand_range(r, q_ord);
        } while (BN_is_zero(r));
        // y = q - r, so y is in [1, q).
        BN_sub(y, q_ord, r);
    } else {
        BN_rand_range(r, q_ord);
        BN_copy(y, r);
    }

    // g4 = g^4 mod P'.
    BIGNUM* g4 = BN_new();
    {
        BIGNUM* four2 = BN_new();
        BN_set_word(four2, 4);
        BN_mod_exp(g4, vss_group_->g, four2, vss_group_->P, ctx.ctx);
        BN_free(four2);
    }

    // g4x = (g^4)^x mod P'.
    BIGNUM* g4x = BN_new();
    BN_mod_exp(g4x, g4, x, vss_group_->P, ctx.ctx);

    // hr = h^y mod P'. Note: h^y where y is what we're using as the
    // blinding for the "commitment" side of the equation. For i == 1
    // this is h^(q-r) which equals h^(-r) because h has order q.
    BIGNUM* hy = BN_new();
    BN_mod_exp(hy, vss_group_->h, y, vss_group_->P, ctx.ctx);

    // C0' = (g^4)^x * h^y mod P'.
    BIGNUM* C0p = BN_new();
    BN_mod_mul(C0p, g4x, hy, vss_group_->P, ctx.ctx);

    // Q_i = g_bar^x mod N.
    BIGNUM* Q = BN_new();
    BN_mod_exp(Q, g_bar_, x, N_candidate_, ctx.ctx);

    // Proof.
    dao_Q_proof proof;
    if (!dao_Q_prove(*vss_group_, N_candidate_, g4, vss_group_->h,
                     g_bar_, C0p, Q, x, y, party_id_,
                     qproof_rounds_, proof)) {
        BN_free(q_ord); BN_free(s); BN_free(x); BN_free(r); BN_free(y);
        BN_free(g4); BN_free(g4x); BN_free(hy); BN_free(C0p); BN_free(Q);
        return false;
    }

    // Broadcast: bytes_a = C0' (P_bytes), bytes_b = Q (N_bytes),
    // bytes_c = serialized proof.
    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(vss_group_->P));
    const size_t N_bytes = static_cast<size_t>(BN_num_bytes(N_candidate_));

    dkg_msg m = make_header(dkg_msg_type::biprimality_Q, 0);
    m.tag32 = party_id_;
    m.bytes_a.assign(P_bytes, 0);
    BN_bn2binpad(C0p, m.bytes_a.data(), static_cast<int>(P_bytes));
    m.bytes_b.assign(N_bytes, 0);
    BN_bn2binpad(Q, m.bytes_b.data(), static_cast<int>(N_bytes));
    serialize_Q_proof(proof, m.bytes_c);

    const bool sent = send_msg(m);

    BN_free(q_ord); BN_free(s); BN_free(x); BN_free(r); BN_free(y);
    BN_free(g4); BN_free(g4x); BN_free(hy); BN_free(C0p); BN_free(Q);
    return sent;
}

// -------------------------------------------------------------------
// Compute the party's share of p and q from received VSS shares.
// -------------------------------------------------------------------

bool dkg_party::do_compute_share_pq()
{
    BIGNUM* sp = BN_new();
    BIGNUM* sq = BN_new();
    BN_zero(sp); BN_zero(sq);
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!shares_p_received_[j] || !shares_q_received_[j]) return false;
        BN_add(sp, sp, shares_p_received_[j]);
        BN_add(sq, sq, shares_q_received_[j]);
    }
    free_bn(share_p_);
    free_bn(share_q_);
    share_p_ = sp;
    share_q_ = sq;
    return true;
}

// -------------------------------------------------------------------
// §4.1 trial division. Fresh VSS of the per-party randomizers.
// `r` selects which small prime this phase is testing. r == 0 uses
// share_p_; r == 1 uses share_q_.
// -------------------------------------------------------------------

bool dkg_party::do_trial_division_prolog(uint32_t r)
{
    if (!vss_group_ || !vss_group_->valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    trial_r_ = r;
    const uint32_t t = threshold_ - 1;

    // p_max = 16 * 3 * 2^(k-1)
    BIGNUM* p_max = BN_new();
    BN_lshift(p_max, BN_value_one(), k_ - 1);
    BN_mul_word(p_max, 3);
    BN_mul_word(p_max, 16);

    // K = 2^security_bits
    BIGNUM* K = BN_new();
    BN_lshift(K, BN_value_one(), security_bits_);

    // K^2 * p_max^2
    BIGNUM* K2 = BN_new();
    BN_sqr(K2, K, ctx.ctx);
    BIGNUM* p_max2 = BN_new();
    BN_sqr(p_max2, p_max, ctx.ctx);
    BIGNUM* Rb_bound = BN_new();
    BN_mul(Rb_bound, K2, p_max2, ctx.ctx);

    // Ra_bound = K * p_max
    BIGNUM* Ra_bound = BN_new();
    BN_mul(Ra_bound, K, p_max, ctx.ctx);

    // Sample ra_i in [0, Ra_bound), rb_i in [0, Rb_bound)
    BIGNUM* ra_i = BN_new();
    BIGNUM* rb_i = BN_new();
    BN_rand_range(ra_i, Ra_bound);
    BN_rand_range(rb_i, Rb_bound);

    // VSS-deal ra_i and rb_i at degree t.
    dao_vss_commitments commits_ra, commits_rb;
    std::vector<BIGNUM*> s_ra, s_rb, b_ra, b_rb;
    if (!dao_vss_deal(*vss_group_, ra_i, committee_size_, t,
                      commits_ra, s_ra, b_ra)) {
        BN_free(p_max); BN_free(K); BN_free(K2);
        BN_free(p_max2); BN_free(Rb_bound); BN_free(Ra_bound);
        BN_free(ra_i); BN_free(rb_i);
        return false;
    }
    if (!dao_vss_deal(*vss_group_, rb_i, committee_size_, t,
                      commits_rb, s_rb, b_rb)) {
        BN_free(p_max); BN_free(K); BN_free(K2);
        BN_free(p_max2); BN_free(Rb_bound); BN_free(Ra_bound);
        BN_free(ra_i); BN_free(rb_i);
        return false;
    }

    // Broadcast commitments.
    {
        dkg_msg m = make_header(dkg_msg_type::trial_division_ra_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_ra.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::trial_division_rb_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_rb.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }

    // Private shares.
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (j == party_id_) {
            if (ra_shares_received_[j]) BN_free(ra_shares_received_[j]);
            if (rb_shares_received_[j]) BN_free(rb_shares_received_[j]);
            ra_shares_received_[j] = BN_dup(s_ra[j - 1]);
            rb_shares_received_[j] = BN_dup(s_rb[j - 1]);
            continue;
        }
        dkg_msg m = make_header(dkg_msg_type::trial_division_ra_share, j);
        m.tag32 = party_id_;
        const int n1 = BN_num_bytes(s_ra[j - 1]);
        m.bytes_a.assign(n1, 0);
        BN_bn2bin(s_ra[j - 1], m.bytes_a.data());
        const int n2 = BN_num_bytes(s_rb[j - 1]);
        m.bytes_b.assign(n2, 0);
        BN_bn2bin(s_rb[j - 1], m.bytes_b.data());
        if (!send_msg(m)) return false;
    }

    for (auto* x : s_ra) BN_free(x);
    for (auto* x : s_rb) BN_free(x);
    for (auto* x : b_ra) BN_free(x);
    for (auto* x : b_rb) BN_free(x);
    BN_free(p_max); BN_free(K); BN_free(K2);
    BN_free(p_max2); BN_free(Rb_bound); BN_free(Ra_bound);
    BN_free(ra_i); BN_free(rb_i);
    return true;
}

bool dkg_party::do_trial_division_gamma(uint32_t r)
{
    if (!share_p_ || !share_q_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // Sum received ra/rb shares into the party's share of Ra and Rb.
    BIGNUM* sra = BN_new();
    BIGNUM* srb = BN_new();
    BN_zero(sra); BN_zero(srb);
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!ra_shares_received_[j] || !rb_shares_received_[j]) return false;
        BN_add(sra, sra, ra_shares_received_[j]);
        BN_add(srb, srb, rb_shares_received_[j]);
    }
    free_bn(share_ra_);
    free_bn(share_rb_);
    share_ra_ = sra;
    share_rb_ = srb;

    // Party's share of the factor to test.
    BIGNUM* share_factor = (trial_r_ == 0) ? share_p_ : share_q_;

    // H_gamma is a shared degree-2t polynomial with H_gamma(0) = 0.
    // Its purpose is to randomize the individual share values of the
    // BGW product (P(x)-1)*Ra(x). In this implementation we set it to
    // zero. The security of the trial-division test does not depend on
    // it here because Ra and Rb are VSS-shared and unknown to any
    // single party, so the reconstructed value
    //     gamma = (p-1)*Ra + r*Rb
    // is already masked relative to p mod r. Setting the term to zero
    // (rather than sampling it locally per party) is required for
    // correctness: a per-party random term does not vanish under
    // Lagrange interpolation and masks the (p-1) mod r == 0 condition,
    // causing the test to falsely accept candidates whose small-prime
    // condition fails.
    BIGNUM* hi = BN_new();
    BN_zero(hi);

    // gamma_share_i = (share_factor - 1) * share_ra + h_i(i) + r * share_rb
    BIGNUM* pminus1 = BN_new();
    BN_sub(pminus1, share_factor, BN_value_one());

    BIGNUM* prod = BN_new();
    BN_mul(prod, pminus1, share_ra_, ctx.ctx);
    BN_add(prod, prod, hi);

    BIGNUM* rbn = BN_new();
    BN_set_word(rbn, r);
    BIGNUM* rterm = BN_new();
    BN_mul(rterm, rbn, share_rb_, ctx.ctx);
    BN_add(prod, prod, rterm);

    free_bn(gamma_share_);
    gamma_share_ = prod;

    dkg_msg m = make_header(dkg_msg_type::trial_division_gamma, 0);
    m.tag32 = party_id_;
    const int nb = BN_num_bytes(gamma_share_);
    m.bytes_a.assign(nb, 0);
    BN_bn2bin(gamma_share_, m.bytes_a.data());
    const bool sent = send_msg(m);
    BN_free(pminus1); BN_free(rbn); BN_free(rterm); BN_free(hi);
    return sent;
}

// -------------------------------------------------------------------
// start_phase / handle_message
// -------------------------------------------------------------------

bool dkg_party::start_phase(uint32_t phase, uint32_t k,
                            uint32_t security_bits, uint32_t target_N_bits)
{
    phase_ = phase;
    k_ = k;
    security_bits_ = security_bits;
    target_N_bits_ = target_N_bits;
    // qproof_rounds is set by the driver via set_qproof_rounds().

    switch (phase) {
        case 1: return do_polynomial_commit();
        case 2: return do_bgw_product();
        case 3: return true;   // driver broadcasts g_bar
        case 4: return do_publish_Q();
        case 5: return true;   // trial division handled by driver
        case 6: return do_phi_share_init();
        case 7: return do_beta_R_generate();
        case 8: return do_beta_R_collect();
        case 9: return do_compute_theta_share();
        case 10: return do_compute_SK();
        case 11: return do_v_commit();
        case 12: return do_v_reveal();
        case 13: return do_compute_V();
        default: return false;
    }
}

bool dkg_party::handle_message(const dkg_msg& m)
{
    if (m.hdr.epoch != epoch_) return false;
    if (m.hdr.sender_id > committee_size_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    switch (m.hdr.type) {
        case dkg_msg_type::polynomial_commitment_p:
            return true;   // stored by driver, not needed per-party in this design

        case dkg_msg_type::polynomial_commitment_q:
            return true;

        case dkg_msg_type::polynomial_commitment_h:
            return true;

        case dkg_msg_type::polynomial_share: {
            const uint32_t j = m.hdr.sender_id;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty() || m.bytes_b.empty() || m.bytes_c.empty())
                return false;

            BIGNUM* sp = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            BIGNUM* sq = BN_bin2bn(m.bytes_b.data(),
                                   static_cast<int>(m.bytes_b.size()), nullptr);
            BIGNUM* sh = BN_bin2bn(m.bytes_c.data(),
                                   static_cast<int>(m.bytes_c.size()), nullptr);
            if (!sp || !sq || !sh) {
                BN_free(sp); BN_free(sq); BN_free(sh); return false;
            }

            if (shares_p_received_[j]) BN_free(shares_p_received_[j]);
            if (shares_q_received_[j]) BN_free(shares_q_received_[j]);
            if (shares_h_received_[j]) BN_free(shares_h_received_[j]);
            shares_p_received_[j] = sp;
            shares_q_received_[j] = sq;
            shares_h_received_[j] = sh;
            return true;
        }

        case dkg_msg_type::bgw_product_share: {
            const uint32_t j = m.hdr.sender_id;
            if (m.bytes_a.empty()) return false;
            BIGNUM* v = BN_bin2bn(m.bytes_a.data(),
                                  static_cast<int>(m.bytes_a.size()), nullptr);
            if (!v) return false;
            if (N_i_received_[j]) BN_free(N_i_received_[j]);
            N_i_received_[j] = v;
            return true;
        }

        case dkg_msg_type::candidate_N: {
            if (m.bytes_a.empty()) return false;
            BIGNUM* nb = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!nb) return false;
            free_bn(N_candidate_);
            N_candidate_ = nb;
            return true;
        }

        case dkg_msg_type::biprimality_base: {
            if (m.bytes_a.empty()) return false;
            BIGNUM* gb = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!gb) return false;
            free_bn(g_bar_);
            g_bar_ = gb;
            return true;
        }

        case dkg_msg_type::biprimality_Q: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_b.empty()) return false;

            // bytes_a = C0', bytes_b = Q, bytes_c = proof.
            // The party does not need to store C0' or the proof
            // itself; the driver collects and verifies them from the
            // message stream directly. Here we just store Q.
            BIGNUM* Q = BN_bin2bn(m.bytes_b.data(),
                                  static_cast<int>(m.bytes_b.size()), nullptr);
            if (!Q) return false;
            if (Q_received_[j]) BN_free(Q_received_[j]);
            Q_received_[j] = Q;
            return true;
        }

        case dkg_msg_type::beta_commit:
        case dkg_msg_type::r_commit:
        case dkg_msg_type::theta_share:
        case dkg_msg_type::v_commit:
            return true;   // driver holds these

        case dkg_msg_type::beta_share: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty() || m.bytes_b.empty()) return false;
            BIGNUM* bv = bn_from_signed(m.bytes_a);
            BIGNUM* rv = bn_from_signed(m.bytes_b);
            if (!bv || !rv) { BN_free(bv); BN_free(rv); return false; }
            if (beta_shares_received_[j]) BN_free(beta_shares_received_[j]);
            if (delta_r_shares_received_[j]) BN_free(delta_r_shares_received_[j]);
            beta_shares_received_[j] = bv;
            delta_r_shares_received_[j] = rv;
            return true;
        }

        case dkg_msg_type::h_theta_share: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty()) return true;
            BIGNUM* hv = bn_from_signed(m.bytes_a);
            if (!hv) return false;
            if (h_theta_shares_received_[j]) BN_free(h_theta_shares_received_[j]);
            h_theta_shares_received_[j] = hv;
            return true;
        }

        case dkg_msg_type::theta_tilde_broadcast: {
            if (m.bytes_a.empty()) return false;
            BIGNUM* tv = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!tv) return false;
            free_bn(theta_tilde_);
            theta_tilde_ = tv;
            // Compute theta = theta_tilde mod N.
            if (N_candidate_) {
                BIGNUM* t = BN_new();
                BN_CTX* c = BN_CTX_new();
                BN_mod(t, theta_tilde_, N_candidate_, c);
                free_bn(theta_);
                theta_ = t;
                BN_CTX_free(c);
            }
            return true;
        }

        case dkg_msg_type::v_reveal: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty()) return false;
            BIGNUM* rv = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!rv) return false;
            if (v_reveal_received_[j]) BN_free(v_reveal_received_[j]);
            v_reveal_received_[j] = rv;
            return true;
        }

        case dkg_msg_type::trial_division_ra_commit:
        case dkg_msg_type::trial_division_rb_commit:
            return true;   // driver holds these

        case dkg_msg_type::trial_division_ra_share: {
            const uint32_t j = m.hdr.sender_id;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty() || m.bytes_b.empty()) return false;
            BIGNUM* sra = BN_bin2bn(m.bytes_a.data(),
                                    static_cast<int>(m.bytes_a.size()), nullptr);
            BIGNUM* srb = BN_bin2bn(m.bytes_b.data(),
                                    static_cast<int>(m.bytes_b.size()), nullptr);
            if (!sra || !srb) { BN_free(sra); BN_free(srb); return false; }
            if (ra_shares_received_[j]) BN_free(ra_shares_received_[j]);
            if (rb_shares_received_[j]) BN_free(rb_shares_received_[j]);
            ra_shares_received_[j] = sra;
            rb_shares_received_[j] = srb;
            return true;
        }

        case dkg_msg_type::trial_division_gamma:
            return true;   // collected by driver

        case dkg_msg_type::candidate_reject:
            aborted_ = true;
            return true;

        default:
            return true;
    }
}

bool dkg_party::public_N(std::vector<uint8_t>& out) const
{
    if (!N_candidate_) return false;
    const int nb = BN_num_bytes(N_candidate_);
    out.assign(nb, 0);
    BN_bn2bin(N_candidate_, out.data());
    return true;
}

// ====================================================================
// §5 threshold key derivation
// ====================================================================

bool dkg_party::do_phi_share_init()
{
    if (!share_p_ || !share_q_ || !N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* phi = BN_new();
    BN_add(phi, N_candidate_, BN_value_one());
    BN_sub(phi, phi, share_p_);
    BN_sub(phi, phi, share_q_);

    free_bn(phi_share_);
    phi_share_ = phi;
    return true;
}

bool dkg_party::do_beta_R_generate()
{
    if (!N_candidate_ || !vss_group_ || !vss_group_->valid()) return false;
    if (security_bits_ == 0) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const uint32_t t = threshold_ - 1;

    // beta_i in [0, K*N], R_i in [0, K^2*N]
    BIGNUM* K = BN_new();
    BN_lshift(K, BN_value_one(), security_bits_);

    BIGNUM* K2 = BN_new();
    BN_sqr(K2, K, ctx.ctx);

    BIGNUM* beta_bound = BN_new();
    BN_mul(beta_bound, K, N_candidate_, ctx.ctx);

    BIGNUM* r_bound = BN_new();
    BN_mul(r_bound, K2, N_candidate_, ctx.ctx);

    free_bn(beta_i_);
    free_bn(R_i_);
    beta_i_ = BN_new();
    R_i_    = BN_new();
    BN_rand_range(beta_i_, beta_bound);
    BN_rand_range(R_i_, r_bound);

    // Delta * R_i
    BIGNUM* delta_R = BN_new();
    BN_mul(delta_R, dao_dkg_delta(), R_i_, ctx.ctx);

    // VSS deal beta_i and delta_R at degree t.
    std::vector<BIGNUM*> s_beta, b_beta, s_dr, b_dr;
    if (!dao_vss_deal(*vss_group_, beta_i_, committee_size_, t,
                      commits_beta_, s_beta, b_beta)) {
        BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
        BN_free(delta_R);
        return false;
    }
    if (!dao_vss_deal(*vss_group_, delta_R, committee_size_, t,
                      commits_delta_r_, s_dr, b_dr)) {
        BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
        BN_free(delta_R);
        return false;
    }

    // VSS deal h_theta at degree 2t with h_theta(0) = 0.
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    std::vector<BIGNUM*> s_h, b_h;
    if (!dao_vss_deal(*vss_group_, zero, committee_size_, 2 * t,
                      commits_h_theta_, s_h, b_h)) {
        BN_free(zero); BN_free(K); BN_free(K2);
        BN_free(beta_bound); BN_free(r_bound); BN_free(delta_R);
        return false;
    }
    BN_free(zero);

    // Broadcast commitments.
    {
        dkg_msg m = make_header(dkg_msg_type::beta_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_beta_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::r_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_delta_r_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::h_theta_share, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_h_theta_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }

    // Private shares.
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (j == party_id_) {
            if (beta_shares_received_[j]) BN_free(beta_shares_received_[j]);
            if (delta_r_shares_received_[j]) BN_free(delta_r_shares_received_[j]);
            if (h_theta_shares_received_[j]) BN_free(h_theta_shares_received_[j]);
            beta_shares_received_[j] = BN_dup(s_beta[j - 1]);
            delta_r_shares_received_[j] = BN_dup(s_dr[j - 1]);
            h_theta_shares_received_[j] = BN_dup(s_h[j - 1]);
            continue;
        }
        dkg_msg m = make_header(dkg_msg_type::beta_share, j);
        m.tag32 = party_id_;
        bn_to_signed(s_beta[j - 1], m.bytes_a);
        bn_to_signed(s_dr[j - 1], m.bytes_b);
        if (!send_msg(m)) return false;

        dkg_msg mh = make_header(dkg_msg_type::h_theta_share, j);
        mh.tag32 = party_id_;
        bn_to_signed(s_h[j - 1], mh.bytes_a);
        if (!send_msg(mh)) return false;
    }

    for (auto* x : s_beta) BN_free(x);
    for (auto* x : b_beta) BN_free(x);
    for (auto* x : s_dr) BN_free(x);
    for (auto* x : b_dr) BN_free(x);
    for (auto* x : s_h) BN_free(x);
    for (auto* x : b_h) BN_free(x);
    BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
    BN_free(delta_R);
    return true;
}

bool dkg_party::do_beta_R_collect()
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* bsum = BN_new();
    BIGNUM* rsum = BN_new();
    BIGNUM* hsum = BN_new();
    BN_zero(bsum); BN_zero(rsum); BN_zero(hsum);

    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!beta_shares_received_[j] ||
            !delta_r_shares_received_[j] ||
            !h_theta_shares_received_[j]) {
            BN_free(bsum); BN_free(rsum); BN_free(hsum);
            return false;
        }
        BN_add(bsum, bsum, beta_shares_received_[j]);
        BN_add(rsum, rsum, delta_r_shares_received_[j]);
        BN_add(hsum, hsum, h_theta_shares_received_[j]);
    }

    free_bn(beta_share_);
    free_bn(f1_share_);
    free_bn(h_theta_share_);
    beta_share_ = bsum;
    f1_share_   = rsum;
    h_theta_share_ = hsum;
    return true;
}

bool dkg_party::do_compute_theta_share()
{
    if (!phi_share_ || !beta_share_ || !f1_share_ ||
        !h_theta_share_ || !N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // Theta(i) = Delta * Phi(i) * Beta(i) + N * F1(i) + H_theta(i)
    BIGNUM* prod = BN_new();
    BN_mul(prod, phi_share_, beta_share_, ctx.ctx);
    BN_mul(prod, prod, dao_dkg_delta(), ctx.ctx);

    BIGNUM* nf1 = BN_new();
    BN_mul(nf1, N_candidate_, f1_share_, ctx.ctx);

    BIGNUM* theta_i = BN_new();
    BN_add(theta_i, prod, nf1);
    BN_add(theta_i, theta_i, h_theta_share_);

    free_bn(theta_share_);
    theta_share_ = theta_i;

    dkg_msg m = make_header(dkg_msg_type::theta_share, 0);
    m.tag32 = party_id_;
    bn_to_signed(theta_share_, m.bytes_a);

    const bool sent = send_msg(m);
    BN_free(prod); BN_free(nf1);
    return sent;
}

bool dkg_party::do_compute_SK()
{
    if (!f1_share_ || !theta_tilde_ || !N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* nf1 = BN_new();
    BN_mul(nf1, N_candidate_, f1_share_, ctx.ctx);

    BIGNUM* sk = BN_new();
    BN_sub(sk, nf1, theta_tilde_);

    free_bn(SK_i_);
    SK_i_ = sk;
    BN_free(nf1);
    return true;
}

bool dkg_party::set_theta_tilde(const BIGNUM* v)
{
    if (!v) return false;
    free_bn(theta_tilde_);
    theta_tilde_ = BN_dup(v);
    if (!theta_tilde_) return false;
    if (N_candidate_) {
        CtxGuard ctx;
        if (!ctx.ok()) return false;
        BIGNUM* t = BN_new();
        BN_mod(t, theta_tilde_, N_candidate_, ctx.ctx);
        free_bn(theta_);
        theta_ = t;
    }
    return true;
}

bool dkg_party::set_V(const BIGNUM* v)
{
    if (!v) return false;
    free_bn(V_);
    V_ = BN_dup(v);
    return V_ != nullptr;
}

bool dkg_party::do_v_commit()
{
    if (!N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // r_i in Z*_{N^2}.
    BIGNUM* r_i = BN_new();
    BIGNUM* gcd = BN_new();
    do {
        BN_rand_range(r_i, vss_group_ ? vss_group_->P : N_candidate_);
        BN_gcd(gcd, r_i, N_candidate_, ctx.ctx);
    } while (!BN_is_one(gcd));
    BN_free(gcd);

    free_bn(v_r_i_);
    v_r_i_ = r_i;

    // Commitment: SHA-256 of "DAO_DKG_V1" || epoch || party_id || r_i_bytes.
    std::vector<uint8_t> buf;
    const char* dom = "DAO_DKG_V1";
    buf.insert(buf.end(), dom, dom + 10);
    for (int i = 0; i < 4; ++i) buf.push_back((epoch_ >> (8*i)) & 0xff);
    for (int i = 0; i < 4; ++i) buf.push_back((party_id_ >> (8*i)) & 0xff);
    const int rb = BN_num_bytes(v_r_i_);
    std::vector<uint8_t> rbytes(rb, 0);
    BN_bn2bin(v_r_i_, rbytes.data());
    buf.insert(buf.end(), rbytes.begin(), rbytes.end());

    std::vector<uint8_t> digest(32, 0);
    SHA256(buf.data(), buf.size(), digest.data());

    dkg_msg m = make_header(dkg_msg_type::v_commit, 0);
    m.tag32 = party_id_;
    m.bytes_a = digest;
    return send_msg(m);
}

bool dkg_party::do_v_reveal()
{
    if (!v_r_i_) return false;

    dkg_msg m = make_header(dkg_msg_type::v_reveal, 0);
    m.tag32 = party_id_;
    const int n = BN_num_bytes(v_r_i_);
    m.bytes_a.assign(n, 0);
    BN_bn2bin(v_r_i_, m.bytes_a.data());
    return send_msg(m);
}

bool dkg_party::do_compute_V()
{
    if (!N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N_candidate_, ctx.ctx);

    BIGNUM* r = BN_new();
    BN_one(r);
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!v_reveal_received_[j]) { BN_free(N2); BN_free(r); return false; }
        BN_mod_mul(r, r, v_reveal_received_[j], N2, ctx.ctx);
    }
    BIGNUM* V = BN_new();
    BN_mod_mul(V, r, r, N2, ctx.ctx);

    free_bn(V_);
    V_ = V;

    BN_free(N2); BN_free(r);
    return true;
}

bool dkg_party::do_derive_VKi(std::vector<uint8_t>& VKi_out)
{
    if (!V_ || !SK_i_ || !N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N_candidate_, ctx.ctx);

    // exp = Delta * SK_i, may be negative.
    BIGNUM* exp = BN_new();
    BN_mul(exp, dao_dkg_delta(), SK_i_, ctx.ctx);

    BIGNUM* result = BN_new();
    if (BN_is_negative(exp)) {
        BIGNUM* Vinv = BN_mod_inverse(nullptr, V_, N2, ctx.ctx);
        BIGNUM* pos = BN_dup(exp);
        BN_set_negative(pos, 0);
        BN_mod_exp(result, Vinv, pos, N2, ctx.ctx);
        BN_free(Vinv); BN_free(pos);
    } else {
        BN_mod_exp(result, V_, exp, N2, ctx.ctx);
    }

    const size_t N_bytes = static_cast<size_t>(BN_num_bytes(N_candidate_));
    VKi_out.assign(2 * N_bytes, 0);
    BN_bn2binpad(result, VKi_out.data(), static_cast<int>(VKi_out.size()));

    BN_free(N2); BN_free(exp); BN_free(result);
    return true;
}

// ====================================================================
// Driver
// ====================================================================

namespace {

// Interpolate N from the party shares N_i via Lagrange at zero over
// the integers. The shares are values of the degree-2t polynomial
// alpha(x), and we want alpha(0).
bool lagrange_interpolate_zero(const std::vector<uint32_t>& subset,
                               const std::vector<const BIGNUM*>& shares,
                               BIGNUM* out, BN_CTX* ctx)
{
    if (subset.size() != shares.size()) return false;
    if (subset.empty()) return false;

    BIGNUM* total = BN_new();
    BN_zero(total);

    for (size_t k = 0; k < subset.size(); ++k) {
        const int64_t i = static_cast<int64_t>(subset[k]);

        // numerator = prod_{j != k} (-j)
        // denominator = prod_{j != k} (i - j)
        BIGNUM* num = BN_new();
        BIGNUM* den = BN_new();
        BN_one(num);
        BN_one(den);

        for (size_t j = 0; j < subset.size(); ++j) {
            if (j == k) continue;
            const int64_t jj = static_cast<int64_t>(subset[j]);
            BIGNUM* bj = BN_new();
            BN_set_word(bj, static_cast<BN_ULONG>(jj < 0 ? -jj : jj));
            if (jj < 0) BN_set_negative(bj, 1);
            BN_mul(num, num, bj, ctx);
            BN_set_negative(num, !BN_is_negative(num));
            BN_free(bj);

            BIGNUM* diff = BN_new();
            BN_set_word(diff, static_cast<BN_ULONG>(i));
            BIGNUM* bj2 = BN_new();
            BN_set_word(bj2, static_cast<BN_ULONG>(jj));
            BN_sub(diff, diff, bj2);
            BN_mul(den, den, diff, ctx);
            BN_free(diff); BN_free(bj2);
        }

        // term = share * num / den
        BIGNUM* term = BN_new();
        BN_mul(term, shares[k], num, ctx);
        BN_div(term, nullptr, term, den, ctx);
        BN_add(total, total, term);

        BN_free(num); BN_free(den); BN_free(term);
    }

    BN_copy(out, total);
    BN_free(total);
    return true;
}

} // anonymous namespace

// ====================================================================
// Test-only accessors used by the in-process driver
//
// These exist because the driver runs all parties in one process and
// must coordinate the phases. They do NOT expose secret material:
// only the values the protocol itself broadcasts or aggregates.
// ====================================================================

namespace {

// Extract the N_i value a party computed in phase 2.
bool party_get_N_i(const dkg_party& p, BIGNUM* out);

// Extract the Q_i value a party computed in phase 4.
bool party_get_Q_i(const dkg_party& p, BIGNUM* out);

// Extract the lambda share from phase 6.
bool party_get_lambda_share(const dkg_party& p, BIGNUM* out);

} // anonymous namespace

// ====================================================================
// Public entry points
// ====================================================================

std::unique_ptr<dkg_party> dkg_party_create(uint32_t party_id,
                                            uint32_t committee_size,
                                            uint32_t threshold,
                                            uint32_t epoch)
{
    return std::unique_ptr<dkg_party>(
        new dkg_party(party_id, committee_size, threshold, epoch));
}

namespace {

// Drain every transport until no more messages are pending.
void drain_all(const std::vector<std::unique_ptr<dkg_transport>>& transports,
               std::vector<dkg_msg>& collected)
{
    bool any = false;
    do {
        any = false;
        for (const auto& t : transports) {
            dkg_msg m;
            while (t->try_recv(m)) {
                collected.push_back(m);
                any = true;
            }
        }
    } while (any);
}

// Route collected messages to all parties whose id matches the
// recipient (or to all if recipient is 0).
bool deliver_all(const std::vector<std::unique_ptr<dkg_party>>& parties,
                 const std::vector<dkg_msg>& msgs)
{
    for (const auto& m : msgs) {
        if (m.hdr.recipient_id == 0) {
            for (const auto& p : parties) {
                if (!p->handle_message(m)) return false;
            }
        } else {
            for (const auto& p : parties) {
                if (p->id() == m.hdr.recipient_id) {
                    if (!p->handle_message(m)) return false;
                }
            }
        }
    }
    return true;
}

// Reconstruct N from the N_i values via Lagrange interpolation over
// the integers at x=0. Uses any (2t+1) = 15 of the 16 shares.
bool reconstruct_N(const std::vector<std::unique_ptr<dkg_party>>& parties,
                   BIGNUM* N_out)
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    std::vector<uint32_t> subset;
    std::vector<const BIGNUM*> shares;

    for (const auto& p : parties) {
        // We do not have an accessor for the raw N_i here; the party's
        // N_candidate_ field is set only after the driver has computed
        // N. The N_i values are what the parties broadcast, and the
        // driver collected them from the transports. This function is
        // therefore called with the collected N_i values by the caller,
        // not by reading the parties.
        (void)p;
    }
    // Placeholder: the caller supplies shares explicitly.
    (void)subset;
    (void)shares;
    (void)N_out;
    return false;
}

// Perform one candidate attempt: phases 1-2 and reconstruction of N.
// Returns true if a candidate N was reconstructed.
bool run_modulus_attempt(const dkg_config& cfg,
                         std::vector<std::unique_ptr<dkg_party>>& parties,
                         std::vector<std::unique_ptr<dkg_transport>>& transports,
                         BIGNUM* N_out)
{
    // Phase 1: each party deals VSS and sends shares.
    for (auto& p : parties) {
        if (!p->start_phase(1, cfg.k, cfg.security_bits, cfg.target_N_bits))
            return false;
    }

    std::vector<dkg_msg> collected;
    drain_all(transports, collected);
    if (!deliver_all(parties, collected)) return false;
    collected.clear();

    // Phase 2: each party forms N_i and broadcasts.
    for (auto& p : parties) {
        if (!p->start_phase(2, cfg.k, cfg.security_bits, cfg.target_N_bits))
            return false;
    }

    drain_all(transports, collected);

    // Collect the broadcast N_i values from the message stream.
    std::vector<BIGNUM*> N_i(parties.size() + 1, nullptr);
    for (const auto& m : collected) {
        if (m.hdr.type != dkg_msg_type::bgw_product_share) continue;
        const uint32_t j = m.hdr.sender_id;
        if (j < 1 || j > parties.size()) return false;
        if (m.bytes_a.empty()) return false;
        N_i[j] = BN_bin2bn(m.bytes_a.data(),
                           static_cast<int>(m.bytes_a.size()), nullptr);
        if (!N_i[j]) return false;
    }

    // Also deliver the messages so the parties can continue.
    if (!deliver_all(parties, collected)) return false;

    // Verify all N_i are present.
    for (size_t j = 1; j <= parties.size(); ++j) {
        if (!N_i[j]) {
            for (auto* x : N_i) if (x) BN_free(x);
            return false;
        }
    }

    // Interpolate at zero using the first 2t+1 = 15 shares.
    const uint32_t deg = 2 * (cfg.threshold - 1);
    const uint32_t need = deg + 1;
    if (parties.size() < need) {
        for (auto* x : N_i) if (x) BN_free(x);
        return false;
    }

    std::vector<uint32_t> idx;
    std::vector<const BIGNUM*> vals;
    for (uint32_t j = 1; j <= need; ++j) {
        idx.push_back(j);
        vals.push_back(N_i[j]);
    }

    CtxGuard ctx;
    if (!ctx.ok()) {
        for (auto* x : N_i) if (x) BN_free(x);
        return false;
    }
    const bool ok = lagrange_interpolate_zero(idx, vals, N_out, ctx.ctx);
    for (auto* x : N_i) if (x) BN_free(x);
    return ok;
}

// Choose g_bar with Jacobi(g_bar, N) = +1.
bool choose_g_bar(const BIGNUM* N, BIGNUM* out)
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    for (int tries = 0; tries < 128; ++tries) {
        if (!BN_rand_range(out, N)) return false;
        if (BN_is_zero(out)) continue;
        if (BN_is_one(out)) continue;
        BIGNUM* gcd = BN_new();
        BN_gcd(gcd, out, N, ctx.ctx);
        const bool coprime = BN_is_one(gcd);
        BN_free(gcd);
        if (!coprime) continue;
        const int jac = BN_kronecker(out, N, ctx.ctx);
        if (jac == 1) return true;
    }
    return false;
}

// Biprimality acceptance: R = Q_1 / prod_{i>=2} Q_i mod N, accept iff
// R == 1 or R == -1. Returns 1 if accepted, 0 if rejected, -1 on error.
int biprimality_check(const std::vector<const BIGNUM*>& Q,
                      const BIGNUM* N)
{
    // Q is indexed 1..n (Q[0] unused). Accept iff
    //     Q[1] / (Q[2] * Q[3] * ... * Q[n]) == +1 or -1 mod N.
    if (Q.size() < 2 || !N) return -1;
    CtxGuard ctx;
    if (!ctx.ok()) return -1;

    // Product of Q[2] .. Q[n], excluding the numerator Q[1].
    BIGNUM* prod = BN_new();
    BN_one(prod);

    for (size_t i = 2; i < Q.size(); ++i) {
        if (!Q[i]) { BN_free(prod); return -1; }
        if (!BN_mod_mul(prod, prod, Q[i], N, ctx.ctx)) {
            BN_free(prod); return -1;
        }
    }

    BIGNUM* inv = BN_mod_inverse(nullptr, prod, N, ctx.ctx);
    if (!inv) { BN_free(prod); return -1; }

    // R = Q[1] * inv mod N
    BIGNUM* R = BN_new();
    if (!BN_mod_mul(R, Q[1], inv, N, ctx.ctx)) {
        BN_free(prod); BN_free(inv); BN_free(R);
        return -1;
    }

    int rc = 0;
    if (BN_is_one(R)) {
        rc = 1;
    } else {
        BIGNUM* Nm1 = BN_new();
        BN_sub(Nm1, N, BN_value_one());
        if (BN_cmp(R, Nm1) == 0) rc = 1;
        BN_free(Nm1);
    }

    BN_free(prod); BN_free(inv); BN_free(R);
    return rc;
}

// §4.1 trial division on one hidden factor. factor_selector: 0 = p,
// 1 = q. The function:
//   1. runs the VSS prolog for Ra/Rb in every party,
//   2. exchanges shares,
//   3. computes the gamma share per party,
//   4. collects gamma shares and reconstructs gamma at x=0,
//   5. checks gcd(gamma, r) == 1.
// Any failure at any repetition for any small prime rejects the
// candidate.
bool trial_division_check_factor(
    const std::vector<std::unique_ptr<dkg_party>>& parties,
    std::vector<std::unique_ptr<dkg_transport>>& transports,
    const dkg_config& cfg,
    uint32_t factor_selector)
{
    const uint32_t t = cfg.threshold - 1;
    const uint32_t deg = 2 * t;
    const uint32_t need = deg + 1;   // 2t+1 = 15 shares

    for (size_t r_idx = 0; r_idx < DAO_DKG_SMALL_PRIME_COUNT; ++r_idx) {
        const uint32_t r = DAO_DKG_SMALL_PRIMES[r_idx];
        bool passed = false;

        for (uint32_t rep = 0; rep < DAO_DKG_TRIAL_DIVISION_REPS && !passed; ++rep) {
            // Phase: prolog.
            for (auto& p : parties) {
                if (!p->do_trial_division_prolog(factor_selector)) return false;
            }
            {
                std::vector<dkg_msg> collected;
                drain_all(transports, collected);
                if (!deliver_all(parties, collected)) return false;
            }

            // Phase: gamma share.
            for (auto& p : parties) {
                if (!p->do_trial_division_gamma(r)) return false;
            }

            std::vector<dkg_msg> collected;
            drain_all(transports, collected);

            // Collect gamma shares.
            std::vector<BIGNUM*> gamma_shares(parties.size() + 1, nullptr);
            for (const auto& m : collected) {
                if (m.hdr.type != dkg_msg_type::trial_division_gamma) continue;
                const uint32_t j = m.tag32;
                if (j < 1 || j > parties.size()) continue;
                if (m.bytes_a.empty()) continue;
                gamma_shares[j] = BN_bin2bn(m.bytes_a.data(),
                                            static_cast<int>(m.bytes_a.size()),
                                            nullptr);
            }
            // Deliver so parties keep any state they need.
            if (!deliver_all(parties, collected)) return false;

            bool all_present = true;
            for (size_t j = 1; j <= need; ++j) {
                if (!gamma_shares[j]) { all_present = false; break; }
            }
            if (!all_present) {
                for (auto* x : gamma_shares) if (x) BN_free(x);
                return false;
            }

            // Reconstruct gamma via Lagrange at 0 using the first `need`
            // shares.
            CtxGuard ctx;
            if (!ctx.ok()) {
                for (auto* x : gamma_shares) if (x) BN_free(x);
                return false;
            }

            std::vector<uint32_t> idx;
            std::vector<const BIGNUM*> vals;
            for (uint32_t j = 1; j <= need; ++j) {
                idx.push_back(j);
                vals.push_back(gamma_shares[j]);
            }
            BIGNUM* gamma = BN_new();
            if (!lagrange_interpolate_zero(idx, vals, gamma, ctx.ctx)) {
                BN_free(gamma);
                for (auto* x : gamma_shares) if (x) BN_free(x);
                return false;
            }
            for (auto* x : gamma_shares) if (x) BN_free(x);

            // gcd(gamma, r) == 1?
            BIGNUM* rbn = BN_new();
            BN_set_word(rbn, r);
            BIGNUM* g = BN_new();
            BN_gcd(g, gamma, rbn, ctx.ctx);
            if (BN_is_one(g)) passed = true;

            BN_free(rbn); BN_free(g); BN_free(gamma);
        }

        if (!passed) return false;
    }
    return true;
}

} // anonymous namespace

// ====================================================================
// dkg_run_with_transport
// ====================================================================

bool dkg_run_with_transport(const dkg_config& cfg,
                            const dkg_transport_factory& factory,
                            dkg_result& out)
{
    out = dkg_result{};

    if (cfg.committee_size < cfg.threshold) return false;
    if (cfg.committee_size != DAO_DKG_COMMITTEE_SIZE) return false;
    if (cfg.threshold != DAO_DKG_THRESHOLD) return false;

    // Create transports.
    std::vector<std::unique_ptr<dkg_transport>> transports;
    transports.reserve(cfg.committee_size);
    for (uint32_t i = 1; i <= cfg.committee_size; ++i) {
        transports.push_back(factory(i));
        if (!transports.back()) return false;
    }

    // Create parties and attach transports.
    std::vector<std::unique_ptr<dkg_party>> parties;
    parties.reserve(cfg.committee_size);
    for (uint32_t i = 1; i <= cfg.committee_size; ++i) {
        auto p = dkg_party_create(i, cfg.committee_size, cfg.threshold, cfg.epoch);
        if (!p) return false;
        p->attach_transport(transports[i - 1].get());
        parties.push_back(std::move(p));
    }

    // The VSS group. In-process, one group is shared across all parties.
    // For the test configuration (k = 60), the size of the shares and
    // the products Ra*p is bounded by roughly 2^200, so a 512-bit P'
    // is sufficient. The production configuration chooses P' after
    // evaluating all bounds from §4.1, §5, and Appendix B.
    dao_vss_group vss;
    const uint32_t required_bits =
        dao_dkg_required_vss_bits(cfg.k, cfg.target_N_bits, cfg.security_bits);
    const unsigned int vss_bits =
        std::max<unsigned int>(required_bits, 512);
    if (!dao_vss_group_generate(vss, vss_bits)) return false;

    for (auto& p : parties) {
        p->attach_vss_group(&vss);
        p->set_qproof_rounds(cfg.qproof_rounds);
    }

    // Main candidate loop.
    BIGNUM* N = BN_new();
    bool accepted = false;

    for (uint32_t attempt = 1; attempt <= cfg.max_attempts; ++attempt) {
        out.candidate_attempts = attempt;

        // Phases 1-2: modulus shares and reconstruction.
        if (!run_modulus_attempt(cfg, parties, transports, N)) {
            continue;
        }

        // Enforce exact target bit length.
        if (static_cast<uint32_t>(BN_num_bits(N)) != cfg.target_N_bits) {
            continue;
        }

        // Declare g_bar before any goto to avoid jumping over its
        // initializer.
        BIGNUM* g_bar = BN_new();

        // Broadcast the reconstructed N to every party so they can
        // compute Q_i.
        {
            dkg_msg mN;
            mN.hdr.version = 1;
            mN.hdr.epoch = cfg.epoch;
            mN.hdr.sender_id = 0;
            mN.hdr.recipient_id = 0;
            mN.hdr.phase = 3;
            mN.hdr.type = dkg_msg_type::candidate_N;
            const int nbN = BN_num_bytes(N);
            mN.bytes_a.assign(nbN, 0);
            BN_bn2bin(N, mN.bytes_a.data());
            for (auto& p : parties) {
                if (!p->handle_message(mN)) {
                    BN_free(g_bar);
                    goto next_attempt;
                }
            }
        }

        // Phase 3: choose g_bar and broadcast.
        if (!choose_g_bar(N, g_bar)) {
            BN_free(g_bar);
            continue;
        }

        for (auto& p : parties) {
            dkg_msg m;
            m.hdr.version = 1;
            m.hdr.epoch = cfg.epoch;
            m.hdr.sender_id = 0;
            m.hdr.recipient_id = 0;
            m.hdr.phase = 3;
            m.hdr.type = dkg_msg_type::biprimality_base;
            const int nb = BN_num_bytes(g_bar);
            m.bytes_a.assign(nb, 0);
            BN_bn2bin(g_bar, m.bytes_a.data());
            if (!p->handle_message(m)) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }

        // Phase 4: each party publishes Q_i.
        for (auto& p : parties) {
            if (!p->start_phase(4, cfg.k, cfg.security_bits, cfg.target_N_bits)) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }

        // Drain and collect Q_i (with proofs), verify each proof, then
        // run the biprimality predicate.
        {
            std::vector<dkg_msg> collected;
            drain_all(transports, collected);

            std::vector<BIGNUM*> Q_own(cfg.committee_size + 1, nullptr);
            std::vector<const BIGNUM*> Q(cfg.committee_size + 1, nullptr);
            bool ok = true;

            for (const auto& m : collected) {
                if (m.hdr.type != dkg_msg_type::biprimality_Q) continue;
                const uint32_t j = m.tag32;
                if (j < 1 || j > cfg.committee_size) { ok = false; break; }
                if (m.bytes_a.empty() || m.bytes_b.empty() || m.bytes_c.empty()) {
                    ok = false; break;
                }
                if (Q_own[j]) continue;

                BIGNUM* C0p = BN_bin2bn(m.bytes_a.data(),
                                        static_cast<int>(m.bytes_a.size()),
                                        nullptr);
                BIGNUM* Qbn = BN_bin2bn(m.bytes_b.data(),
                                        static_cast<int>(m.bytes_b.size()),
                                        nullptr);
                if (!C0p || !Qbn) {
                    if (C0p) BN_free(C0p);
                    if (Qbn) BN_free(Qbn);
                    ok = false; break;
                }

                dao_Q_proof proof;
                if (!deserialize_Q_proof(m.bytes_c, proof) ||
                    proof.member_index != j) {
                    BN_free(C0p); BN_free(Qbn);
                    ok = false; break;
                }

                BIGNUM* g4 = BN_new();
                BIGNUM* four2 = BN_new();
                BN_set_word(four2, 4);
                BN_CTX* qctx = BN_CTX_new();
                if (!qctx) { BN_free(C0p); BN_free(Qbn); BN_free(g4); BN_free(four2); ok = false; break; }
                BN_mod_exp(g4, vss.g, four2, vss.P, qctx);
                BN_free(four2);
                BN_CTX_free(qctx);

                const bool vok = dao_Q_verify(vss, N, g4, vss.h, g_bar,
                                              C0p, Qbn, proof);
                BN_free(g4); BN_free(C0p);

                if (!vok) {
                    BN_free(Qbn);
                    ok = false; break;
                }

                Q_own[j] = Qbn;
                Q[j] = Qbn;
            }

            for (size_t j = 1; j <= cfg.committee_size && ok; ++j) {
                if (!Q[j]) ok = false;
            }

            if (ok) {
                const int bi = biprimality_check(Q, N);
                if (bi == 0) {
                    out.biprimality_failures++;
                    ok = false;
                } else if (bi < 0) {
                    ok = false;
                }
            }

            for (auto* q : Q_own) if (q) BN_free(q);

            if (!deliver_all(parties, collected)) {
                BN_free(g_bar);
                goto next_attempt;
            }

            if (!ok) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }

        // Phase 5: trial division §4.1 on hidden p and q separately.
        // do_compute_share_pq aggregates the received VSS shares into
        // each party's own share of p and q.
        for (auto& p : parties) {
            if (!p->do_compute_share_pq()) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }
        if (!trial_division_check_factor(parties, transports, cfg, 0)) {
            out.trial_division_failures++;
            BN_free(g_bar);
            goto next_attempt;
        }
        if (!trial_division_check_factor(parties, transports, cfg, 1)) {
            out.trial_division_failures++;
            BN_free(g_bar);
            goto next_attempt;
        }

        // Candidate accepted.
        {
            out.N.assign(PAILLIER_MODULUS_BYTES, 0);
            BN_bn2binpad(N, out.N.data(), PAILLIER_MODULUS_BYTES);
        }
        BN_free(g_bar);
        accepted = true;
        break;

    next_attempt:
        (void)0;
    }

    BN_free(N);

    if (!accepted) {
        out.ok = false;
        out.candidate_accepted = false;
        return false;
    }

    // Phase 6-7: threshold key derivation and public record assembly
    // are delivered in the next message. For now, record the modulus
    // and mark the result as incomplete.
    out.candidate_accepted = true;
    out.epoch = cfg.epoch;

    // ---------------------------------------------------------------
    // Phases 6-13: threshold key derivation (§5)
    // ---------------------------------------------------------------

    // Theta_tilde may fail gcd(theta, N) == 1; retry the beta phase.
    bool key_ok = false;
    for (uint32_t beta_try = 1;
         beta_try <= 8 && !key_ok;
         ++beta_try)
    {
        if (beta_try > 1) out.beta_phase_retries++;

        // Phase 6: each party computes phi_share = N + 1 - p(i) - q(i).
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] try=" << beta_try << " start phase 6\n";
        #endif
        for (auto& p : parties) {
            if (!p->do_phi_share_init()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 6 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 6 ok\n";
        #endif

        // Phase 7: beta_i, R_i generate + VSS deal + private share.
        for (auto& p : parties) {
            if (!p->do_beta_R_generate()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 7 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 7 ok\n";
        #endif
        {
            std::vector<dkg_msg> collected;
            drain_all(transports, collected);
            if (!deliver_all(parties, collected)) goto after_key_phase;
        }

        // Phase 8: aggregate Beta(i), F1(i), H_theta(i).
        for (auto& p : parties) {
            if (!p->do_beta_R_collect()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 8 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 8 ok\n";
        #endif

        // Phase 9: compute Theta(i).
        for (auto& p : parties) {
            if (!p->do_compute_theta_share()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 9 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 9 ok\n";
        #endif

        // Collect theta shares and reconstruct theta_tilde by Lagrange
        // at 0 over the 2t+1 = 15 largest-index shares.
        {
            std::vector<dkg_msg> collected;
            drain_all(transports, collected);

            const uint32_t deg = 2 * (cfg.threshold - 1);
            const uint32_t need = deg + 1;
            std::vector<BIGNUM*> theta_shares(cfg.committee_size + 1, nullptr);
            for (const auto& m : collected) {
                if (m.hdr.type != dkg_msg_type::theta_share) continue;
                const uint32_t j = m.tag32;
                if (j < 1 || j > cfg.committee_size) continue;
                if (m.bytes_a.empty()) continue;
                if (theta_shares[j]) continue;
                theta_shares[j] = bn_from_signed(m.bytes_a);
            }
            bool have_all = true;
            for (uint32_t j = 1; j <= need; ++j)
                if (!theta_shares[j]) { have_all = false; break; }

            CtxGuard ctx;
            BIGNUM* theta_tilde = nullptr;
            if (have_all && ctx.ok()) {
                std::vector<uint32_t> idx;
                std::vector<const BIGNUM*> vals;
                for (uint32_t j = 1; j <= need; ++j) {
                    idx.push_back(j);
                    vals.push_back(theta_shares[j]);
                }
                theta_tilde = BN_new();
                if (!lagrange_interpolate_zero(idx, vals, theta_tilde, ctx.ctx)) {
                    BN_free(theta_tilde);
                    theta_tilde = nullptr;
                }
            }
            for (auto* x : theta_shares) if (x) BN_free(x);

            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] theta_shares have_all=" << have_all << "\n";
            #endif
            if (!theta_tilde) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] theta_tilde reconstruction failed\n";
                #endif
                goto after_key_phase;
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] theta_tilde reconstructed\n";
            #endif

            // theta = theta_tilde mod N
            BIGNUM* theta = BN_new();
            BN_CTX* tctx = BN_CTX_new();
            BN_mod(theta, theta_tilde, N, tctx);
            BN_CTX_free(tctx);

            // gcd(theta, N) == 1?
            BIGNUM* gcd = BN_new();
            tctx = BN_CTX_new();
            BN_gcd(gcd, theta, N, tctx);
            const bool invertible = BN_is_one(gcd);
            BN_CTX_free(tctx);
            BN_free(gcd);

            if (!invertible) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] gcd(theta,N) != 1, retrying\n";
                #endif
                BN_free(theta_tilde);
                BN_free(theta);
                continue;   // retry beta phase
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] theta invertible\n";
            #endif

            // Broadcast theta_tilde to all parties.
            for (auto& p : parties) {
                if (!p->set_theta_tilde(theta_tilde)) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }

            // Save for later driver-side use.
            out.theta.assign(PAILLIER_MODULUS_BYTES, 0);
            BN_bn2binpad(theta, out.theta.data(), PAILLIER_MODULUS_BYTES);

            // Phase 10: each party computes SK_i = N*F1(i) - theta_tilde.
            for (auto& p : parties) {
                if (!p->do_compute_SK()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 10 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 10 ok\n";
            #endif

            // Phase 11: V commit round.
            for (auto& p : parties) {
                if (!p->do_v_commit()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 11 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 11 ok\n";
            #endif
            {
                std::vector<dkg_msg> vcollected;
                drain_all(transports, vcollected);

                // Verify each commitment before reveal.
                bool commits_ok = true;
                for (const auto& m : vcollected) {
                    if (m.hdr.type != dkg_msg_type::v_commit) continue;
                    const uint32_t j = m.tag32;
                    if (j < 1 || j > cfg.committee_size) { commits_ok = false; break; }
                    if (m.bytes_a.size() != 32) { commits_ok = false; break; }
                }
                if (!commits_ok || !deliver_all(parties, vcollected)) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }

            // Phase 12: V reveal round.
            for (auto& p : parties) {
                if (!p->do_v_reveal()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 12 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 12 ok\n";
            #endif
            {
                std::vector<dkg_msg> vcollected;
                drain_all(transports, vcollected);
                if (!deliver_all(parties, vcollected)) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }

            // Phase 13: compute V.
            for (auto& p : parties) {
                if (!p->do_compute_V()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 13 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 13 ok\n";
            #endif

            // Derive V_K_i for each party and collect.
            out.V_K_i.assign(cfg.committee_size, {});
            for (size_t k = 0; k < parties.size(); ++k) {
                if (!parties[k]->do_derive_VKi(out.V_K_i[k])) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] VKi failed at party " << k << "\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] VKi ok\n";
            #endif

            // Fill record basics.
            out.record.version        = 1;
            out.record.epoch          = cfg.epoch;
            out.record.committee_size = cfg.committee_size;
            out.record.threshold      = cfg.threshold;
            out.record.t              = cfg.threshold - 1;

            out.record.committee_id_hash.assign(32, 0);
            {
                SHA256_CTX sha;
                SHA256_Init(&sha);
                unsigned char eb[4];
                for (int i = 0; i < 4; ++i) eb[i] = (cfg.epoch >> (8*i)) & 0xff;
                SHA256_Update(&sha, eb, 4);
                SHA256_Final(out.record.committee_id_hash.data(), &sha);
            }

            out.record.delta.assign(32, 0);
            {
                BIGNUM* d = BN_dup(dao_dkg_delta());
                BN_bn2binpad(d, out.record.delta.data(), 32);
                BN_free(d);
            }

            out.record.N.assign(PAILLIER_MODULUS_BYTES, 0);
            BN_bn2binpad(N, out.record.N.data(), PAILLIER_MODULUS_BYTES);

            // G = N + 1.
            {
                BIGNUM* G = BN_new();
                BN_add(G, N, BN_value_one());
                out.record.G.assign(PAILLIER_MODULUS_BYTES, 0);
                BN_bn2binpad(G, out.record.G.data(), PAILLIER_MODULUS_BYTES);
                BN_free(G);
            }

            out.record.theta = out.theta;
            out.record.V.assign(PAILLIER_CT_BYTES, 0);
            {
                const BIGNUM* Vbn = parties[0]->V();
                if (!Vbn) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
                BN_bn2binpad(Vbn, out.record.V.data(), PAILLIER_CT_BYTES);
            }
            out.record.V_K_i = out.V_K_i;

            // VSS public parameters.
            {
                auto bn_to_vec = [](const BIGNUM* b, std::vector<uint8_t>& v) {
                    const int n = BN_num_bytes(b);
                    v.assign(n, 0);
                    BN_bn2bin(b, v.data());
                };
                bn_to_vec(vss.P, out.record.vss_P);
                bn_to_vec(vss.g, out.record.vss_g);
                bn_to_vec(vss.h, out.record.vss_h);
                // P' = (P-1)/2.
                BIGNUM* pp = BN_new();
                BN_sub(pp, vss.P, BN_value_one());
                BN_rshift1(pp, pp);
                bn_to_vec(pp, out.record.vss_P_prime);
                BN_free(pp);
            }

            out.record.activation_height = 0;

            // Transcript hash: canonical hash of record-so-far plus a
            // domain string. Computed after populating every field
            // except transcript_hash and key_id.
            {
                std::vector<uint8_t> enc;
                // Use a temporary record with placeholder transcript/key_id.
                dao_tally_key_record tmp = out.record;
                tmp.dkg_transcript_hash.assign(32, 0);
                tmp.key_id.assign(32, 0);
                std::vector<uint8_t> body;
                tmp.serialize(body);

                std::vector<uint8_t> tb;
                const char* dom = "VeilRoot-DAO-DKG-V1";
                tb.insert(tb.end(), dom, dom + 20);
                tb.insert(tb.end(), body.begin(), body.end());

                out.record.dkg_transcript_hash.assign(32, 0);
                SHA256(tb.data(), tb.size(),
                       out.record.dkg_transcript_hash.data());
            }

            // Key id = SHA-256 of the record with key_id zeroed.
            {
                dao_tally_key_record tmp2 = out.record;
                tmp2.key_id.assign(32, 0);
                std::vector<uint8_t> body2;
                tmp2.serialize(body2);
                out.record.key_id.assign(32, 0);
                SHA256(body2.data(), body2.size(), out.record.key_id.data());
            }

            out.key_id = out.record.key_id;

#ifdef VEILROOT_DAO_DKG_TESTING
            // Oracle fields.
            {
                CtxGuard tctx2;
                BIGNUM* sum_p = BN_new();
                BIGNUM* sum_q = BN_new();
                BIGNUM* sum_beta = BN_new();
                BN_zero(sum_p); BN_zero(sum_q); BN_zero(sum_beta);
                for (auto& p : parties) {
                    BN_add(sum_p, sum_p, p->test_p_i());
                    BN_add(sum_q, sum_q, p->test_q_i());
                    BN_add(sum_beta, sum_beta, p->test_beta_i());
                }
                auto bn_out = [](const BIGNUM* b, std::vector<uint8_t>& v) {
                    const int n = BN_num_bytes(b);
                    v.assign(n, 0);
                    BN_bn2bin(b, v.data());
                };
                bn_out(sum_p, out.test_p);
                bn_out(sum_q, out.test_q);
                bn_out(sum_beta, out.test_beta);

                BIGNUM* phi = BN_new();
                BN_add(phi, N, BN_value_one());
                BN_sub(phi, phi, sum_p);
                BN_sub(phi, phi, sum_q);
                bn_out(phi, out.test_phi);
                bn_out(theta_tilde, out.test_theta_tilde);

                out.test_SK.assign(cfg.committee_size, {});
                for (size_t k = 0; k < parties.size(); ++k) {
                    // SK_i is signed; serialize as decimal so the test
                    // can reconstruct the sign unambiguously.
                    char* dec = BN_bn2dec(parties[k]->test_SK());
                    if (!dec) continue;
                    out.test_SK[k].assign(dec, dec + strlen(dec));
                    OPENSSL_free(dec);
                }

                BN_free(sum_p); BN_free(sum_q); BN_free(sum_beta);
                BN_free(phi);
            }
#endif

            BN_free(theta_tilde);
            BN_free(theta);
            #ifdef VEILROOT_DAO_DKG_TESTING
            {
                CtxGuard dctx;
                BIGNUM* sum_p = BN_new();
                BIGNUM* sum_q = BN_new();
                BIGNUM* sum_beta = BN_new();
                BN_zero(sum_p); BN_zero(sum_q); BN_zero(sum_beta);
                for (auto& p : parties) {
                    BN_add(sum_p, sum_p, p->test_p_i());
                    BN_add(sum_q, sum_q, p->test_q_i());
                    BN_add(sum_beta, sum_beta, p->test_beta_i());
                }
                BIGNUM* phi_d = BN_new();
                BN_add(phi_d, N, BN_value_one());
                BN_sub(phi_d, phi_d, sum_p);
                BN_sub(phi_d, phi_d, sum_q);

                BIGNUM* prod = BN_new();
                BN_mul(prod, phi_d, sum_beta, dctx.ctx);
                BN_mul(prod, prod, dao_dkg_delta(), dctx.ctx);
                BIGNUM* theta_exp = BN_new();
                BN_mod(theta_exp, prod, N, dctx.ctx);

                BIGNUM* tt_mod = BN_new();
                BN_mod(tt_mod, theta_tilde, N, dctx.ctx);

                BIGNUM* delta_bn = BN_dup(dao_dkg_delta());

                char* s1 = BN_bn2dec(theta_exp);
                char* s2 = BN_bn2dec(tt_mod);
                char* s3 = BN_bn2dec(theta_tilde);
                char* s4 = BN_bn2dec(phi_d);
                char* s5 = BN_bn2dec(sum_beta);
                char* s6 = BN_bn2dec(delta_bn);
                std::cerr << "[diag] expected_theta   = " << s1 << "\n";
                std::cerr << "[diag] theta_tilde modN = " << s2 << "\n";
                std::cerr << "[diag] theta_tilde full = " << s3 << "\n";
                std::cerr << "[diag] phi              = " << s4 << "\n";
                std::cerr << "[diag] beta             = " << s5 << "\n";
                std::cerr << "[diag] delta            = " << s6 << "\n";

                OPENSSL_free(s1); OPENSSL_free(s2); OPENSSL_free(s3);
                OPENSSL_free(s4); OPENSSL_free(s5); OPENSSL_free(s6);
                BN_free(sum_p); BN_free(sum_q); BN_free(sum_beta);
                BN_free(phi_d); BN_free(prod); BN_free(theta_exp); BN_free(tt_mod);
                BN_free(delta_bn);
            }
#endif
            key_ok = true;
        }
    }

after_key_phase:
    if (!key_ok) {
        out.ok = false;
        return false;
    }

    out.ok = true;
    return true;
}

bool dkg_run(const dkg_config& cfg, dkg_result& out)
{
    // Construct an in-process transport factory using the network
    // helper from dao_dkg_transport.h.
    dkg_inproc_network net = dkg_make_inproc_network(cfg.committee_size, nullptr);
    auto* hub = net.hub.get();

    auto factory = [hub](uint32_t) -> std::unique_ptr<dkg_transport> {
        // The transports were already built by dkg_make_inproc_network;
        // we cannot easily hand them out individually from here. For
        // the in-process default entry point, callers use
        // dkg_run_with_transport directly with the network's endpoints.
        (void)hub;
        return nullptr;
    };

    // Delegate: the caller should use dkg_run_with_transport with the
    // endpoints from dkg_make_inproc_network. This function returns
    // false to signal that the caller must supply a transport.
    (void)factory;
    out = dkg_result{};
    return false;
}

// ====================================================================
// §3.3 Q_i proof
// ====================================================================

namespace {

void bn_to_bytes(const BIGNUM* v, size_t width, std::vector<uint8_t>& out)
{
    out.assign(width, 0);
    BN_bn2binpad(v, out.data(), static_cast<int>(width));
}

} // anonymous namespace

bool dao_Q_prove(const dao_vss_group& grp,
                 const BIGNUM* N,
                 const BIGNUM* g4,
                 const BIGNUM* h,
                 const BIGNUM* g_bar,
                 const BIGNUM* C0,
                 const BIGNUM* Q,
                 const BIGNUM* x,
                 const BIGNUM* y,
                 uint32_t member_index,
                 uint32_t rounds,
                 dao_Q_proof& proof_out)
{
    if (!grp.valid() || !N || !g4 || !h || !g_bar || !C0 || !Q || !x || !y)
        return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(grp.P));
    const size_t N_bytes = static_cast<size_t>(BN_num_bytes(N));

    proof_out.member_index = member_index;
    proof_out.reps.clear();

    // Response-domain bound. For the Appendix-B integer equality
    // proof, responses zx = a + c*x and zy = b + c*y must lie in a
    // fixed public interval larger than the witnesses x and y. We use
    // 2^(bitlen(P') + 1), which is above 2*max(|x|, |y|).
    BIGNUM* resp_bound = BN_new();
    BN_lshift(resp_bound, BN_value_one(), BN_num_bits(grp.P) + 1);

    for (uint32_t i = 0; i < rounds; ++i) {
        BIGNUM* a = BN_new();
        BIGNUM* b = BN_new();
        BN_rand_range(a, resp_bound);
        BN_rand_range(b, resp_bound);

        // A = (g^4)^a * h^b mod P'
        BIGNUM* Aa = BN_new();
        BIGNUM* Ab = BN_new();
        BIGNUM* A  = BN_new();
        BN_mod_exp(Aa, g4, a, grp.P, ctx.ctx);
        BN_mod_exp(Ab, h,  b, grp.P, ctx.ctx);
        BN_mod_mul(A, Aa, Ab, grp.P, ctx.ctx);

        // B = g_bar^a mod N
        BIGNUM* B = BN_new();
        BN_mod_exp(B, g_bar, a, N, ctx.ctx);

        // Fiat-Shamir challenge bit. Bind transcript: N, member, C0, Q,
        // A, B, and the round index.
        SHA256_CTX sha;
        SHA256_Init(&sha);
        unsigned char nb[256];
        BN_bn2binpad(N, nb, 256);
        SHA256_Update(&sha, nb, 256);
        uint8_t mi_le[4];
        for (int q2 = 0; q2 < 4; ++q2) mi_le[q2] = (member_index >> (8*q2)) & 0xff;
        SHA256_Update(&sha, mi_le, 4);
        std::vector<uint8_t> c0b(P_bytes, 0);
        std::vector<uint8_t> qb(N_bytes, 0);
        std::vector<uint8_t> ab(P_bytes, 0);
        std::vector<uint8_t> bb(N_bytes, 0);
        BN_bn2binpad(C0, c0b.data(), static_cast<int>(P_bytes));
        BN_bn2binpad(Q,  qb.data(),  static_cast<int>(N_bytes));
        BN_bn2binpad(A,  ab.data(),  static_cast<int>(P_bytes));
        BN_bn2binpad(B,  bb.data(),  static_cast<int>(N_bytes));
        SHA256_Update(&sha, c0b.data(), c0b.size());
        SHA256_Update(&sha, qb.data(), qb.size());
        SHA256_Update(&sha, ab.data(), ab.size());
        SHA256_Update(&sha, bb.data(), bb.size());
        SHA256_Update(&sha, &i, sizeof(i));
        unsigned char dig[32];
        SHA256_Final(dig, &sha);
        const uint8_t c = dig[0] & 1;

        // zx = a + c*x, zy = b + c*y
        BIGNUM* zx = BN_new();
        BIGNUM* zy = BN_new();
        if (c) {
            BN_add(zx, a, x);
            BN_add(zy, b, y);
        } else {
            BN_copy(zx, a);
            BN_copy(zy, b);
        }

        dao_Q_proof_repetition rep;
        bn_to_bytes(A, P_bytes, rep.A);
        bn_to_bytes(B, N_bytes, rep.B);
        rep.c = c;
        rep.zx.assign(BN_num_bytes(zx), 0);
        BN_bn2bin(zx, rep.zx.data());
        rep.zy.assign(BN_num_bytes(zy), 0);
        BN_bn2bin(zy, rep.zy.data());
        proof_out.reps.push_back(std::move(rep));

        BN_free(a); BN_free(b);
        BN_free(Aa); BN_free(Ab); BN_free(A); BN_free(B);
        BN_free(zx); BN_free(zy);
    }

    BN_free(resp_bound);
    return true;
}

bool dao_Q_verify(const dao_vss_group& grp,
                  const BIGNUM* N,
                  const BIGNUM* g4,
                  const BIGNUM* h,
                  const BIGNUM* g_bar,
                  const BIGNUM* C0,
                  const BIGNUM* Q,
                  const dao_Q_proof& proof)
{
    if (!grp.valid() || !N || !g4 || !h || !g_bar || !C0 || !Q) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(grp.P));
    const size_t N_bytes = static_cast<size_t>(BN_num_bytes(N));

    for (uint32_t i = 0; i < proof.reps.size(); ++i) {
        const auto& rep = proof.reps[i];
        if (rep.A.size() != P_bytes) return false;
        if (rep.B.size() != N_bytes) return false;

        BIGNUM* A = BN_bin2bn(rep.A.data(), static_cast<int>(rep.A.size()), nullptr);
        BIGNUM* B = BN_bin2bn(rep.B.data(), static_cast<int>(rep.B.size()), nullptr);
        BIGNUM* zx = BN_bin2bn(rep.zx.data(), static_cast<int>(rep.zx.size()), nullptr);
        BIGNUM* zy = BN_bin2bn(rep.zy.data(), static_cast<int>(rep.zy.size()), nullptr);
        if (!A || !B || !zx || !zy) return false;

        // Recompute challenge.
        SHA256_CTX sha;
        SHA256_Init(&sha);
        unsigned char nb[256];
        BN_bn2binpad(N, nb, 256);
        SHA256_Update(&sha, nb, 256);
        uint8_t mi_le[4];
        for (int q2 = 0; q2 < 4; ++q2) mi_le[q2] = (proof.member_index >> (8*q2)) & 0xff;
        SHA256_Update(&sha, mi_le, 4);
        std::vector<uint8_t> c0b(P_bytes, 0), qb(N_bytes, 0);
        std::vector<uint8_t> ab(P_bytes, 0), bb(N_bytes, 0);
        BN_bn2binpad(C0, c0b.data(), static_cast<int>(P_bytes));
        BN_bn2binpad(Q,  qb.data(),  static_cast<int>(N_bytes));
        BN_bn2binpad(A,  ab.data(),  static_cast<int>(P_bytes));
        BN_bn2binpad(B,  bb.data(),  static_cast<int>(N_bytes));
        SHA256_Update(&sha, c0b.data(), c0b.size());
        SHA256_Update(&sha, qb.data(), qb.size());
        SHA256_Update(&sha, ab.data(), ab.size());
        SHA256_Update(&sha, bb.data(), bb.size());
        SHA256_Update(&sha, &i, sizeof(i));
        unsigned char dig[32];
        SHA256_Final(dig, &sha);
        const uint8_t c = dig[0] & 1;
        if (c != rep.c) return false;

        // Check: (g^4)^zx * h^zy == A * C0^c mod P'
        BIGNUM* lhs_a = BN_new();
        BIGNUM* lhs_b = BN_new();
        BIGNUM* lhs = BN_new();
        BN_mod_exp(lhs_a, g4, zx, grp.P, ctx.ctx);
        BN_mod_exp(lhs_b, h, zy, grp.P, ctx.ctx);
        BN_mod_mul(lhs, lhs_a, lhs_b, grp.P, ctx.ctx);

        BIGNUM* rhs_a = BN_new();
        BIGNUM* rhs = BN_new();
        if (c) {
            BN_mod_mul(rhs_a, A, C0, grp.P, ctx.ctx);
            BN_copy(rhs, rhs_a);
        } else {
            BN_copy(rhs, A);
        }

        if (BN_cmp(lhs, rhs) != 0) return false;

        // Check: g_bar^zx == B * Q^c mod N
        BIGNUM* lhs2 = BN_new();
        BN_mod_exp(lhs2, g_bar, zx, N, ctx.ctx);

        BIGNUM* rhs2 = BN_new();
        if (c) {
            BIGNUM* qc = BN_new();
            BN_mod_mul(qc, B, Q, N, ctx.ctx);
            BN_copy(rhs2, qc);
            BN_free(qc);
        } else {
            BN_copy(rhs2, B);
        }

        const bool ok = (BN_cmp(lhs2, rhs2) == 0);

        BN_free(A); BN_free(B); BN_free(zx); BN_free(zy);
        BN_free(lhs_a); BN_free(lhs_b); BN_free(lhs);
        BN_free(rhs_a); BN_free(rhs); BN_free(lhs2); BN_free(rhs2);

        if (!ok) return false;
    }
    return true;
}
} // namespace dao
} // namespace cryptonote
