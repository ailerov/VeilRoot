// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_consistency.h"

#include <algorithm>
#include <cstring>

#include <openssl/sha.h>

#include "ringct/rctOps.h"
#include "governance/dao_paillier.h"

using namespace rct;

namespace cryptonote {
namespace dao {

namespace {

struct CtxGuard
{
    BN_CTX* ctx;
    CtxGuard() : ctx(BN_CTX_new()) {}
    ~CtxGuard() { if (ctx) BN_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
    bool ok() const { return ctx != nullptr; }
};

// Curve order ℓ (Ed25519 base point order).
static const char CURVE_ORDER_HEX[] =
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

// BIGNUM -> 32-byte little-endian curve scalar, reduced mod ℓ.
key bn_to_scalar_reduced(const BIGNUM* b, BN_CTX* ctx)
{
    BIGNUM* ell = nullptr;
    BN_hex2bn(&ell, CURVE_ORDER_HEX);
    BIGNUM* r = BN_new();
    BN_mod(r, b, ell, ctx);

    std::vector<uint8_t> be(BN_num_bytes(r));
    BN_bn2bin(r, be.data());

    key k{};
    std::memset(k.bytes, 0, 32);
    const size_t n = std::min(be.size(), static_cast<size_t>(32));
    for (size_t i = 0; i < n; ++i) {
        k.bytes[i] = be[be.size() - 1 - i];
    }
    BN_free(r); BN_free(ell);
    return k;
}

void append_le32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8*i)) & 0xff);
}

void append_le64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8*i)) & 0xff);
}

bool compute_challenge(const dao_consistency_context& ctx,
                       const BIGNUM* N,
                       const std::vector<uint8_t>& E,
                       const key& C,
                       const key& A_C,
                       const std::vector<uint8_t>& A_P,
                       BIGNUM* e_out)
{
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), ctx.domain.begin(), ctx.domain.end());
    buf.push_back(0);
    buf.push_back(ctx.version);
    buf.insert(buf.end(), ctx.proposal_id.data, ctx.proposal_id.data + 32);
    append_le64(buf, ctx.vote_height);
    append_le32(buf, ctx.tally_key_epoch);
    append_le32(buf, static_cast<uint32_t>(ctx.vote_input_transcript.size()));
    buf.insert(buf.end(), ctx.vote_input_transcript.begin(),
               ctx.vote_input_transcript.end());
    {
        std::vector<uint8_t> n_be(PAILLIER_MODULUS_BYTES, 0);
        BN_bn2binpad(N, n_be.data(), PAILLIER_MODULUS_BYTES);
        buf.insert(buf.end(), n_be.begin(), n_be.end());
    }
    buf.insert(buf.end(), E.begin(), E.end());
    buf.insert(buf.end(), C.bytes,   C.bytes + 32);
    buf.insert(buf.end(), A_C.bytes, A_C.bytes + 32);
    buf.insert(buf.end(), A_P.begin(), A_P.end());

    unsigned char digest[32];
    SHA256(buf.data(), buf.size(), digest);
    return BN_bin2bn(digest, 32, e_out) != nullptr;
}

void push_vec(std::vector<uint8_t>& out, const std::vector<uint8_t>& v)
{
    const uint32_t n = static_cast<uint32_t>(v.size());
    for (int i = 0; i < 4; ++i) out.push_back((n >> (8*i)) & 0xff);
    out.insert(out.end(), v.begin(), v.end());
}

bool pull_vec(const std::vector<uint8_t>& in, size_t& off,
              std::vector<uint8_t>& v)
{
    if (off + 4 > in.size()) return false;
    uint32_t n = 0;
    for (int i = 0; i < 4; ++i) n |= uint32_t(in[off++]) << (8*i);
    if (off + n > in.size()) return false;
    v.assign(in.begin() + off, in.begin() + off + n);
    off += n;
    return true;
}

} // anonymous namespace

bool dao_consistency_proof::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    out.insert(out.end(), A_C.bytes, A_C.bytes + 32);
    push_vec(out, A_P);
    push_vec(out, e);
    push_vec(out, z_m);
    push_vec(out, z_r);
    push_vec(out, z_rho);
    return true;
}

bool dao_consistency_proof::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (in.size() < 32) return false;
    std::memcpy(A_C.bytes, in.data() + off, 32);
    off += 32;
    if (!pull_vec(in, off, A_P))   return false;
    if (!pull_vec(in, off, e))     return false;
    if (!pull_vec(in, off, z_m))   return false;
    if (!pull_vec(in, off, z_r))   return false;
    if (!pull_vec(in, off, z_rho)) return false;
    return off == in.size();
}

bool dao_consistency_prove(const dao_consistency_context& ctx,
                           const BIGNUM* N,
                           const std::vector<uint8_t>& E,
                           const key& C,
                           const BIGNUM* m,
                           const BIGNUM* r,
                           const key& rho,
                           dao_consistency_proof& proof_out)
{
    if (!N || !m || !r) return false;
    if (E.size() != PAILLIER_CT_BYTES) return false;
    if (BN_is_negative(m) || BN_is_negative(r)) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, g.ctx);

    BIGNUM* a_m = BN_new();
    BIGNUM* a_r = BN_new();
    key a_rho = skGen();

    BN_rand_range(a_m, N);
    for (int tries = 0; tries < 64; ++tries) {
        BN_rand_range(a_r, N);
        if (BN_is_zero(a_r)) continue;
        BIGNUM* gcd = BN_new();
        BN_gcd(gcd, a_r, N, g.ctx);
        const bool cop = BN_is_one(gcd);
        BN_free(gcd);
        if (cop) break;
    }

    // A_P = (1+N)^a_m * a_r^N mod N^2
    BIGNUM* one_N = BN_new();
    BN_add(one_N, N, BN_value_one());

    BIGNUM* A_P_1 = BN_new();
    BN_mod_exp(A_P_1, one_N, a_m, N2, g.ctx);
    BIGNUM* A_P_2 = BN_new();
    BN_mod_exp(A_P_2, a_r, N, N2, g.ctx);
    BIGNUM* A_P_bn = BN_new();
    BN_mod_mul(A_P_bn, A_P_1, A_P_2, N2, g.ctx);

    std::vector<uint8_t> A_P(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(A_P_bn, A_P.data(), PAILLIER_CT_BYTES);

    // A_C = a_m*H + a_rho*G
    key a_m_scalar = bn_to_scalar_reduced(a_m, g.ctx);
    key a_m_H, a_rho_G, A_C;
    scalarmultKey(a_m_H, H, a_m_scalar);
    scalarmultBase(a_rho_G, a_rho);
    addKeys(A_C, a_m_H, a_rho_G);

    BIGNUM* e = BN_new();
    if (!compute_challenge(ctx, N, E, C, A_C, A_P, e)) {
        BN_free(N2); BN_free(a_m); BN_free(a_r); BN_free(one_N);
        BN_free(A_P_1); BN_free(A_P_2); BN_free(A_P_bn); BN_free(e);
        return false;
    }

    // z_m = a_m + e*m (exact integer)
    BIGNUM* z_m = BN_new();
    BN_mul(z_m, e, m, g.ctx);
    BN_add(z_m, z_m, a_m);

    // z_r = a_r * r^e mod N
    BIGNUM* r_e = BN_new();
    BN_mod_exp(r_e, r, e, N, g.ctx);
    BIGNUM* z_r = BN_new();
    BN_mod_mul(z_r, a_r, r_e, N, g.ctx);

    // z_rho = a_rho + e*rho mod ℓ
    key e_scalar = bn_to_scalar_reduced(e, g.ctx);
    key z_rho{};
    sc_muladd(z_rho.bytes, e_scalar.bytes, rho.bytes, a_rho.bytes);

    proof_out.A_C = A_C;
    proof_out.A_P = A_P;
    proof_out.e.assign(32, 0);
    BN_bn2binpad(e, proof_out.e.data(), 32);
    proof_out.z_m.assign(BN_num_bytes(z_m), 0);
    BN_bn2bin(z_m, proof_out.z_m.data());
    proof_out.z_r.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(z_r, proof_out.z_r.data(), PAILLIER_CT_BYTES);
    proof_out.z_rho.assign(32, 0);
    std::memcpy(proof_out.z_rho.data(), z_rho.bytes, 32);

    BN_free(N2); BN_free(a_m); BN_free(a_r);
    BN_free(one_N); BN_free(A_P_1); BN_free(A_P_2); BN_free(A_P_bn);
    BN_free(e); BN_free(z_m); BN_free(r_e); BN_free(z_r);
    return true;
}

std::vector<uint8_t> dao_vote_input_transcript(
    const std::vector<key>& nullifiers,
    const std::vector<uint64_t>& key_offsets)
{
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), "VeilRoot-DAO-VOTE-INPUT-V1",
               "VeilRoot-DAO-VOTE-INPUT-V1" + 27);
    buf.push_back(0);
    for (int i = 0; i < 4; ++i)
        buf.push_back((uint32_t(nullifiers.size()) >> (8*i)) & 0xff);
    for (const auto& nf : nullifiers)
        buf.insert(buf.end(), nf.bytes, nf.bytes + 32);
    for (int i = 0; i < 4; ++i)
        buf.push_back((uint32_t(key_offsets.size()) >> (8*i)) & 0xff);
    for (uint64_t ko : key_offsets)
        for (int i = 0; i < 8; ++i)
            buf.push_back((ko >> (8*i)) & 0xff);

    unsigned char digest[32];
    SHA256(buf.data(), buf.size(), digest);
    return std::vector<uint8_t>(digest, digest + 32);
}

std::vector<uint8_t> dao_extra_binding(
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const dao_consistency_proof& proof_W,
    const dao_consistency_proof& proof_S)
{
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), "VeilRoot-DAO-EXTRA-V1",
               "VeilRoot-DAO-EXTRA-V1" + 21);
    buf.push_back(0);
    push_vec(buf, E_W);
    push_vec(buf, E_S);
    push_vec(buf, proof_W.e);
    push_vec(buf, proof_W.z_m);
    push_vec(buf, proof_W.z_r);
    push_vec(buf, proof_W.z_rho);
    push_vec(buf, proof_S.e);
    push_vec(buf, proof_S.z_m);
    push_vec(buf, proof_S.z_r);
    push_vec(buf, proof_S.z_rho);

    unsigned char digest[32];
    SHA256(buf.data(), buf.size(), digest);
    return std::vector<uint8_t>(digest, digest + 32);
}

bool dao_consistency_verify(const dao_consistency_context& ctx,
                            const BIGNUM* N,
                            const std::vector<uint8_t>& E,
                            const key& C,
                            const dao_consistency_proof& proof)
{
    if (!N) return false;
    if (E.size() != PAILLIER_CT_BYTES) return false;
    if (proof.A_P.size() != PAILLIER_CT_BYTES) return false;
    if (proof.e.size() != 32) return false;
    if (proof.z_r.size() != PAILLIER_CT_BYTES) return false;
    if (proof.z_rho.size() != 32) return false;
    if (proof.z_m.empty()) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, g.ctx);

    BIGNUM* e_check = BN_new();
    if (!compute_challenge(ctx, N, E, C, proof.A_C, proof.A_P, e_check)) {
        BN_free(N2); BN_free(e_check);
        return false;
    }
    BIGNUM* e_given = BN_bin2bn(proof.e.data(), 32, nullptr);
    if (BN_cmp(e_check, e_given) != 0) {
        BN_free(N2); BN_free(e_check); BN_free(e_given);
        return false;
    }

    // Curve check: z_m*H + z_rho*G == A_C + e*C
    BIGNUM* z_m_bn = BN_bin2bn(proof.z_m.data(),
                               static_cast<int>(proof.z_m.size()), nullptr);
    key z_m_scalar = bn_to_scalar_reduced(z_m_bn, g.ctx);
    key e_scalar   = bn_to_scalar_reduced(e_check, g.ctx);

    key z_rho_key{};
    std::memcpy(z_rho_key.bytes, proof.z_rho.data(), 32);

    key z_m_H, z_rho_G, lhs;
    scalarmultKey(z_m_H, H, z_m_scalar);
    scalarmultBase(z_rho_G, z_rho_key);
    addKeys(lhs, z_m_H, z_rho_G);

    key e_C, rhs;
    scalarmultKey(e_C, C, e_scalar);
    addKeys(rhs, proof.A_C, e_C);

    if (!(lhs == rhs)) {
        BN_free(N2); BN_free(e_check); BN_free(e_given); BN_free(z_m_bn);
        return false;
    }

    // Paillier check: (1+N)^z_m * z_r^N == A_P * E^e mod N^2
    BIGNUM* one_N = BN_new();
    BN_add(one_N, N, BN_value_one());

    BIGNUM* lhs_1 = BN_new();
    BN_mod_exp(lhs_1, one_N, z_m_bn, N2, g.ctx);

    BIGNUM* z_r_bn = BN_bin2bn(proof.z_r.data(),
                               static_cast<int>(proof.z_r.size()), nullptr);
    BIGNUM* lhs_2 = BN_new();
    BN_mod_exp(lhs_2, z_r_bn, N, N2, g.ctx);

    BIGNUM* lhs_p = BN_new();
    BN_mod_mul(lhs_p, lhs_1, lhs_2, N2, g.ctx);

    BIGNUM* A_P_bn = BN_bin2bn(proof.A_P.data(),
                               static_cast<int>(proof.A_P.size()), nullptr);
    BIGNUM* E_bn = BN_bin2bn(E.data(), static_cast<int>(E.size()), nullptr);

    BIGNUM* E_e = BN_new();
    BN_mod_exp(E_e, E_bn, e_check, N2, g.ctx);
    BIGNUM* rhs_p = BN_new();
    BN_mod_mul(rhs_p, A_P_bn, E_e, N2, g.ctx);

    const bool ok = (BN_cmp(lhs_p, rhs_p) == 0);

    BN_free(N2); BN_free(e_check); BN_free(e_given); BN_free(z_m_bn);
    BN_free(one_N); BN_free(lhs_1); BN_free(z_r_bn); BN_free(lhs_2);
    BN_free(lhs_p); BN_free(A_P_bn); BN_free(E_bn); BN_free(E_e); BN_free(rhs_p);
    return ok;
}

} // namespace dao
} // namespace cryptonote