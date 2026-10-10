// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_reshare_proof.h"

#include <array>
#include <cstring>
#include <string>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

void push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

void push_bytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

// Modular exponentiation with support for a signed exponent. A
// negative exponent is handled by inverting the base modulo the
// modulus first.
bool modexp_signed(const BIGNUM* base, const BIGNUM* exp,
                   const BIGNUM* mod, BIGNUM* out, BN_CTX* ctx)
{
    if (!BN_is_negative(exp))
        return BN_mod_exp(out, base, exp, mod, ctx) == 1;

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

bool bn_to_fixed(const BIGNUM* b, size_t width, std::vector<uint8_t>& out)
{
    out.assign(width, 0);
    return BN_bn2binpad(b, out.data(), static_cast<int>(width)) ==
           static_cast<int>(width);
}

// Canonical transcript. Binds every public input plus every commitment,
// in a single unambiguous order. Length-prefixed where variable, fixed
// width where the field has one.
void build_transcript(const dao_reshare_link_context& ctx,
                      const dao_reshare_link_proof& proof,
                      std::vector<uint8_t>& out)
{
    static const char DOMAIN[] = "VeilRoot-DAO-RESHARE-LINK-V1";
    out.clear();
    out.insert(out.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);

    out.insert(out.end(), ctx.genesis_block_hash.data,
               ctx.genesis_block_hash.data + 32);
    push_bytes(out, ctx.stable_key_record_hash);
    push_u64(out, ctx.share_set_id);
    push_bytes(out, ctx.contributor_pubkey);
    push_u32(out, ctx.original_index);
    push_u32(out, static_cast<uint32_t>(ctx.contributor_subset.size()));
    for (uint32_t s : ctx.contributor_subset) push_u32(out, s);

    push_bytes(out, ctx.Delta);
    push_bytes(out, ctx.mu_i);
    push_bytes(out, ctx.N);
    push_bytes(out, ctx.V);
    push_bytes(out, ctx.VK_i);
    push_bytes(out, ctx.C_i0);

    for (size_t l = 0; l < proof.A.size(); ++l)
        out.insert(out.end(), proof.A[l].begin(), proof.A[l].end());
    for (size_t l = 0; l < proof.B.size(); ++l)
        out.insert(out.end(), proof.B[l].begin(), proof.B[l].end());
}

bool derive_challenge_bits(const std::vector<uint8_t>& transcript,
                           std::array<uint8_t, 16>& bits_out)
{
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md) return false;
    bool ok = true;
    ok = ok && EVP_DigestInit_ex(md, EVP_shake256(), nullptr) == 1;
    ok = ok && EVP_DigestUpdate(md, transcript.data(),
                                 transcript.size()) == 1;
    ok = ok && EVP_DigestFinalXOF(md, bits_out.data(),
                                   bits_out.size()) == 1;
    EVP_MD_CTX_free(md);
    return ok;
}

// MSB-first within each byte.
uint8_t bit_at(const std::array<uint8_t, 16>& b, size_t l)
{
    return (b[l / 8] >> (7 - (l % 8))) & 1;
}

} // namespace

bool dao_reshare_link_proof::serialize(std::vector<uint8_t>& out) const
{
    if (A.size() != dao_reshare_link_proof::REPS || B.size() != dao_reshare_link_proof::REPS || Z.size() != dao_reshare_link_proof::REPS)
        return false;
    out.clear();
    push_u32(out, static_cast<uint32_t>(dao_reshare_link_proof::REPS));
    for (size_t l = 0; l < dao_reshare_link_proof::REPS; ++l) {
        if (A[l].size() != PAILLIER_CT_BYTES) return false;
        if (B[l].size() != PAILLIER_CT_BYTES) return false;
        if (Z[l].size() != 1 + dao_reshare_link_proof::SCALAR_BYTES)  return false;
        if (Z[l][0] != 0 && Z[l][0] != 1)     return false;
        out.insert(out.end(), A[l].begin(), A[l].end());
        out.insert(out.end(), B[l].begin(), B[l].end());
        out.insert(out.end(), Z[l].begin(), Z[l].end());
    }
    return true;
}

bool dao_reshare_link_proof::deserialize(const std::vector<uint8_t>& in)
{
    if (in.size() < 4) return false;
    size_t off = 0;
    uint32_t reps = 0;
    for (int i = 0; i < 4; ++i) reps |= uint32_t(in[off++]) << (8 * i);
    if (reps != dao_reshare_link_proof::REPS) return false;

    const size_t per = 2 * PAILLIER_CT_BYTES + 1 + dao_reshare_link_proof::SCALAR_BYTES;
    if (in.size() != off + dao_reshare_link_proof::REPS * per) return false;

    A.assign(dao_reshare_link_proof::REPS, {});
    B.assign(dao_reshare_link_proof::REPS, {});
    Z.assign(dao_reshare_link_proof::REPS, {});
    for (size_t l = 0; l < dao_reshare_link_proof::REPS; ++l) {
        A[l].assign(in.begin() + off,
                    in.begin() + off + PAILLIER_CT_BYTES);
        off += PAILLIER_CT_BYTES;
        B[l].assign(in.begin() + off,
                    in.begin() + off + PAILLIER_CT_BYTES);
        off += PAILLIER_CT_BYTES;
        Z[l].assign(in.begin() + off,
                    in.begin() + off + 1 + dao_reshare_link_proof::SCALAR_BYTES);
        off += 1 + dao_reshare_link_proof::SCALAR_BYTES;
        if (Z[l][0] != 0 && Z[l][0] != 1) return false;
    }
    return true;
}

bool dao_reshare_link_prove(
    const dao_reshare_link_context& ctx,
    const BIGNUM* s_i,
    dao_reshare_link_proof& proof_out)
{
    if (!s_i) return false;
    if (ctx.N.size()    != PAILLIER_MODULUS_BYTES) return false;
    if (ctx.V.size()    != PAILLIER_CT_BYTES)      return false;
    if (ctx.VK_i.size() != PAILLIER_CT_BYTES)      return false;
    if (ctx.C_i0.size() != PAILLIER_CT_BYTES)      return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* N  = BN_bin2bn(ctx.N.data(),
                            static_cast<int>(ctx.N.size()), nullptr);
    BIGNUM* V  = BN_bin2bn(ctx.V.data(),
                            static_cast<int>(ctx.V.size()), nullptr);
    BIGNUM* VK = BN_bin2bn(ctx.VK_i.data(),
                            static_cast<int>(ctx.VK_i.size()), nullptr);
    BIGNUM* C0 = BN_bin2bn(ctx.C_i0.data(),
                            static_cast<int>(ctx.C_i0.size()), nullptr);
    BIGNUM* Dl = BN_bin2bn(ctx.Delta.data(),
                            static_cast<int>(ctx.Delta.size()), nullptr);
    BIGNUM* mu = BN_bin2bn(ctx.mu_i.data(),
                            static_cast<int>(ctx.mu_i.size()), nullptr);
    if (!N || !V || !VK || !C0 || !Dl || !mu) {
        BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
        BN_free(Dl); BN_free(mu);
        return false;
    }

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, g.ctx);

    BIGNUM* g1 = BN_new();
    BIGNUM* g2 = BN_new();
    if (!BN_mod_exp(g1, V, Dl, N2, g.ctx) ||
        !BN_mod_exp(g2, V, mu, N2, g.ctx)) {
        BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
        BN_free(Dl); BN_free(mu); BN_free(N2);
        BN_free(g1); BN_free(g2);
        return false;
    }

    // Sample fresh signed randomizers r_l. Range considerations for the
    // full VSS are handled in the separate range proof; for the
    // common-exponent relation any uniform r_l suffices.
    std::vector<BIGNUM*> rs(dao_reshare_link_proof::REPS, nullptr);
    proof_out.A.assign(dao_reshare_link_proof::REPS, {});
    proof_out.B.assign(dao_reshare_link_proof::REPS, {});
    for (size_t l = 0; l < dao_reshare_link_proof::REPS; ++l) {
        rs[l] = BN_new();
        if (!rs[l] || !BN_rand_range(rs[l], N)) {
            for (auto* p : rs) if (p) BN_free(p);
            BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
            BN_free(Dl); BN_free(mu); BN_free(N2);
            BN_free(g1); BN_free(g2);
            return false;
        }
        uint8_t sign_byte = 0;
        if (RAND_bytes(&sign_byte, 1) != 1) {
            for (auto* p : rs) if (p) BN_free(p);
            BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
            BN_free(Dl); BN_free(mu); BN_free(N2);
            BN_free(g1); BN_free(g2);
            return false;
        }
        if (sign_byte & 1) BN_set_negative(rs[l], 1);

        BIGNUM* Al = BN_new();
        BIGNUM* Bl = BN_new();
        if (!Al || !Bl ||
            !modexp_signed(g1, rs[l], N2, Al, g.ctx) ||
            !modexp_signed(g2, rs[l], N2, Bl, g.ctx) ||
            !bn_to_fixed(Al, PAILLIER_CT_BYTES, proof_out.A[l]) ||
            !bn_to_fixed(Bl, PAILLIER_CT_BYTES, proof_out.B[l])) {
            BN_free(Al); BN_free(Bl);
            for (auto* p : rs) if (p) BN_free(p);
            BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
            BN_free(Dl); BN_free(mu); BN_free(N2);
            BN_free(g1); BN_free(g2);
            return false;
        }
        BN_free(Al); BN_free(Bl);
    }

    std::vector<uint8_t> transcript;
    build_transcript(ctx, proof_out, transcript);
    std::array<uint8_t, 16> bits{};
    if (!derive_challenge_bits(transcript, bits)) {
        for (auto* p : rs) if (p) BN_free(p);
        BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
        BN_free(Dl); BN_free(mu); BN_free(N2);
        BN_free(g1); BN_free(g2);
        return false;
    }

    proof_out.Z.assign(dao_reshare_link_proof::REPS, {});
    for (size_t l = 0; l < dao_reshare_link_proof::REPS; ++l) {
        BIGNUM* z = BN_dup(rs[l]);
        if (!z) {
            for (auto* p : rs) if (p) BN_free(p);
            BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
            BN_free(Dl); BN_free(mu); BN_free(N2);
            BN_free(g1); BN_free(g2);
            return false;
        }
        if (bit_at(bits, l)) {
            if (!BN_add(z, z, s_i)) {
                BN_free(z);
                for (auto* p : rs) if (p) BN_free(p);
                BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
                BN_free(Dl); BN_free(mu); BN_free(N2);
                BN_free(g1); BN_free(g2);
                return false;
            }
        }
        std::vector<uint8_t> zs(1 + dao_reshare_link_proof::SCALAR_BYTES, 0);
        zs[0] = BN_is_negative(z) ? 1 : 0;
        BIGNUM* abs_z = BN_dup(z);
        BN_set_negative(abs_z, 0);
        const bool ok_ser = abs_z &&
            BN_bn2binpad(abs_z, zs.data() + 1,
                         dao_reshare_link_proof::SCALAR_BYTES) ==
            dao_reshare_link_proof::SCALAR_BYTES;
        BN_free(abs_z);
        BN_free(z);
        if (!ok_ser) {
            for (auto* p : rs) if (p) BN_free(p);
            BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
            BN_free(Dl); BN_free(mu); BN_free(N2);
            BN_free(g1); BN_free(g2);
            return false;
        }
        proof_out.Z[l] = std::move(zs);
    }

    for (auto* p : rs) if (p) BN_free(p);
    BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
    BN_free(Dl); BN_free(mu); BN_free(N2);
    BN_free(g1); BN_free(g2);
    return true;
}

bool dao_reshare_link_verify(
    const dao_reshare_link_context& ctx,
    const dao_reshare_link_proof& proof)
{
    if (proof.A.size() != dao_reshare_link_proof::REPS ||
        proof.B.size() != dao_reshare_link_proof::REPS ||
        proof.Z.size() != dao_reshare_link_proof::REPS)
        return false;
    if (ctx.N.size() != PAILLIER_MODULUS_BYTES) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* N  = BN_bin2bn(ctx.N.data(),
                            static_cast<int>(ctx.N.size()), nullptr);
    BIGNUM* V  = BN_bin2bn(ctx.V.data(),
                            static_cast<int>(ctx.V.size()), nullptr);
    BIGNUM* VK = BN_bin2bn(ctx.VK_i.data(),
                            static_cast<int>(ctx.VK_i.size()), nullptr);
    BIGNUM* C0 = BN_bin2bn(ctx.C_i0.data(),
                            static_cast<int>(ctx.C_i0.size()), nullptr);
    BIGNUM* Dl = BN_bin2bn(ctx.Delta.data(),
                            static_cast<int>(ctx.Delta.size()), nullptr);
    BIGNUM* mu = BN_bin2bn(ctx.mu_i.data(),
                            static_cast<int>(ctx.mu_i.size()), nullptr);
    if (!N || !V || !VK || !C0 || !Dl || !mu) {
        BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
        BN_free(Dl); BN_free(mu);
        return false;
    }

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, g.ctx);

    BIGNUM* g1 = BN_new();
    BIGNUM* g2 = BN_new();
    if (!BN_mod_exp(g1, V, Dl, N2, g.ctx) ||
        !BN_mod_exp(g2, V, mu, N2, g.ctx)) {
        BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
        BN_free(Dl); BN_free(mu); BN_free(N2);
        BN_free(g1); BN_free(g2);
        return false;
    }

    std::vector<uint8_t> transcript;
    build_transcript(ctx, proof, transcript);
    std::array<uint8_t, 16> bits{};
    if (!derive_challenge_bits(transcript, bits)) {
        BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
        BN_free(Dl); BN_free(mu); BN_free(N2);
        BN_free(g1); BN_free(g2);
        return false;
    }

    bool ok = true;
    for (size_t l = 0; l < dao_reshare_link_proof::REPS && ok; ++l) {
        if (proof.A[l].size() != PAILLIER_CT_BYTES ||
            proof.B[l].size() != PAILLIER_CT_BYTES ||
            proof.Z[l].size() != 1 + dao_reshare_link_proof::SCALAR_BYTES) {
            ok = false; break;
        }
        if (proof.Z[l][0] != 0 && proof.Z[l][0] != 1) { ok = false; break; }

        BIGNUM* Al = BN_bin2bn(proof.A[l].data(),
                                static_cast<int>(proof.A[l].size()), nullptr);
        BIGNUM* Bl = BN_bin2bn(proof.B[l].data(),
                                static_cast<int>(proof.B[l].size()), nullptr);
        BIGNUM* z  = BN_bin2bn(proof.Z[l].data() + 1,
                                static_cast<int>(proof.Z[l].size() - 1),
                                nullptr);
        if (!Al || !Bl || !z) {
            BN_free(Al); BN_free(Bl); BN_free(z);
            ok = false; break;
        }
        if (proof.Z[l][0] == 1) BN_set_negative(z, 1);

        const uint8_t el = bit_at(bits, l);

        BIGNUM* lhs1 = BN_new();
        BIGNUM* rhs1 = BN_new();
        if (!lhs1 || !rhs1 ||
            !modexp_signed(g1, z, N2, lhs1, g.ctx) ||
            !BN_copy(rhs1, Al) ||
            (el && !BN_mod_mul(rhs1, rhs1, VK, N2, g.ctx)) ||
            BN_cmp(lhs1, rhs1) != 0) {
            ok = false;
        }
        BN_free(lhs1); BN_free(rhs1);

        if (ok) {
            BIGNUM* lhs2 = BN_new();
            BIGNUM* rhs2 = BN_new();
            if (!lhs2 || !rhs2 ||
                !modexp_signed(g2, z, N2, lhs2, g.ctx) ||
                !BN_copy(rhs2, Bl) ||
                (el && !BN_mod_mul(rhs2, rhs2, C0, N2, g.ctx)) ||
                BN_cmp(lhs2, rhs2) != 0) {
                ok = false;
            }
            BN_free(lhs2); BN_free(rhs2);
        }

        BN_free(Al); BN_free(Bl); BN_free(z);
    }

    BN_free(N); BN_free(V); BN_free(VK); BN_free(C0);
    BN_free(Dl); BN_free(mu); BN_free(N2);
    BN_free(g1); BN_free(g2);
    return ok;
}

} // namespace dao
} // namespace cryptonote
