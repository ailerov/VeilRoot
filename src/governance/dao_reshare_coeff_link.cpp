// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_reshare_coeff_link.h"

#include <array>
#include <cstring>

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

bool pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out)
{
    if (off + 4 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= uint32_t(v[off++]) << (8 * i);
    return true;
}

bool bn_fixed(const BIGNUM* b, size_t w, std::vector<uint8_t>& out)
{
    out.assign(w, 0);
    return BN_bn2binpad(b, out.data(), static_cast<int>(w)) ==
           static_cast<int>(w);
}

void build_transcript(const dao_reshare_coeff_link_context& ctx,
                      const dao_reshare_coeff_link_proof& proof,
                      std::vector<uint8_t>& out)
{
    static const char DOMAIN[] = "VeilRoot-DAO-RESHARE-COEFF-LINK-V1";
    out.clear();
    out.insert(out.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
    out.insert(out.end(), ctx.genesis_block_hash.data,
               ctx.genesis_block_hash.data + 32);
    push_bytes(out, ctx.stable_key_record_hash);
    push_u64(out, ctx.share_set_id);
    push_bytes(out, ctx.contributor_pubkey);
    push_u32(out, ctx.contributor_index);
    push_u32(out, ctx.coefficient_index);
    push_bytes(out, ctx.G);
    push_bytes(out, ctx.C_ik);
    push_bytes(out, ctx.Y);
    push_bytes(out, ctx.D_x);
    push_bytes(out, ctx.range_proof_hash);
    for (size_t l = 0; l < proof.A_paillier.size(); ++l)
        out.insert(out.end(), proof.A_paillier[l].begin(),
                   proof.A_paillier[l].end());
    for (size_t l = 0; l < proof.A_vss.size(); ++l)
        out.insert(out.end(), proof.A_vss[l].begin(),
                   proof.A_vss[l].end());
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

uint8_t bit_at(const std::array<uint8_t, 16>& b, size_t l)
{
    return (b[l / 8] >> (7 - (l % 8))) & 1;
}

bool is_unit_mod(const BIGNUM* x, const BIGNUM* mod, BN_CTX* ctx)
{
    BIGNUM* g = BN_new();
    if (!g) return false;
    BN_gcd(g, x, mod, ctx);
    const bool ok = BN_is_one(g);
    BN_free(g);
    return ok;
}

} // namespace

bool dao_reshare_coeff_link_proof::serialize(
    std::vector<uint8_t>& out, size_t vss_element_bytes) const
{
    if (A_paillier.size() != dao_reshare_coeff_link_proof::REPS || A_vss.size() != dao_reshare_coeff_link_proof::REPS ||
        Z_x.size() != dao_reshare_coeff_link_proof::REPS || Z_rho.size() != dao_reshare_coeff_link_proof::REPS)
        return false;
    if (vss_element_bytes == 0 || vss_element_bytes > 1024) return false;
    out.clear();
    push_u32(out, static_cast<uint32_t>(dao_reshare_coeff_link_proof::REPS));
    push_u32(out, static_cast<uint32_t>(vss_element_bytes));
    for (size_t l = 0; l < dao_reshare_coeff_link_proof::REPS; ++l) {
        if (A_paillier[l].size() != PAILLIER_CT_BYTES) return false;
        if (A_vss[l].size()      != vss_element_bytes)  return false;
        if (Z_x[l].size()        != dao_reshare_coeff_link_proof::ZX_BYTES)           return false;
        if (Z_rho[l].size()      != vss_element_bytes)  return false;
        out.insert(out.end(), A_paillier[l].begin(), A_paillier[l].end());
        out.insert(out.end(), A_vss[l].begin(),      A_vss[l].end());
        out.insert(out.end(), Z_x[l].begin(),        Z_x[l].end());
        out.insert(out.end(), Z_rho[l].begin(),      Z_rho[l].end());
    }
    return true;
}

bool dao_reshare_coeff_link_proof::deserialize(
    const std::vector<uint8_t>& in, size_t vss_element_bytes)
{
    if (in.size() < 8) return false;
    if (vss_element_bytes == 0 || vss_element_bytes > 1024) return false;
    size_t off = 0;
    uint32_t reps = 0, veb = 0;
    if (!pull_u32(in, off, reps)) return false;
    if (!pull_u32(in, off, veb))  return false;
    if (reps != dao_reshare_coeff_link_proof::REPS) return false;
    if (veb != vss_element_bytes) return false;

    const size_t per = PAILLIER_CT_BYTES + vss_element_bytes
                     + dao_reshare_coeff_link_proof::ZX_BYTES + vss_element_bytes;
    if (in.size() != off + dao_reshare_coeff_link_proof::REPS * per) return false;

    A_paillier.assign(dao_reshare_coeff_link_proof::REPS, {});
    A_vss.assign(dao_reshare_coeff_link_proof::REPS, {});
    Z_x.assign(dao_reshare_coeff_link_proof::REPS, {});
    Z_rho.assign(dao_reshare_coeff_link_proof::REPS, {});
    for (size_t l = 0; l < dao_reshare_coeff_link_proof::REPS; ++l) {
        A_paillier[l].assign(in.begin() + off,
                             in.begin() + off + PAILLIER_CT_BYTES);
        off += PAILLIER_CT_BYTES;
        A_vss[l].assign(in.begin() + off,
                        in.begin() + off + vss_element_bytes);
        off += vss_element_bytes;
        Z_x[l].assign(in.begin() + off, in.begin() + off + dao_reshare_coeff_link_proof::ZX_BYTES);
        off += dao_reshare_coeff_link_proof::ZX_BYTES;
        Z_rho[l].assign(in.begin() + off,
                        in.begin() + off + vss_element_bytes);
        off += vss_element_bytes;
    }
    return true;
}

bool dao_reshare_coeff_link_prove(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const dao_reshare_coeff_link_context& ctx,
    const BIGNUM* x,
    const BIGNUM* rho,
    dao_reshare_coeff_link_proof& proof_out)
{
    if (!pk.valid() || !grp.valid() || !x || !rho) return false;
    if (BN_is_negative(x) || BN_is_negative(rho)) return false;
    if (ctx.G.size()    != PAILLIER_CT_BYTES) return false;
    if (ctx.C_ik.size() != PAILLIER_CT_BYTES) return false;
    if (ctx.Y.size()    != PAILLIER_CT_BYTES) return false;

    const size_t vss_element_bytes = BN_num_bytes(grp.P);
    if (ctx.D_x.size() != vss_element_bytes) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    const BIGNUM* N2 = pk.N2();
    BIGNUM* G  = BN_bin2bn(ctx.G.data(),  (int)ctx.G.size(),  nullptr);
    BIGNUM* Y  = BN_bin2bn(ctx.Y.data(),  (int)ctx.Y.size(),  nullptr);
    if (!G || !Y) { BN_free(G); BN_free(Y); return false; }

    proof_out.A_paillier.assign(dao_reshare_coeff_link_proof::REPS, {});
    proof_out.A_vss.assign(dao_reshare_coeff_link_proof::REPS, {});
    proof_out.Z_x.assign(dao_reshare_coeff_link_proof::REPS, {});
    proof_out.Z_rho.assign(dao_reshare_coeff_link_proof::REPS, {});

    std::vector<BIGNUM*> as(dao_reshare_coeff_link_proof::REPS, nullptr);
    std::vector<BIGNUM*> us(dao_reshare_coeff_link_proof::REPS, nullptr);
    auto bail = [&]() {
        for (auto* p : as) if (p) BN_free(p);
        for (auto* p : us) if (p) BN_free(p);
        BN_free(G); BN_free(Y);
        return false;
    };

    for (size_t l = 0; l < dao_reshare_coeff_link_proof::REPS; ++l) {
        as[l] = BN_new();
        us[l] = BN_new();
        if (!as[l] || !us[l] ||
            !BN_rand(as[l], 193, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
            !BN_rand_range(us[l], grp.P_prime)) return bail();

        BIGNUM* Ap  = BN_new();
        BIGNUM* Av  = BN_new();
        BIGNUM* g_a = BN_new();
        BIGNUM* h_u = BN_new();
        if (!Ap || !Av || !g_a || !h_u ||
            !BN_mod_exp(Ap, G, as[l], N2, g.ctx) ||
            !BN_mod_exp(g_a, grp.g, as[l], grp.P, g.ctx) ||
            !BN_mod_exp(h_u, grp.h, us[l], grp.P, g.ctx) ||
            !BN_mod_mul(Av, g_a, h_u, grp.P, g.ctx) ||
            !bn_fixed(Ap, PAILLIER_CT_BYTES, proof_out.A_paillier[l]) ||
            !bn_fixed(Av, vss_element_bytes, proof_out.A_vss[l])) {
            BN_free(Ap); BN_free(Av); BN_free(g_a); BN_free(h_u);
            return bail();
        }
        BN_free(Ap); BN_free(Av); BN_free(g_a); BN_free(h_u);
    }

    std::vector<uint8_t> transcript;
    build_transcript(ctx, proof_out, transcript);
    std::array<uint8_t, 16> bits{};
    if (!derive_challenge_bits(transcript, bits)) return bail();

    for (size_t l = 0; l < dao_reshare_coeff_link_proof::REPS; ++l) {
        const uint8_t el = bit_at(bits, l);
        BIGNUM* zx = BN_dup(as[l]);
        BIGNUM* zr = BN_dup(us[l]);
        if (!zx || !zr) { BN_free(zx); BN_free(zr); return bail(); }
        if (el) {
            if (!BN_add(zx, zx, x) || !BN_add(zr, zr, rho)) {
                BN_free(zx); BN_free(zr);
                return bail();
            }
        }
        if (!BN_mod(zr, zr, grp.P_prime, g.ctx) ||
            !bn_fixed(zx, dao_reshare_coeff_link_proof::ZX_BYTES, proof_out.Z_x[l]) ||
            !bn_fixed(zr, vss_element_bytes, proof_out.Z_rho[l])) {
            BN_free(zx); BN_free(zr);
            return bail();
        }
        BN_free(zx); BN_free(zr);
    }

    for (auto* p : as) if (p) BN_free(p);
    for (auto* p : us) if (p) BN_free(p);
    BN_free(G); BN_free(Y);
    return true;
}

bool dao_reshare_coeff_link_verify(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const dao_reshare_coeff_link_context& ctx,
    const dao_reshare_coeff_link_proof& proof)
{
    if (!pk.valid() || !grp.valid()) return false;
    if (proof.A_paillier.size() != dao_reshare_coeff_link_proof::REPS) return false;
    if (proof.A_vss.size()      != dao_reshare_coeff_link_proof::REPS) return false;
    if (proof.Z_x.size()        != dao_reshare_coeff_link_proof::REPS) return false;
    if (proof.Z_rho.size()      != dao_reshare_coeff_link_proof::REPS) return false;
    if (ctx.G.size()    != PAILLIER_CT_BYTES) return false;
    if (ctx.C_ik.size() != PAILLIER_CT_BYTES) return false;
    if (ctx.Y.size()    != PAILLIER_CT_BYTES) return false;

    const size_t vss_element_bytes = BN_num_bytes(grp.P);
    if (ctx.D_x.size() != vss_element_bytes) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    const BIGNUM* N2 = pk.N2();
    BIGNUM* G  = BN_bin2bn(ctx.G.data(),  (int)ctx.G.size(),  nullptr);
    BIGNUM* Y  = BN_bin2bn(ctx.Y.data(),  (int)ctx.Y.size(),  nullptr);
    BIGNUM* Dx = BN_bin2bn(ctx.D_x.data(),(int)ctx.D_x.size(),nullptr);
    if (!G || !Y || !Dx) { BN_free(G); BN_free(Y); BN_free(Dx); return false; }

    if (!is_unit_mod(G, N2, g.ctx) || !is_unit_mod(Y, N2, g.ctx)) {
        BN_free(G); BN_free(Y); BN_free(Dx);
        return false;
    }

    BIGNUM* zlimit = BN_new();
    BN_one(zlimit);
    BN_lshift(zlimit, zlimit, 194);

    std::vector<uint8_t> transcript;
    build_transcript(ctx, proof, transcript);
    std::array<uint8_t, 16> bits{};
    if (!derive_challenge_bits(transcript, bits)) {
        BN_free(zlimit); BN_free(G); BN_free(Y); BN_free(Dx);
        return false;
    }

    bool ok = true;
    for (size_t l = 0; l < dao_reshare_coeff_link_proof::REPS && ok; ++l) {
        if (proof.A_paillier[l].size() != PAILLIER_CT_BYTES ||
            proof.A_vss[l].size()      != vss_element_bytes ||
            proof.Z_x[l].size()        != dao_reshare_coeff_link_proof::ZX_BYTES ||
            proof.Z_rho[l].size()      != vss_element_bytes) {
            ok = false; break;
        }

        BIGNUM* Ap = BN_bin2bn(proof.A_paillier[l].data(),
                                (int)proof.A_paillier[l].size(), nullptr);
        BIGNUM* Av = BN_bin2bn(proof.A_vss[l].data(),
                                (int)proof.A_vss[l].size(), nullptr);
        BIGNUM* zx = BN_bin2bn(proof.Z_x[l].data(),
                                (int)proof.Z_x[l].size(), nullptr);
        BIGNUM* zr = BN_bin2bn(proof.Z_rho[l].data(),
                                (int)proof.Z_rho[l].size(), nullptr);
        if (!Ap || !Av || !zx || !zr) {
            BN_free(Ap); BN_free(Av); BN_free(zx); BN_free(zr);
            ok = false; break;
        }

        if (BN_cmp(zx, zlimit) >= 0) { ok = false; }

        const uint8_t el = bit_at(bits, l);

        if (ok) {
            BIGNUM* lhs1 = BN_new();
            BIGNUM* rhs1 = BN_new();
            if (!lhs1 || !rhs1 ||
                !BN_mod_exp(lhs1, G, zx, N2, g.ctx) ||
                !BN_copy(rhs1, Ap) ||
                (el && !BN_mod_mul(rhs1, rhs1, Y, N2, g.ctx)) ||
                BN_cmp(lhs1, rhs1) != 0) {
                ok = false;
            }
            BN_free(lhs1); BN_free(rhs1);
        }

        if (ok) {
            BIGNUM* lhs2 = BN_new();
            BIGNUM* rhs2 = BN_new();
            BIGNUM* g_zx = BN_new();
            BIGNUM* h_zr = BN_new();
            if (!lhs2 || !rhs2 || !g_zx || !h_zr ||
                !BN_mod_exp(g_zx, grp.g, zx, grp.P, g.ctx) ||
                !BN_mod_exp(h_zr, grp.h, zr, grp.P, g.ctx) ||
                !BN_mod_mul(lhs2, g_zx, h_zr, grp.P, g.ctx) ||
                !BN_copy(rhs2, Av) ||
                (el && !BN_mod_mul(rhs2, rhs2, Dx, grp.P, g.ctx)) ||
                BN_cmp(lhs2, rhs2) != 0) {
                ok = false;
            }
            BN_free(lhs2); BN_free(rhs2); BN_free(g_zx); BN_free(h_zr);
        }

        BN_free(Ap); BN_free(Av); BN_free(zx); BN_free(zr);
    }

    BN_free(zlimit);
    BN_free(G); BN_free(Y); BN_free(Dx);
    return ok;
}

} // namespace dao
} // namespace cryptonote
