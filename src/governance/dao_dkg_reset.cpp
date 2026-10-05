// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_dkg_reset.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include <cstring>

namespace cryptonote {
namespace dao {

namespace {

BIGNUM* vec_to_bn(const std::vector<uint8_t>& v)
{
    if (v.empty()) return BN_new();
    return BN_bin2bn(v.data(), static_cast<int>(v.size()), nullptr);
}

void bn_to_vec(const BIGNUM* x, std::vector<uint8_t>& out)
{
    if (!x) { out.clear(); return; }
    const int nb = BN_num_bytes(x);
    out.assign(static_cast<size_t>(nb), 0);
    if (nb > 0) BN_bn2bin(x, out.data());
}

void bn_to_signed_vec(const BIGNUM* x, std::vector<uint8_t>& out)
{
    if (!x) { out.clear(); return; }
    const int nb = BN_num_bytes(x);
    out.assign(1 + static_cast<size_t>(nb), 0);
    out[0] = BN_is_negative(x) ? 1 : 0;
    if (nb > 0) BN_bn2bin(x, out.data() + 1);
}

BIGNUM* signed_vec_to_bn(const std::vector<uint8_t>& v)
{
    if (v.empty()) return nullptr;
    BIGNUM* b = BN_bin2bn(v.data() + 1,
                          static_cast<int>(v.size() - 1), nullptr);
    if (!b) return nullptr;
    if (v[0]) BN_set_negative(b, 1);
    return b;
}

void bn_to_pad(const BIGNUM* x, size_t n, std::vector<uint8_t>& out)
{
    out.assign(n, 0);
    if (!x) return;
    BN_bn2binpad(x, out.data(), static_cast<int>(n));
}

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

bool pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& x)
{
    if (off + 4 > v.size()) return false;
    x = 0;
    for (int i = 0; i < 4; ++i) x |= uint32_t(v[off++]) << (8 * i);
    return true;
}

bool push_blob(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
    return true;
}

bool pull_blob(const std::vector<uint8_t>& v, size_t& off,
               std::vector<uint8_t>& out)
{
    uint32_t n = 0;
    if (!pull_u32(v, off, n)) return false;
    if (off + n > v.size()) return false;
    out.assign(v.begin() + off, v.begin() + off + n);
    off += n;
    return true;
}

// SHA-256 into a scalar mod q.
bool hash_to_scalar(const std::vector<uint8_t>& in,
                    const BIGNUM* q,
                    BIGNUM* out, BN_CTX* ctx)
{
    uint8_t digest[32];
    SHA256(in.data(), in.size(), digest);
    BIGNUM* h = BN_bin2bn(digest, 32, nullptr);
    if (!h) return false;
    bool ok = BN_nnmod(out, h, q, ctx) == 1;
    BN_free(h);
    return ok;
}

} // anonymous namespace

// --------------------------------------------------------------------
// Proof serialization
// --------------------------------------------------------------------

bool dao_reset_share_link_proof::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    push_blob(out, T_vss);
    push_blob(out, T_paillier);
    push_blob(out, z_share);
    push_blob(out, z_blinding);
    return true;
}

bool dao_reset_share_link_proof::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (!pull_blob(in, off, T_vss)) return false;
    if (!pull_blob(in, off, T_paillier)) return false;
    if (!pull_blob(in, off, z_share)) return false;
    if (!pull_blob(in, off, z_blinding)) return false;
    return off == in.size();
}

// --------------------------------------------------------------------
// Link proof — shared challenge builder
// --------------------------------------------------------------------

namespace {

bool build_link_challenge(
    const dao_vss_group& grp,
    const BIGNUM* mu,
    const BIGNUM* C0,
    const BIGNUM* VKi,
    const BIGNUM* T_vss,
    const BIGNUM* T_paillier,
    const std::vector<uint8_t>& ctx_bytes,
    BIGNUM* e_out,
    BN_CTX* ctx)
{
    const size_t p_sz  = static_cast<size_t>(BN_num_bytes(grp.P));
    const size_t pp_sz = static_cast<size_t>(BN_num_bytes(grp.P_prime));

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-DKG-RESET-SHARE-LINK-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    push_blob(buf, ctx_bytes);

    // mu signed: sign byte + magnitude padded to P' bytes
    {
        buf.push_back(BN_is_negative(mu) ? 1 : 0);
        std::vector<uint8_t> tmp;
        bn_to_pad(mu, pp_sz, tmp);
        buf.insert(buf.end(), tmp.begin(), tmp.end());
    }
    { std::vector<uint8_t> tmp; bn_to_pad(C0, p_sz, tmp);
      buf.insert(buf.end(), tmp.begin(), tmp.end()); }
    { std::vector<uint8_t> tmp; bn_to_pad(VKi, 512, tmp);
      buf.insert(buf.end(), tmp.begin(), tmp.end()); }
    { std::vector<uint8_t> tmp; bn_to_pad(T_vss, p_sz, tmp);
      buf.insert(buf.end(), tmp.begin(), tmp.end()); }
    { std::vector<uint8_t> tmp; bn_to_pad(T_paillier, 512, tmp);
      buf.insert(buf.end(), tmp.begin(), tmp.end()); }

    return hash_to_scalar(buf, grp.P_prime, e_out, ctx);
}

} // anonymous namespace

// --------------------------------------------------------------------
// Reset-generation: works in integers. Polynomial coefficients A[k], B[k]
// are integer, A[0] = mu*SK, A[k] = Delta*a_raw, B[k] = Delta*b_raw.
// --------------------------------------------------------------------

bool dao_dkg_reset_compute_lambda_unused_placeholder() { return true; }

bool dao_dkg_reset_generate_contribution(
    const dao_dkg_reset_config& cfg,
    uint32_t old_member_id,
    const std::vector<uint8_t>& local_old_share,
    const dao_vss_group& vss,
    const BIGNUM* N2,
    const BIGNUM* V_K,
    const std::vector<uint8_t>& V_K_i_bytes,
    dao_reset_public_contribution& public_out,
    std::vector<dao_reset_private_subshare>& private_out)
{
    if (!vss.valid() || !N2 || !V_K) return false;
    if (cfg.new_threshold < 1) return false;
    if (cfg.new_threshold > cfg.new_members.size()) return false;
    if (old_member_id == 0) return false;
    if (V_K_i_bytes.empty()) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;
    const BIGNUM* Delta = dao_dkg_delta();

    const uint32_t deg = cfg.new_threshold - 1;

    // Hoisted so no goto crosses an initialization.
    std::vector<uint32_t> old_ids;
    BIGNUM* SK      = nullptr;
    BIGNUM* mu      = nullptr;
    std::vector<BIGNUM*> a_raw;
    std::vector<BIGNUM*> b_raw;
    std::vector<BIGNUM*> A;
    std::vector<BIGNUM*> B;
    BIGNUM* C0_bn   = nullptr;
    int p_bytes     = 0;
    bool ok         = false;

    for (size_t i = 0; i < cfg.old_members.size(); ++i)
        old_ids.push_back(static_cast<uint32_t>(i + 1));

    SK = signed_vec_to_bn(local_old_share);
    if (!SK) goto done;

    mu = BN_new();
    if (!mu || !dao_dkg_lagrange_mu(old_ids, old_member_id, mu)) goto done;

    a_raw.assign(deg + 1, nullptr);
    b_raw.assign(deg + 1, nullptr);
    for (uint32_t k = 0; k <= deg; ++k) {
        a_raw[k] = BN_new();
        b_raw[k] = BN_new();
        if (!a_raw[k] || !b_raw[k]) goto done;
    }

    if (!BN_copy(a_raw[0], SK)) goto done;

    for (uint32_t k = 1; k <= deg; ++k) {
        BIGNUM* upper = BN_new();
        if (!upper) goto done;
        BN_set_bit(upper, 128);
        bool r = BN_rand_range(a_raw[k], upper) == 1;
        BN_free(upper);
        if (!r) goto done;
    }
    for (uint32_t k = 0; k <= deg; ++k) {
        BIGNUM* upper = BN_new();
        if (!upper) goto done;
        BN_set_bit(upper, 128);
        bool r = BN_rand_range(b_raw[k], upper) == 1;
        BN_free(upper);
        if (!r) goto done;
    }

    A.assign(deg + 1, nullptr);
    B.assign(deg + 1, nullptr);
    for (uint32_t k = 0; k <= deg; ++k) {
        A[k] = BN_new(); B[k] = BN_new();
        if (!A[k] || !B[k]) goto done;
    }

    if (!BN_mul(A[0], mu, SK, ctx)) goto done;
    for (uint32_t k = 1; k <= deg; ++k)
        if (!BN_mul(A[k], a_raw[k], Delta, ctx)) goto done;
    for (uint32_t k = 0; k <= deg; ++k)
        if (!BN_mul(B[k], b_raw[k], Delta, ctx)) goto done;

    public_out = dao_reset_public_contribution{};
    public_out.old_member_id = old_member_id;
    public_out.coefficient_commitments.assign(deg + 1, {});

    p_bytes = BN_num_bytes(vss.P);
    C0_bn = BN_new();
    if (!C0_bn) goto done;

    for (uint32_t k = 0; k <= deg; ++k) {
        BIGNUM* am = BN_new();
        BIGNUM* bm = BN_new();
        BIGNUM* ga = BN_new();
        BIGNUM* hb = BN_new();
        BIGNUM* Ck = BN_new();
        if (!am || !bm || !ga || !hb || !Ck) {
            BN_free(am); BN_free(bm); BN_free(ga); BN_free(hb); BN_free(Ck);
            goto done;
        }
        if (!BN_nnmod(am, A[k], vss.P_prime, ctx) ||
            !BN_nnmod(bm, B[k], vss.P_prime, ctx) ||
            !BN_mod_exp(ga, vss.g, am, vss.P, ctx) ||
            !BN_mod_exp(hb, vss.h, bm, vss.P, ctx) ||
            !BN_mod_mul(Ck, ga, hb, vss.P, ctx)) {
            BN_free(am); BN_free(bm); BN_free(ga); BN_free(hb); BN_free(Ck);
            goto done;
        }
        bn_to_pad(Ck, static_cast<size_t>(p_bytes),
                  public_out.coefficient_commitments[k]);
        if (k == 0) BN_copy(C0_bn, Ck);
        BN_free(am); BN_free(bm); BN_free(ga); BN_free(hb); BN_free(Ck);
    }

    // Link proof.
    {
        // ds, db in [0, P')
        BIGNUM* ds = BN_new();
        BIGNUM* db = BN_new();
        BIGNUM* T_vss = BN_new();
        BIGNUM* T_paillier = BN_new();
        BIGNUM* e = BN_new();
        BIGNUM* zs = BN_new();
        BIGNUM* zb = BN_new();
        BIGNUM* tmp = BN_new();
        BIGNUM* exp = BN_new();
        BIGNUM* VKi = vec_to_bn(V_K_i_bytes);

        if (!ds || !db || !T_vss || !T_paillier || !e || !zs || !zb ||
            !tmp || !exp || !VKi) {
            BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
            BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
            BN_free(exp); BN_free(VKi);
            goto done;
        }

        if (!BN_rand_range(ds, vss.P_prime) ||
            !BN_rand_range(db, vss.P_prime)) {
            BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
            BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
            BN_free(exp); BN_free(VKi);
            goto done;
        }

        // T_vss = g^(mu*ds) * h^(Delta*db) mod P.
        {
            BIGNUM* mu_mod = BN_new();
            BIGNUM* ds_mod = BN_new();
            BIGNUM* e1_mod = BN_new();
            BIGNUM* e2_mod = BN_new();
            BIGNUM* gpart = BN_new();
            BIGNUM* hpart = BN_new();
            if (!mu_mod || !ds_mod || !e1_mod || !e2_mod || !gpart || !hpart) {
                BN_free(mu_mod); BN_free(ds_mod); BN_free(e1_mod);
                BN_free(e2_mod); BN_free(gpart); BN_free(hpart);
                BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
                BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
                BN_free(exp); BN_free(VKi);
                goto done;
            }
            BN_nnmod(mu_mod, mu, vss.P_prime, ctx);
            BN_nnmod(ds_mod, ds, vss.P_prime, ctx);
            BN_nnmod(e1_mod, exp, vss.P_prime, ctx); // placeholder before set
            BN_mul(e1_mod, mu_mod, ds_mod, ctx);
            BN_nnmod(e1_mod, e1_mod, vss.P_prime, ctx);
            BN_mul(e2_mod, Delta, db, ctx);
            BN_nnmod(e2_mod, e2_mod, vss.P_prime, ctx);
            bool s = BN_mod_exp(gpart, vss.g, e1_mod, vss.P, ctx) == 1 &&
                     BN_mod_exp(hpart, vss.h, e2_mod, vss.P, ctx) == 1 &&
                     BN_mod_mul(T_vss, gpart, hpart, vss.P, ctx) == 1;
            BN_free(mu_mod); BN_free(ds_mod); BN_free(e1_mod);
            BN_free(e2_mod); BN_free(gpart); BN_free(hpart);
            if (!s) {
                BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
                BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
                BN_free(exp); BN_free(VKi);
                goto done;
            }
        }

        // T_paillier = V_K^(Delta*ds) mod N^2.
        if (!BN_mul(exp, Delta, ds, ctx) ||
            !BN_mod_exp(T_paillier, V_K, exp, N2, ctx)) {
            BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
            BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
            BN_free(exp); BN_free(VKi);
            goto done;
        }

        // challenge
        {
            std::vector<uint8_t> ctx_bytes;
            // Bind to config: key_id + epochs + committee ids.
            ctx_bytes.insert(ctx_bytes.end(),
                             cfg.key_id.data, cfg.key_id.data + 32);
            for (int i = 0; i < 8; ++i) ctx_bytes.push_back((cfg.old_epoch >> (8*i)) & 0xff);
            for (int i = 0; i < 8; ++i) ctx_bytes.push_back((cfg.new_epoch >> (8*i)) & 0xff);

            if (!build_link_challenge(vss, mu, C0_bn, VKi, T_vss, T_paillier,
                                      ctx_bytes, e, ctx)) {
                BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
                BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
                BN_free(exp); BN_free(VKi);
                goto done;
            }
        }

        // zs = ds + e*SK  (integer, NOT reduced mod P')
        // zb = db + e*b_raw[0]  (integer, NOT reduced mod P')
        //
        // The Paillier side checks V_K^(Delta*zs) == T_paillier * V_K_i^e
        // in the multiplicative group of Z_{N^2}, whose order is unknown.
        // Reducing zs mod P' would silently invalidate that check.
        // The VSS side reduces mu*zs and Delta*zb internally as needed.
        {
            if (!BN_mul(tmp, e, SK, ctx) || !BN_add(zs, ds, tmp)) {
                BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
                BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
                BN_free(exp); BN_free(VKi);
                goto done;
            }
            if (!BN_mul(tmp, e, b_raw[0], ctx) || !BN_add(zb, db, tmp)) {
                BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
                BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
                BN_free(exp); BN_free(VKi);
                goto done;
            }
        }

        bn_to_pad(T_vss, static_cast<size_t>(p_bytes),
                  public_out.share_link_proof.T_vss);
        bn_to_pad(T_paillier, 512,
                  public_out.share_link_proof.T_paillier);
        // zs, zb are plain integers and may be negative or wider than P'.
        // Variable-length signed encoding.
        bn_to_signed_vec(zs, public_out.share_link_proof.z_share);
        bn_to_signed_vec(zb, public_out.share_link_proof.z_blinding);

        BN_free(ds); BN_free(db); BN_free(T_vss); BN_free(T_paillier);
        BN_free(e); BN_free(zs); BN_free(zb); BN_free(tmp);
        BN_free(exp); BN_free(VKi);
    }

    // Private subshares.
    private_out.clear();
    private_out.reserve(cfg.new_members.size());
    for (size_t j = 0; j < cfg.new_members.size(); ++j) {
        const uint32_t x_j = static_cast<uint32_t>(j + 1);

        BIGNUM* sh = BN_new();
        BIGNUM* bl = BN_new();
        if (!sh || !bl) { BN_free(sh); BN_free(bl); goto done; }

        if (!dao_dkg_reset_evaluate(A, x_j, nullptr, sh, ctx) ||
            !dao_dkg_reset_evaluate(B, x_j, nullptr, bl, ctx)) {
            BN_free(sh); BN_free(bl); goto done;
        }

        dao_reset_private_subshare entry{};
        entry.from_old_member_id = old_member_id;
        entry.to_new_member_id   = static_cast<uint32_t>(j + 1);
        bn_to_signed_vec(sh, entry.subshare);
        bn_to_signed_vec(bl, entry.blinding);
        private_out.push_back(std::move(entry));

        BN_free(sh); BN_free(bl);
    }

    ok = true;

done:
    BN_free(C0_bn);
    for (auto* b : A)     BN_free(b);
    for (auto* b : B)     BN_free(b);
    for (auto* b : a_raw) BN_free(b);
    for (auto* b : b_raw) BN_free(b);
    BN_free(mu); BN_free(SK); BN_CTX_free(ctx);
    return ok;
}

// --------------------------------------------------------------------
// Subshare verification (unchanged relation).
// --------------------------------------------------------------------

bool dao_dkg_reset_verify_subshare(
    const dao_vss_group& vss,
    uint32_t recipient_new_id,
    const std::vector<uint8_t>& subshare,
    const std::vector<uint8_t>& blinding,
    const std::vector<std::vector<uint8_t>>& coefficient_commitments)
{
    if (!vss.valid() || recipient_new_id == 0) return false;
    if (coefficient_commitments.empty()) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;

    BIGNUM* sh = signed_vec_to_bn(subshare);
    BIGNUM* bl = signed_vec_to_bn(blinding);
    BIGNUM* lhs = BN_new();
    BIGNUM* rhs = BN_new();
    BIGNUM* Ck  = BN_new();
    if (!sh || !bl || !lhs || !rhs || !Ck) {
        BN_free(sh); BN_free(bl);
        BN_free(lhs); BN_free(rhs); BN_free(Ck);
        BN_CTX_free(ctx); return false;
    }

    bool ok = false;
    BIGNUM* shm = BN_new();
    BIGNUM* blm = BN_new();
    if (!shm || !blm) goto done;

    if (!BN_nnmod(shm, sh, vss.P_prime, ctx)) goto done;
    if (!BN_nnmod(blm, bl, vss.P_prime, ctx)) goto done;

    {
        BIGNUM* ga = BN_new();
        BIGNUM* hb = BN_new();
        if (!ga || !hb) { BN_free(ga); BN_free(hb); goto done; }
        bool s = BN_mod_exp(ga, vss.g, shm, vss.P, ctx) == 1 &&
                 BN_mod_exp(hb, vss.h, blm, vss.P, ctx) == 1 &&
                 BN_mod_mul(lhs, ga, hb, vss.P, ctx) == 1;
        BN_free(ga); BN_free(hb);
        if (!s) goto done;
    }

    if (!BN_one(rhs)) goto done;
    {
        BIGNUM* xj   = BN_new();
        BIGNUM* xpow = BN_new();
        if (!xj || !xpow) { BN_free(xj); BN_free(xpow); goto done; }
        if (!BN_set_word(xj, recipient_new_id)) {
            BN_free(xj); BN_free(xpow); goto done;
        }
        BN_one(xpow);

        for (size_t k = 0; k < coefficient_commitments.size(); ++k) {
            const auto& ck = coefficient_commitments[k];
            if (ck.empty()) { BN_free(xj); BN_free(xpow); goto done; }
            if (!BN_bin2bn(ck.data(), static_cast<int>(ck.size()), Ck)) {
                BN_free(xj); BN_free(xpow); goto done;
            }
            if (!BN_nnmod(Ck, Ck, vss.P, ctx)) {
                BN_free(xj); BN_free(xpow); goto done;
            }

            BIGNUM* term = BN_new();
            if (!term) { BN_free(xj); BN_free(xpow); goto done; }
            if (!BN_mod_exp(term, Ck, xpow, vss.P, ctx)) {
                BN_free(term); BN_free(xj); BN_free(xpow); goto done;
            }
            if (!BN_mod_mul(rhs, rhs, term, vss.P, ctx)) {
                BN_free(term); BN_free(xj); BN_free(xpow); goto done;
            }
            BN_free(term);

            if (k + 1 < coefficient_commitments.size()) {
                if (!BN_mul(xpow, xpow, xj, ctx) ||
                    !BN_nnmod(xpow, xpow, vss.P_prime, ctx)) {
                    BN_free(xj); BN_free(xpow); goto done;
                }
            }
        }
        BN_free(xj); BN_free(xpow);
    }

    ok = (BN_cmp(lhs, rhs) == 0);

done:
    BN_free(shm); BN_free(blm);
    BN_free(sh); BN_free(bl);
    BN_free(lhs); BN_free(rhs); BN_free(Ck);
    BN_CTX_free(ctx);
    return ok;
}

// --------------------------------------------------------------------
// Link proof verification
// --------------------------------------------------------------------

bool dao_dkg_reset_share_link_verify(
    const dao_vss_group& vss,
    const BIGNUM* N2,
    const BIGNUM* V_K,
    const std::vector<uint8_t>& V_K_i_bytes,
    const BIGNUM* mu,
    const BIGNUM* C0,
    const std::vector<uint8_t>& ctx_bytes,
    const dao_reset_share_link_proof& proof)
{
    if (!vss.valid() || !N2 || !V_K || V_K_i_bytes.empty() || !mu || !C0)
        return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;

    BIGNUM* T_vss = vec_to_bn(proof.T_vss);
    BIGNUM* T_paillier = vec_to_bn(proof.T_paillier);
    BIGNUM* zs = signed_vec_to_bn(proof.z_share);
    BIGNUM* zb = signed_vec_to_bn(proof.z_blinding);
    BIGNUM* VKi = vec_to_bn(V_K_i_bytes);
    BIGNUM* e = BN_new();

    if (!T_vss || !T_paillier || !zs || !zb || !VKi || !e) {
        BN_free(T_vss); BN_free(T_paillier); BN_free(zs); BN_free(zb);
        BN_free(VKi); BN_free(e);
        BN_CTX_free(ctx); return false;
    }

    bool ok = false;

    // challenge
    if (!build_link_challenge(vss, mu, C0, VKi, T_vss, T_paillier,
                              ctx_bytes, e, ctx)) {
        goto done;
    }

    // LHS1 = g^(mu*zs) * h^(Delta*zb) mod P.
    // RHS1 = T_vss * C0^e mod P.
    {
        BIGNUM* mu_mod = BN_new();
        BIGNUM* zs_mod = BN_new();
        BIGNUM* e1 = BN_new();
        BIGNUM* e2 = BN_new();
        BIGNUM* L = BN_new();
        BIGNUM* R = BN_new();
        BIGNUM* t1 = BN_new();
        BIGNUM* t2 = BN_new();
        BIGNUM* t3 = BN_new();
        if (!mu_mod || !zs_mod || !e1 || !e2 || !L || !R ||
            !t1 || !t2 || !t3) {
            BN_free(mu_mod); BN_free(zs_mod); BN_free(e1); BN_free(e2);
            BN_free(L); BN_free(R); BN_free(t1); BN_free(t2); BN_free(t3);
            goto done;
        }
        BN_nnmod(mu_mod, mu, vss.P_prime, ctx);
        BN_nnmod(zs_mod, zs, vss.P_prime, ctx);
        BN_mul(e1, mu_mod, zs_mod, ctx);
        BN_nnmod(e1, e1, vss.P_prime, ctx);
        BN_mul(e2, dao_dkg_delta(), zb, ctx);
        BN_nnmod(e2, e2, vss.P_prime, ctx);

        bool s = BN_mod_exp(t1, vss.g, e1, vss.P, ctx) == 1 &&
                 BN_mod_exp(t2, vss.h, e2, vss.P, ctx) == 1 &&
                 BN_mod_mul(L, t1, t2, vss.P, ctx) == 1 &&
                 BN_mod_exp(t3, C0, e, vss.P, ctx) == 1 &&
                 BN_mod_mul(R, T_vss, t3, vss.P, ctx) == 1;
        bool eq1 = s && BN_cmp(L, R) == 0;
        BN_free(mu_mod); BN_free(zs_mod); BN_free(e1); BN_free(e2);
        BN_free(L); BN_free(R); BN_free(t1); BN_free(t2); BN_free(t3);
        if (!eq1) goto done;
    }

    // LHS2 = V_K^(Delta*zs) mod N^2.  (zs is the integer ds + e*SK.)
    // RHS2 = T_paillier * V_K_i^e mod N^2.
    {
        BIGNUM* exp = BN_new();
        BIGNUM* L = BN_new();
        BIGNUM* t = BN_new();
        if (!exp || !L || !t) {
            BN_free(exp); BN_free(L); BN_free(t);
            goto done;
        }
        BN_mul(exp, dao_dkg_delta(), zs, ctx);
        bool base_ok;
        BIGNUM* base = BN_new();
        if (!base) { BN_free(exp); BN_free(L); BN_free(t); goto done; }
        if (BN_is_negative(exp)) {
            BN_set_negative(exp, 0);
            base_ok = BN_mod_inverse(base, V_K, N2, ctx) != nullptr;
        } else {
            base_ok = BN_copy(base, V_K) != nullptr;
        }
        bool s = base_ok &&
                 BN_mod_exp(L, base, exp, N2, ctx) == 1 &&
                 BN_mod_exp(t, VKi, e, N2, ctx) == 1;
        BN_free(base);
        if (s) {
            BIGNUM* R = BN_new();
            if (!R) { BN_free(exp); BN_free(L); BN_free(t); goto done; }
            s = BN_mod_mul(R, T_paillier, t, N2, ctx) == 1 &&
                BN_cmp(L, R) == 0;
            if (!s) {
            }
            BN_free(R);
        }
        BN_free(exp); BN_free(L); BN_free(t);
        if (!s) goto done;
    }

    ok = true;

done:
    BN_free(T_vss); BN_free(T_paillier); BN_free(zs); BN_free(zb);
    BN_free(VKi); BN_free(e);
    BN_CTX_free(ctx);
    return ok;
}

// --------------------------------------------------------------------
// Reset acceptance
// --------------------------------------------------------------------

bool dao_dkg_reset_accept(
    const dao_dkg_reset_config& cfg,
    uint32_t self_new_id,
    const std::vector<dao_reset_public_contribution>& publics,
    const std::vector<dao_reset_private_subshare>& my_subshares,
    const dao_vss_group& vss,
    const BIGNUM* N2,
    const BIGNUM* V_K,
    const std::vector<std::vector<uint8_t>>& old_vk_i_list,
    std::vector<uint8_t>& new_share_out)
{
    if (!vss.valid() || !N2 || !V_K) return false;
    if (self_new_id == 0) return false;
    if (publics.empty()) return false;
    if (old_vk_i_list.size() != cfg.old_members.size()) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;
    const BIGNUM* Delta = dao_dkg_delta();

    std::vector<uint32_t> old_ids;
    for (size_t i = 0; i < cfg.old_members.size(); ++i)
        old_ids.push_back(static_cast<uint32_t>(i + 1));

    BIGNUM* sum_h = BN_new();
    if (!sum_h) { BN_CTX_free(ctx); return false; }
    BN_zero(sum_h);

    bool ok = false;
    size_t matched = 0;

    for (const auto& pub : publics) {
        const std::vector<uint8_t>* vk_i = nullptr;
        for (size_t i = 0; i < old_ids.size(); ++i) {
            if (old_ids[i] == pub.old_member_id) {
                vk_i = &old_vk_i_list[i];
                break;
            }
        }
        if (!vk_i) goto done;

        BIGNUM* mu = BN_new();
        if (!mu || !dao_dkg_lagrange_mu(old_ids, pub.old_member_id, mu)) {
            BN_free(mu); goto done;
        }

        if (pub.coefficient_commitments.empty()) { BN_free(mu); goto done; }
        BIGNUM* C0 = vec_to_bn(pub.coefficient_commitments[0]);
        if (!C0) { BN_free(mu); goto done; }

        std::vector<uint8_t> ctx_bytes;
        ctx_bytes.insert(ctx_bytes.end(),
                         cfg.key_id.data, cfg.key_id.data + 32);
        for (int i = 0; i < 8; ++i)
            ctx_bytes.push_back((cfg.old_epoch >> (8*i)) & 0xff);
        for (int i = 0; i < 8; ++i)
            ctx_bytes.push_back((cfg.new_epoch >> (8*i)) & 0xff);

        bool proof_ok = dao_dkg_reset_share_link_verify(
            vss, N2, V_K, *vk_i, mu, C0, ctx_bytes, pub.share_link_proof);
        BN_free(mu); BN_free(C0);
        if (!proof_ok) goto done;

        const dao_reset_private_subshare* mine = nullptr;
        for (const auto& ss : my_subshares) {
            if (ss.from_old_member_id == pub.old_member_id &&
                ss.to_new_member_id   == self_new_id) {
                mine = &ss; break;
            }
        }
        if (!mine) goto done;

        if (!dao_dkg_reset_verify_subshare(
                vss, self_new_id, mine->subshare, mine->blinding,
                pub.coefficient_commitments)) {
            goto done;
        }

        BIGNUM* h = signed_vec_to_bn(mine->subshare);
        if (!h) goto done;
        if (!BN_add(sum_h, sum_h, h)) { BN_free(h); goto done; }
        BN_free(h);
        ++matched;
    }

    if (matched != publics.size()) goto done;

    {
        BIGNUM* rem = BN_new();
        BIGNUM* sd  = BN_new();
        if (!rem || !sd) {
            BN_free(rem); BN_free(sd); goto done;
        }
        if (!BN_div(sd, rem, sum_h, Delta, ctx) || !BN_is_zero(rem)) {
            BN_free(rem); BN_free(sd); goto done;
        }
        bn_to_signed_vec(sd, new_share_out);
        BN_free(rem); BN_free(sd);
    }

    ok = true;

done:
    BN_free(sum_h);
    BN_CTX_free(ctx);
    return ok;
}


// --------------------------------------------------------------------
// Integer-only ceremony (no Pedersen, no proof) — used by the arithmetic
// regression tests.
// --------------------------------------------------------------------

bool dao_dkg_reset_evaluate(
    const std::vector<BIGNUM*>& coeffs,
    uint32_t x,
    const BIGNUM* field_modulus,
    BIGNUM* out,
    BN_CTX* ctx)
{
    if (coeffs.empty() || !out || !ctx) return false;
    BIGNUM* xb  = BN_new();
    BIGNUM* acc = BN_new();
    if (!xb || !acc) { BN_free(xb); BN_free(acc); return false; }
    bool ok = false;
    if (!BN_set_word(xb, x)) goto done;
    BN_zero(acc);
    for (size_t k = coeffs.size(); k-- > 0; ) {
        if (!coeffs[k]) goto done;
        if (!BN_mul(acc, acc, xb, ctx)) goto done;
        if (!BN_add(acc, acc, coeffs[k])) goto done;
        if (field_modulus && !BN_is_zero(field_modulus)) {
            if (!BN_mod(acc, acc, field_modulus, ctx)) goto done;
        }
    }
    if (!BN_copy(out, acc)) goto done;
    ok = true;
done:
    BN_free(xb); BN_free(acc);
    return ok;
}

bool dao_dkg_reset_full_ceremony(
    const dao_dkg_reset_config& cfg,
    const std::vector<std::vector<uint8_t>>& all_old_shares,
    const std::vector<uint8_t>& field_modulus_bytes,
    std::vector<std::vector<uint8_t>>& new_shares_out)
{
    (void)field_modulus_bytes;
    if (all_old_shares.size() != cfg.old_members.size()) return false;
    if (cfg.old_members.empty() || cfg.new_members.empty()) return false;
    if (cfg.new_threshold < 1) return false;
    if (cfg.new_threshold > cfg.new_members.size()) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;
    const BIGNUM* Delta = dao_dkg_delta();

    std::vector<uint32_t> old_ids;
    for (size_t i = 0; i < cfg.old_members.size(); ++i)
        old_ids.push_back(static_cast<uint32_t>(i + 1));

    std::vector<BIGNUM*> old_shares(cfg.old_members.size(), nullptr);
    for (size_t i = 0; i < all_old_shares.size(); ++i) {
        old_shares[i] = vec_to_bn(all_old_shares[i]);
        if (!old_shares[i]) goto done_ceremony;
    }

    {
        const uint32_t new_deg = cfg.new_threshold - 1;
        std::vector<std::vector<BIGNUM*>> H(cfg.old_members.size());

        for (size_t l = 0; l < cfg.old_members.size(); ++l) {
            H[l].assign(new_deg + 1, nullptr);
            BIGNUM* mu_l = BN_new();
            if (!mu_l) goto done_ceremony;
            if (!dao_dkg_lagrange_mu(old_ids,
                                     static_cast<uint32_t>(l + 1),
                                     mu_l)) {
                BN_free(mu_l); goto done_ceremony;
            }
            H[l][0] = BN_new();
            if (!H[l][0]) { BN_free(mu_l); goto done_ceremony; }
            if (!BN_mul(H[l][0], mu_l, old_shares[l], ctx)) {
                BN_free(mu_l); goto done_ceremony;
            }
            BN_free(mu_l);
            for (uint32_t k = 1; k <= new_deg; ++k) {
                BIGNUM* upper = BN_new();
                BIGNUM* b = BN_new();
                H[l][k] = BN_new();
                if (!upper || !b || !H[l][k]) {
                    BN_free(upper); BN_free(b); goto done_ceremony;
                }
                BN_set_bit(upper, 128);
                if (!BN_rand_range(b, upper)) {
                    BN_free(upper); BN_free(b); goto done_ceremony;
                }
                if (!BN_mul(H[l][k], b, Delta, ctx)) {
                    BN_free(upper); BN_free(b); goto done_ceremony;
                }
                BN_free(upper); BN_free(b);
            }
        }

        new_shares_out.assign(cfg.new_members.size(), {});
        for (size_t j = 0; j < cfg.new_members.size(); ++j) {
            const uint32_t x_j = static_cast<uint32_t>(j + 1);
            BIGNUM* sum = BN_new();
            if (!sum) goto done_ceremony;
            BN_zero(sum);
            for (size_t l = 0; l < H.size(); ++l) {
                BIGNUM* eval = BN_new();
                if (!eval) { BN_free(sum); goto done_ceremony; }
                if (!dao_dkg_reset_evaluate(H[l], x_j, nullptr, eval, ctx)) {
                    BN_free(eval); BN_free(sum); goto done_ceremony;
                }
                if (!BN_add(sum, sum, eval)) {
                    BN_free(eval); BN_free(sum); goto done_ceremony;
                }
                BN_free(eval);
            }
            BIGNUM* rem = BN_new();
            BIGNUM* sdp = BN_new();
            if (!rem || !sdp) {
                BN_free(rem); BN_free(sdp); BN_free(sum); goto done_ceremony;
            }
            if (!BN_div(sdp, rem, sum, Delta, ctx) || !BN_is_zero(rem)) {
                BN_free(rem); BN_free(sdp); BN_free(sum); goto done_ceremony;
            }
            BN_free(rem);
            bn_to_vec(sdp, new_shares_out[j]);
            BN_free(sdp); BN_free(sum);
        }
        for (auto& v : H) for (auto* b : v) BN_free(b);
    }

    for (auto* b : old_shares) BN_free(b);
    BN_CTX_free(ctx);
    return true;

done_ceremony:
    for (auto* b : old_shares) BN_free(b);
    BN_CTX_free(ctx);
    return false;
}

bool dao_dkg_reset(
    const dao_dkg_reset_config& cfg,
    const std::vector<uint8_t>& local_old_share,
    const dao_tally_public_key_record& public_key,
    dao_dkg_reset_result& result)
{
    (void)cfg; (void)local_old_share; (void)public_key;
    result = dao_dkg_reset_result{};
    return false;
}

} // namespace dao
} // namespace cryptonote
