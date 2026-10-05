// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_dkg_reset.h"

#include <openssl/rand.h>
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

} // anonymous namespace

bool dao_dkg_reset_compute_lambda(
    const std::vector<uint32_t>& old_ids,
    uint32_t member_id,
    const BIGNUM* field_modulus,
    BIGNUM* lambda_out)
{
    (void)field_modulus;
    return dao_dkg_lagrange_mu(old_ids, member_id, lambda_out);
}

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
    BN_free(xb);
    BN_free(acc);
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
    old_ids.reserve(cfg.old_members.size());
    for (size_t i = 0; i < cfg.old_members.size(); ++i)
        old_ids.push_back(static_cast<uint32_t>(i + 1));

    std::vector<BIGNUM*> old_shares(cfg.old_members.size(), nullptr);
    for (size_t i = 0; i < all_old_shares.size(); ++i) {
        old_shares[i] = vec_to_bn(all_old_shares[i]);
        if (!old_shares[i]) goto fail;
    }

    {
        const uint32_t new_deg = cfg.new_threshold - 1;
        std::vector<std::vector<BIGNUM*>> H(cfg.old_members.size());

        for (size_t l = 0; l < cfg.old_members.size(); ++l) {
            H[l].assign(new_deg + 1, nullptr);

            BIGNUM* mu_l = BN_new();
            if (!mu_l) goto fail_inner;
            if (!dao_dkg_reset_compute_lambda(old_ids,
                                              static_cast<uint32_t>(l + 1),
                                              nullptr, mu_l)) {
                BN_free(mu_l); goto fail_inner;
            }

            H[l][0] = BN_new();
            if (!H[l][0]) { BN_free(mu_l); goto fail_inner; }
            if (!BN_mul(H[l][0], mu_l, old_shares[l], ctx)) {
                BN_free(mu_l); goto fail_inner;
            }
            BN_free(mu_l);

            for (uint32_t k = 1; k <= new_deg; ++k) {
                BIGNUM* upper = BN_new();
                BIGNUM* b = BN_new();
                H[l][k] = BN_new();
                if (!upper || !b || !H[l][k]) {
                    BN_free(upper); BN_free(b); goto fail_inner;
                }
                BN_set_bit(upper, 128);
                if (!BN_rand_range(b, upper)) {
                    BN_free(upper); BN_free(b); goto fail_inner;
                }
                if (!BN_mul(H[l][k], b, Delta, ctx)) {
                    BN_free(upper); BN_free(b); goto fail_inner;
                }
                BN_free(upper); BN_free(b);
            }
        }

        new_shares_out.assign(cfg.new_members.size(), {});

        for (size_t j = 0; j < cfg.new_members.size(); ++j) {
            const uint32_t x_j = static_cast<uint32_t>(j + 1);

            BIGNUM* sum = BN_new();
            if (!sum) goto fail_inner;
            BN_zero(sum);

            for (size_t l = 0; l < H.size(); ++l) {
                BIGNUM* eval = BN_new();
                if (!eval) { BN_free(sum); goto fail_inner; }
                if (!dao_dkg_reset_evaluate(H[l], x_j, nullptr, eval, ctx)) {
                    BN_free(eval); BN_free(sum); goto fail_inner;
                }
                if (!BN_add(sum, sum, eval)) {
                    BN_free(eval); BN_free(sum); goto fail_inner;
                }
                BN_free(eval);
            }

            BIGNUM* rem = BN_new();
            BIGNUM* sdp = BN_new();
            if (!rem || !sdp) {
                BN_free(rem); BN_free(sdp); BN_free(sum); goto fail_inner;
            }
            if (!BN_div(sdp, rem, sum, Delta, ctx) || !BN_is_zero(rem)) {
                BN_free(rem); BN_free(sdp); BN_free(sum); goto fail_inner;
            }
            BN_free(rem);
            bn_to_vec(sdp, new_shares_out[j]);
            BN_free(sdp);
            BN_free(sum);
        }

        for (auto& v : H) for (auto* b : v) BN_free(b);
    }

    for (auto* b : old_shares) BN_free(b);
    BN_CTX_free(ctx);
    return true;

fail_inner:
fail:
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
    (void)cfg;
    (void)local_old_share;
    (void)public_key;
    result = dao_dkg_reset_result{};
    return false;
}

// --------------------------------------------------------------------
// Pedersen-verified Reset
// --------------------------------------------------------------------

bool dao_dkg_reset_generate_contribution(
    const dao_dkg_reset_config& cfg,
    uint32_t old_member_id,
    const std::vector<uint8_t>& local_old_share,
    const dao_vss_group& vss,
    dao_reset_public_contribution& public_out,
    std::vector<dao_reset_private_subshare>& private_out)
{
    if (!vss.valid()) return false;
    if (cfg.new_threshold < 1) return false;
    if (cfg.new_threshold > cfg.new_members.size()) return false;
    if (old_member_id == 0) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;
    const BIGNUM* Delta = dao_dkg_delta();

    std::vector<uint32_t> old_ids;
    old_ids.reserve(cfg.old_members.size());
    for (size_t i = 0; i < cfg.old_members.size(); ++i)
        old_ids.push_back(static_cast<uint32_t>(i + 1));

    BIGNUM* sigma = signed_vec_to_bn(local_old_share);
    if (!sigma) { BN_CTX_free(ctx); return false; }

    BIGNUM* mu = BN_new();
    if (!mu || !dao_dkg_lagrange_mu(old_ids, old_member_id, mu)) {
        BN_free(mu); BN_free(sigma); BN_CTX_free(ctx); return false;
    }

    const uint32_t deg = cfg.new_threshold - 1;
    std::vector<BIGNUM*> a(deg + 1, nullptr);
    std::vector<BIGNUM*> b(deg + 1, nullptr);
    for (uint32_t k = 0; k <= deg; ++k) {
        a[k] = BN_new();
        b[k] = BN_new();
        if (!a[k] || !b[k]) goto fail_coeffs;
    }

    if (!BN_mul(a[0], mu, sigma, ctx)) goto fail_coeffs;

    for (uint32_t k = 1; k <= deg; ++k) {
        BIGNUM* upper = BN_new();
        BIGNUM* rk    = BN_new();
        if (!upper || !rk) { BN_free(upper); BN_free(rk); goto fail_coeffs; }
        BN_set_bit(upper, 128);
        if (!BN_rand_range(rk, upper)) {
            BN_free(upper); BN_free(rk); goto fail_coeffs;
        }
        if (!BN_mul(a[k], rk, Delta, ctx)) {
            BN_free(upper); BN_free(rk); goto fail_coeffs;
        }
        BN_free(upper); BN_free(rk);
    }

    for (uint32_t k = 0; k <= deg; ++k) {
        BIGNUM* upper = BN_new();
        if (!upper) goto fail_coeffs;
        BN_set_bit(upper, 128);
        if (!BN_rand_range(b[k], upper)) {
            BN_free(upper); goto fail_coeffs;
        }
        BN_free(upper);
    }

    public_out = dao_reset_public_contribution{};
    public_out.old_member_id = old_member_id;
    public_out.coefficient_commitments.assign(deg + 1, {});

    for (uint32_t k = 0; k <= deg; ++k) {
        BIGNUM* a_mod = BN_new();
        BIGNUM* b_mod = BN_new();
        BIGNUM* ga    = BN_new();
        BIGNUM* hb    = BN_new();
        BIGNUM* Ck    = BN_new();
        if (!a_mod || !b_mod || !ga || !hb || !Ck) {
            BN_free(a_mod); BN_free(b_mod); BN_free(ga); BN_free(hb); BN_free(Ck);
            goto fail_coeffs;
        }
        if (!BN_nnmod(a_mod, a[k], vss.P_prime, ctx) ||
            !BN_nnmod(b_mod, b[k], vss.P_prime, ctx) ||
            !BN_mod_exp(ga, vss.g, a_mod, vss.P, ctx) ||
            !BN_mod_exp(hb, vss.h, b_mod, vss.P, ctx) ||
            !BN_mod_mul(Ck, ga, hb, vss.P, ctx)) {
            BN_free(a_mod); BN_free(b_mod); BN_free(ga); BN_free(hb); BN_free(Ck);
            goto fail_coeffs;
        }

        const int p_bytes = BN_num_bytes(vss.P);
        auto& slot = public_out.coefficient_commitments[k];
        slot.assign(static_cast<size_t>(p_bytes), 0);
        BN_bn2binpad(Ck, slot.data(), p_bytes);

        BN_free(a_mod); BN_free(b_mod); BN_free(ga); BN_free(hb); BN_free(Ck);
    }

    private_out.clear();
    private_out.reserve(cfg.new_members.size());
    for (size_t j = 0; j < cfg.new_members.size(); ++j) {
        const uint32_t x_j = static_cast<uint32_t>(j + 1);

        BIGNUM* sh = BN_new();
        BIGNUM* bl = BN_new();
        if (!sh || !bl) { BN_free(sh); BN_free(bl); goto fail_coeffs; }

        if (!dao_dkg_reset_evaluate(a, x_j, nullptr, sh, ctx) ||
            !dao_dkg_reset_evaluate(b, x_j, nullptr, bl, ctx)) {
            BN_free(sh); BN_free(bl); goto fail_coeffs;
        }

        dao_reset_private_subshare entry{};
        entry.from_old_member_id = old_member_id;
        entry.to_new_member_id   = static_cast<uint32_t>(j + 1);
        bn_to_signed_vec(sh, entry.subshare);
        bn_to_signed_vec(bl, entry.blinding);
        private_out.push_back(std::move(entry));

        BN_free(sh); BN_free(bl);
    }

    for (uint32_t k = 0; k <= deg; ++k) { BN_free(a[k]); BN_free(b[k]); }
    BN_free(mu); BN_free(sigma); BN_CTX_free(ctx);
    return true;

fail_coeffs:
    for (uint32_t k = 0; k <= deg; ++k) { BN_free(a[k]); BN_free(b[k]); }
    BN_free(mu); BN_free(sigma); BN_CTX_free(ctx);
    return false;
}

bool dao_dkg_reset_verify_subshare(
    const dao_vss_group& vss,
    uint32_t recipient_new_id,
    const std::vector<uint8_t>& subshare,
    const std::vector<uint8_t>& blinding,
    const std::vector<std::vector<uint8_t>>& coefficient_commitments)
{
    if (!vss.valid()) return false;
    if (recipient_new_id == 0) return false;
    if (coefficient_commitments.empty()) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;

    BIGNUM* sh = signed_vec_to_bn(subshare);
    BIGNUM* bl = signed_vec_to_bn(blinding);
    if (!sh || !bl) {
        BN_free(sh); BN_free(bl); BN_CTX_free(ctx); return false;
    }

    BIGNUM* sh_mod = BN_new();
    BIGNUM* bl_mod = BN_new();
    BIGNUM* lhs    = BN_new();
    BIGNUM* rhs    = BN_new();
    BIGNUM* Ck     = BN_new();
    if (!sh_mod || !bl_mod || !lhs || !rhs || !Ck) {
        BN_free(sh); BN_free(bl);
        BN_free(sh_mod); BN_free(bl_mod); BN_free(lhs); BN_free(rhs); BN_free(Ck);
        BN_CTX_free(ctx);
        return false;
    }

    bool ok = false;

    if (!BN_nnmod(sh_mod, sh, vss.P_prime, ctx)) goto done;
    if (!BN_nnmod(bl_mod, bl, vss.P_prime, ctx)) goto done;

    {
        BIGNUM* ga = BN_new();
        BIGNUM* hb = BN_new();
        if (!ga || !hb) { BN_free(ga); BN_free(hb); goto done; }
        bool s = BN_mod_exp(ga, vss.g, sh_mod, vss.P, ctx) == 1 &&
                 BN_mod_exp(hb, vss.h, bl_mod, vss.P, ctx) == 1 &&
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
        BN_one(xpow);   // x^0

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
    BN_free(sh); BN_free(bl);
    BN_free(sh_mod); BN_free(bl_mod); BN_free(lhs); BN_free(rhs); BN_free(Ck);
    BN_CTX_free(ctx);
    return ok;
}

bool dao_dkg_reset_accept(
    const dao_dkg_reset_config& cfg,
    uint32_t self_new_id,
    const std::vector<dao_reset_public_contribution>& publics,
    const std::vector<dao_reset_private_subshare>& my_subshares,
    const dao_vss_group& vss,
    std::vector<uint8_t>& new_share_out)
{
    (void)cfg;
    if (!vss.valid()) return false;
    if (self_new_id == 0) return false;
    if (publics.empty()) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;
    const BIGNUM* Delta = dao_dkg_delta();

    BIGNUM* sum_h = BN_new();
    if (!sum_h) { BN_CTX_free(ctx); return false; }
    BN_zero(sum_h);

    size_t matched = 0;
    for (const auto& pub : publics) {
        const dao_reset_private_subshare* mine = nullptr;
        for (const auto& ss : my_subshares) {
            if (ss.from_old_member_id == pub.old_member_id &&
                ss.to_new_member_id   == self_new_id) {
                mine = &ss; break;
            }
        }
        if (!mine) { BN_free(sum_h); BN_CTX_free(ctx); return false; }

        if (!dao_dkg_reset_verify_subshare(
                vss, self_new_id, mine->subshare, mine->blinding,
                pub.coefficient_commitments)) {
            BN_free(sum_h); BN_CTX_free(ctx); return false;
        }

        BIGNUM* h = signed_vec_to_bn(mine->subshare);
        if (!h) { BN_free(sum_h); BN_CTX_free(ctx); return false; }
        if (!BN_add(sum_h, sum_h, h)) {
            BN_free(h); BN_free(sum_h); BN_CTX_free(ctx); return false;
        }
        BN_free(h);
        ++matched;
    }

    if (matched != publics.size()) {
        BN_free(sum_h); BN_CTX_free(ctx); return false;
    }

    BIGNUM* rem = BN_new();
    BIGNUM* sd  = BN_new();
    if (!rem || !sd) {
        BN_free(rem); BN_free(sd); BN_free(sum_h); BN_CTX_free(ctx); return false;
    }

    if (!BN_div(sd, rem, sum_h, Delta, ctx) || !BN_is_zero(rem)) {
        BN_free(rem); BN_free(sd); BN_free(sum_h); BN_CTX_free(ctx); return false;
    }

    bn_to_signed_vec(sd, new_share_out);
    BN_free(rem); BN_free(sd); BN_free(sum_h); BN_CTX_free(ctx);

    // TODO(bootstrap-continuity): verify aggregate C_0 commits to Delta*SK(0)
    // once the bootstrap DKG exposes its aggregate VSS commitment.
    return true;
}

} // namespace dao
} // namespace cryptonote
