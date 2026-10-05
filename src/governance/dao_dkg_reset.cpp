// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_dkg_reset.h"
#include "governance/dao_threshold.h"

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

} // anonymous namespace

bool dao_dkg_reset_compute_lambda(
    const std::vector<uint32_t>& old_ids,
    uint32_t member_id,
    const BIGNUM* field_modulus,
    BIGNUM* lambda_out)
{
    // Integer Delta-scaled Lagrange at 0:
    //   mu_i = Delta * prod_{u != i} (-u) / (i - u)
    // Same construction as dao_dkg_lagrange_mu (which uses dao_dkg_delta).
    // field_modulus is unused for the integer Lagrange; parameter kept for
    // API stability.
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
    (void)field_modulus_bytes;  // integer construction ignores it

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

        // Build h_l for each old shareholder.
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
                BN_set_bit(upper, 128);            // b in [0, 2^128)
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

} // namespace dao
} // namespace cryptonote
