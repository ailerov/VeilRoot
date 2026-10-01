// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_threshold.h"

#include <cstring>

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

// Modular exponentiation with support for a signed exponent.
// Negative exponent: base is inverted mod modulus first.
bool modexp_signed(const BIGNUM* base, const BIGNUM* exp_signed,
                   const BIGNUM* modulus, BIGNUM* out)
{
    if (!base || !exp_signed || !modulus || !out) return false;
    CtxGuard g;
    if (!g.ok()) return false;

    if (!BN_is_negative(exp_signed)) {
        return BN_mod_exp(out, base, exp_signed, modulus, g.ctx) == 1;
    }

    BIGNUM* base_inv = BN_mod_inverse(nullptr, base, modulus, g.ctx);
    if (!base_inv) return false;

    BIGNUM* pos_exp = BN_dup(exp_signed);
    if (!pos_exp) { BN_free(base_inv); return false; }
    BN_set_negative(pos_exp, 0);

    const bool ok = BN_mod_exp(out, base_inv, pos_exp, modulus, g.ctx) == 1;
    BN_free(base_inv);
    BN_free(pos_exp);
    return ok;
}

// Inverse of `a` modulo `n`, handling a negative `a` by tracking sign.
// Result is normalized to [0, n).
bool inverse_mod_signed(const BIGNUM* a, const BIGNUM* n,
                        BIGNUM* out, BN_CTX* ctx)
{
    BIGNUM* abs_a = BN_dup(a);
    if (!abs_a) return false;
    BN_set_negative(abs_a, 0);

    BIGNUM* inv = BN_mod_inverse(nullptr, abs_a, n, ctx);
    BN_free(abs_a);
    if (!inv) return false;

    if (BN_is_negative(a)) BN_set_negative(inv, 1);
    BN_nnmod(out, inv, n, ctx);
    BN_free(inv);
    return true;
}

} // anonymous namespace

const BIGNUM* dao_dkg_delta()
{
    static BIGNUM* delta = []() -> BIGNUM* {
        BIGNUM* d = BN_new();
        if (d) BN_dec2bn(&d, "20922789888000");  // 16!
        return d;
    }();
    return delta;
}

bool dao_dkg_lagrange_mu(const std::vector<uint32_t>& subset,
                         uint32_t i,
                         BIGNUM* mu_out)
{
    if (!mu_out) return false;
    if (subset.size() < 2) return false;

    bool found = false;
    for (uint32_t s : subset) if (s == i) { found = true; break; }
    if (!found) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* num = BN_dup(dao_dkg_delta());
    BIGNUM* den = BN_new();
    if (!num || !den) { BN_free(num); BN_free(den); return false; }

    bool ok = false;
    do {
        if (!BN_one(den)) break;

        bool step_ok = true;
        for (uint32_t j : subset) {
            if (j == i) continue;

            // num *= -j
            BIGNUM* bj = BN_new();
            if (!bj) { step_ok = false; break; }
            if (!BN_set_word(bj, j) ||
                !BN_mul(num, num, bj, g.ctx)) {
                BN_free(bj); step_ok = false; break;
            }
            BN_free(bj);
            BN_set_negative(num, !BN_is_negative(num));

            // den *= (i - j)
            BIGNUM* diff = BN_new();
            if (!diff) { step_ok = false; break; }
            if (!BN_set_word(diff, i)) { BN_free(diff); step_ok = false; break; }
            BIGNUM* bj2 = BN_new();
            if (!bj2) { BN_free(diff); step_ok = false; break; }
            if (!BN_set_word(bj2, j) || !BN_sub(diff, diff, bj2) ||
                !BN_mul(den, den, diff, g.ctx)) {
                BN_free(diff); BN_free(bj2); step_ok = false; break;
            }
            BN_free(diff); BN_free(bj2);
        }
        if (!step_ok) break;

        BIGNUM* rem = BN_new();
        if (!rem) break;
        if (!BN_div(mu_out, rem, num, den, g.ctx)) {
            BN_free(rem); break;
        }
        ok = BN_is_zero(rem);
        BN_free(rem);
    } while (false);

    BN_free(num);
    BN_free(den);
    return ok;
}

bool dao_threshold_partial_decrypt(const PaillierPublicKey& pk,
                                   const std::vector<uint8_t>& c_bytes,
                                   const BIGNUM* share,
                                   std::vector<uint8_t>& c_i_out)
{
    if (!pk.valid()) return false;
    if (c_bytes.size() != PAILLIER_CT_BYTES) return false;
    if (!share) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* c = BN_bin2bn(c_bytes.data(),
                          static_cast<int>(c_bytes.size()), nullptr);
    if (!c) return false;

    BIGNUM* exp = BN_new();
    BIGNUM* result = BN_new();
    bool ok = false;

    do {
        if (!exp || !result) break;
        if (!BN_copy(exp, share)) break;
        if (!BN_mul(exp, exp, dao_dkg_delta(), g.ctx)) break;
        if (!BN_lshift(exp, exp, 1)) break;   // * 2

        if (!modexp_signed(c, exp, pk.N2(), result)) break;

        c_i_out.assign(PAILLIER_CT_BYTES, 0);
        const int n = BN_bn2binpad(result, c_i_out.data(),
                                   static_cast<int>(PAILLIER_CT_BYTES));
        if (n != static_cast<int>(PAILLIER_CT_BYTES)) {
            c_i_out.clear();
            break;
        }
        ok = true;
    } while (false);

    BN_free(c);
    BN_clear_free(exp);
    BN_free(result);
    return ok;
}

bool dao_threshold_combine(const PaillierPublicKey& pk,
                           const std::vector<uint32_t>& subset,
                           const std::vector<std::vector<uint8_t>>& partials,
                           uint32_t threshold,
                           std::vector<uint8_t>& C_out)
{
    if (!pk.valid()) return false;
    if (subset.size() != partials.size()) return false;
    if (threshold == 0) return false;
    if (subset.size() < threshold) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* C = BN_new();
    if (!C) return false;
    if (!BN_one(C)) { BN_free(C); return false; }

    bool ok = true;
    for (size_t k = 0; k < subset.size() && ok; ++k) {
        const uint32_t i = subset[k];
        const auto& p = partials[k];
        if (p.size() != PAILLIER_CT_BYTES) { ok = false; break; }

        BIGNUM* c_i = BN_bin2bn(p.data(),
                                static_cast<int>(p.size()), nullptr);
        BIGNUM* mu  = BN_new();
        BIGNUM* exp = BN_new();
        BIGNUM* term = BN_new();

        if (!c_i || !mu || !exp || !term) {
            BN_free(c_i); BN_free(mu); BN_free(exp); BN_free(term);
            ok = false; break;
        }

        bool step = true;
        step = step && dao_dkg_lagrange_mu(subset, i, mu);
        step = step && BN_copy(exp, mu);
        step = step && BN_lshift(exp, exp, 1);     // * 2
        step = step && modexp_signed(c_i, exp, pk.N2(), term);
        step = step && BN_mod_mul(C, C, term, pk.N2(), g.ctx);

        BN_free(c_i); BN_free(mu); BN_free(exp); BN_free(term);
        ok = step;
    }

    if (ok) {
        C_out.assign(PAILLIER_CT_BYTES, 0);
        const int n = BN_bn2binpad(C, C_out.data(),
                                   static_cast<int>(PAILLIER_CT_BYTES));
        if (n != static_cast<int>(PAILLIER_CT_BYTES)) {
            C_out.clear();
            ok = false;
        }
    }

    BN_free(C);
    return ok;
}

bool dao_threshold_finalize(const PaillierPublicKey& pk,
                            const std::vector<uint8_t>& C_bytes,
                            const BIGNUM* theta_prime,
                            BIGNUM* m_out)
{
    if (!pk.valid() || !theta_prime || !m_out) return false;
    if (C_bytes.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* C        = BN_bin2bn(C_bytes.data(),
                                 static_cast<int>(C_bytes.size()), nullptr);
    BIGNUM* L        = BN_new();
    BIGNUM* D2       = BN_new();
    BIGNUM* four_D2  = BN_new();
    BIGNUM* coeff    = BN_new();
    BIGNUM* coeff_inv = BN_new();
    BIGNUM* tmp      = BN_new();

    bool ok = false;
    do {
        if (!C || !L || !D2 || !four_D2 || !coeff || !coeff_inv || !tmp) break;

        // L = (C - 1) / N
        if (!BN_sub(L, C, BN_value_one())) break;
        if (!BN_div(L, nullptr, L, pk.N(), g.ctx)) break;

        // coeff = -4 * Delta^2 * theta'
        if (!BN_copy(D2, dao_dkg_delta())) break;
        if (!BN_sqr(D2, D2, g.ctx)) break;
        if (!BN_lshift(four_D2, D2, 2)) break;    // * 4
        if (!BN_mul(coeff, four_D2, theta_prime, g.ctx)) break;
        BN_set_negative(coeff, 1);

        // coeff_inv = coeff^{-1} mod N, sign-tracked.
        if (!inverse_mod_signed(coeff, pk.N(), coeff_inv, g.ctx)) break;

        // M = L * coeff_inv mod N
        if (!BN_mod_mul(tmp, L, coeff_inv, pk.N(), g.ctx)) break;
        if (!BN_copy(m_out, tmp)) break;
        ok = true;
    } while (false);

    BN_free(C);
    BN_free(L);
    BN_free(D2);
    BN_free(four_D2);
    BN_free(coeff);
    BN_free(coeff_inv);
    BN_free(tmp);
    return ok;
}

} // namespace dao
} // namespace cryptonote