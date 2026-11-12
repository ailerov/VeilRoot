#include "dao_mpc_crt.h"
#include <openssl/bn.h>

namespace cryptonote { namespace dao {

bool dao_mpc_crt::sieved_primes(uint32_t B, std::vector<uint32_t>& out)


{
    out.clear();
    if (B < 3) return true;
    std::vector<bool> is_p(B, true);
    if (B > 0) is_p[0] = false;
    if (B > 1) is_p[1] = false;
    for (uint32_t p = 2; (uint64_t)p * p < B; ++p) {
        if (!is_p[p]) continue;
        for (uint32_t m = p * p; m < B; m += p) is_p[m] = false;
    }
    for (uint32_t p = 3; p < B; p += 2)
        if (is_p[p]) out.push_back(p);
    return true;
}

bool dao_mpc_crt::near_primorial_primes(uint32_t kappa, uint32_t n,
                                         std::vector<uint32_t>& out)
{
    out.clear();
    if (kappa < 4 || n < 2) return false;

    // bit_budget = kappa - floor(log2(n)) - 1.
    uint32_t log2n = 0;
    for (uint32_t t = n; t > 1; t >>= 1) ++log2n;
    if (kappa <= log2n + 1) return false;
    const uint32_t bit_budget = kappa - log2n - 1;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;
    BN_CTX_start(ctx);
    BIGNUM* bound = BN_CTX_get(ctx);
    BIGNUM* prod  = BN_CTX_get(ctx);
    BIGNUM* trial = BN_CTX_get(ctx);
    bool ok = bound && prod && trial;

    if (ok) {
        BN_one(bound);
        BN_lshift(bound, bound, bit_budget);
        BN_one(prod);
    }

    // Trial prime generation. Smallest allowed odd prime is
    // max(3, 2t+2) where t = (n+1)/2 - 1, i.e. 2t+1 = n. So the
    // start is strictly greater than 2t+1 = n. This is required so
    // that Lagrange interpolation over 2t+1 = n points {1..n} is
    // well-defined in F_r (no point is 0 mod r, and points are
    // distinct mod r).
    //
    // For n=3: 2t+1=3, start = max(3, 4) = 4 → first odd = 5. But
    // r=3 still works because x_3=3≡0 and the Lagrange coefficient
    // collapse is correct (L_1=L_2=0, L_3=1). So n=3 starts at 3.
    // For n=16: 2t+1=15, start = max(3, 16) = 16 → first odd = 17.
    // Primes 3, 5, 7, 11, 13 are excluded. Aggregate coprimality to
    // those primes is enforced by the runner-side gcd(N, 105·11·13)
    // check, not by the sieve.
    const uint32_t tp1 = (n + 1) / 2;
    const uint32_t two_t_plus_1 = 2 * (tp1 - 1) + 1;
    uint32_t p = (3 > two_t_plus_1 + 1) ? 3 : two_t_plus_1 + 1;
    if (p == 3 && n <= 3) p = 3;   // n=3 case: allow r=3
    if ((p & 1) == 0) ++p;         // ensure odd
    while (ok && p < 200000) {
        // Simple primality: trial divide by odd q in [3, sqrt(p)].
        bool is_prime = true;
        for (uint32_t q = 3; (uint64_t)q * q <= p; q += 2) {
            if (p % q == 0) { is_prime = false; break; }
        }
        if (is_prime) {
            BN_set_word(trial, p);
            BIGNUM* cand = BN_new();
            if (!cand) { ok = false; break; }
            if (!BN_mul(cand, prod, trial, ctx)) { BN_free(cand); ok = false; break; }
            if (BN_cmp(cand, bound) < 0) {
                BN_copy(prod, cand);
                out.push_back(p);
                BN_free(cand);
            } else {
                BN_free(cand);
                break;
            }
        }
        p += 2;
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (!ok) { out.clear(); return false; }
    return true;
}

bool dao_mpc_crt::sieve_product(const std::vector<uint32_t>& primes,
                                BIGNUM* Q_out, BN_CTX*)
{
    if (!Q_out || primes.empty()) return false;
    BN_one(Q_out);
    for (uint32_t r : primes) {
        if (!BN_mul_word(Q_out, r)) return false;
    }
    return true;
}

bool dao_mpc_crt::sample_party_residues(const std::vector<uint32_t>& primes,
                                        uint32_t n,
                                        std::vector<std::vector<uint32_t>>& out)
{
    out.clear();
    if (n == 0 || primes.empty()) return false;
    out.assign(n, std::vector<uint32_t>(primes.size(), 0));

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;
    BN_CTX_start(ctx);
    BIGNUM* mod = BN_CTX_get(ctx);
    BIGNUM* tmp = BN_CTX_get(ctx);
    bool ok = mod && tmp;

    for (size_t j = 0; j < primes.size() && ok; ++j) {
        BN_set_word(mod, primes[j]);
        for (uint32_t i = 0; i < n && ok; ++i) {
            uint32_t u = 0;
            for (int tries = 0; tries < 16 && u == 0; ++tries) {
                if (!BN_rand_range(tmp, mod)) { ok = false; break; }
                u = (uint32_t)BN_get_word(tmp);
            }
            if (u == 0) { ok = false; break; }
            out[i][j] = u;
        }
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (!ok) { out.clear(); return false; }
    return true;
}

bool dao_mpc_crt::crt_reconstruct(const std::vector<uint32_t>& primes,
                                  const std::vector<std::vector<uint32_t>>& shares,
                                  std::vector<BIGNUM*>& out, BN_CTX* ctx)
{
    out.clear();
    const size_t k = primes.size();
    if (k == 0 || shares.empty()) return false;
    for (const auto& s : shares) if (s.size() != k) return false;
    if (!ctx) return false;

    BIGNUM* Q = BN_new();
    if (!Q) return false;
    BN_one(Q);
    for (uint32_t r : primes) {
        if (!BN_mul_word(Q, r)) { BN_free(Q); return false; }
    }

    std::vector<BIGNUM*> M(k, nullptr);
    std::vector<uint32_t> inv(k, 0);
    bool ok = true;
    BN_CTX_start(ctx);
    BIGNUM* base = BN_CTX_get(ctx);
    BIGNUM* exp  = BN_CTX_get(ctx);
    BIGNUM* rmod = BN_CTX_get(ctx);
    BIGNUM* res  = BN_CTX_get(ctx);
    ok = base && exp && rmod && res;

    for (size_t i = 0; i < k && ok; ++i) {
        M[i] = BN_dup(Q);
        if (!M[i]) { ok = false; break; }
        BN_div_word(M[i], primes[i]);
        BN_set_word(rmod, primes[i]);
        if (!BN_nnmod(base, M[i], rmod, ctx)) { ok = false; break; }
        BN_set_word(exp, primes[i] - 2);
        if (!BN_mod_exp(res, base, exp, rmod, ctx)) { ok = false; break; }
        inv[i] = (uint32_t)BN_get_word(res);
    }
    BN_CTX_end(ctx);

    if (ok) {
        for (const auto& s : shares) {
            BIGNUM* U = BN_new();
            if (!U) { ok = false; break; }
            BN_zero(U);
            for (size_t i = 0; i < k; ++i) {
                BIGNUM* term = BN_dup(M[i]);
                if (!term) { BN_free(U); ok = false; break; }
                if (!BN_mul_word(term, s[i]) ||
                    !BN_mul_word(term, inv[i]) ||
                    !BN_add(U, U, term)) {
                    BN_free(term); BN_free(U); ok = false; break;
                }
                BN_free(term);
            }
            if (!ok) break;
            if (!BN_nnmod(U, U, Q, ctx)) { BN_free(U); ok = false; break; }
            out.push_back(U);
        }
    }

    for (auto* m : M) if (m) BN_free(m);
    BN_free(Q);
    if (!ok) {
        for (auto* u : out) if (u) BN_free(u);
        out.clear();
        return false;
    }
    return true;
}

bool dao_mpc_crt::lift_to_range(const BIGNUM* U, const BIGNUM* Q,
                                uint32_t bits, uint32_t target_mod4,
                                BIGNUM* out, BN_CTX* ctx)
{
    if (!U || !Q || !out || !ctx || bits == 0) return false;
    if (BN_is_zero(Q)) return false;
    // Q must be odd so gcd(Q,4)=1.
    if ((BN_mod_word(Q, 4) & 1) == 0) return false;

    // Step 1: k0 in [0,3] with (U + k0*Q) mod 4 == target_mod4.
    uint32_t k0 = 0;
    bool found = false;
    for (uint32_t k = 0; k < 4; ++k) {
        BIGNUM* tmp = BN_new();
        if (!tmp) return false;
        BN_copy(tmp, U);
        BN_mul_word(tmp, 1);
        for (uint32_t t = 0; t < k; ++t) BN_add(tmp, tmp, Q);
        if ((BN_mod_word(tmp, 4) == target_mod4)) { k0 = k; found = true; BN_free(tmp); break; }
        BN_free(tmp);
    }
    if (!found) return false;

    // Start value V0 = U + k0*Q.
    BIGNUM* V0 = BN_new();
    if (!V0) return false;
    BN_copy(V0, U);
    for (uint32_t t = 0; t < k0; ++t) BN_add(V0, V0, Q);

    // lower = 2^{bits-1}, upper = 2^{bits}, Q4 = 4*Q.
    BIGNUM* lower = BN_new();
    BIGNUM* upper = BN_new();
    BIGNUM* Q4 = BN_new();
    BIGNUM* gap = BN_new();
    BIGNUM* kprime = BN_new();
    BIGNUM* mult = BN_new();
    BIGNUM* result = BN_new();
    bool ok = lower && upper && Q4 && gap && kprime && mult && result;
    if (ok) {
        BN_one(lower); BN_lshift(lower, lower, bits - 1);
        BN_one(upper); BN_lshift(upper, upper, bits);
        BN_copy(Q4, Q); BN_mul_word(Q4, 4);

        if (BN_cmp(V0, lower) >= 0) {
            BN_zero(kprime);
        } else {
            BN_sub(gap, lower, V0);              // gap > 0
            // kprime = ceil(gap / Q4) = (gap + Q4 - 1) / Q4
            BIGNUM* adj = BN_new();
            if (!adj) ok = false;
            else {
                BN_copy(adj, Q4); BN_sub_word(adj, 1);
                BN_add(gap, gap, adj);
                BN_div(kprime, nullptr, gap, Q4, ctx);
                BN_free(adj);
            }
        }

        if (ok) {
            // mult = k0 + 4*kprime
            BN_copy(mult, kprime);
            BN_mul_word(mult, 4);
            BN_add_word(mult, k0);
            BN_mul(result, mult, Q, ctx);
            BN_add(result, result, U);

            if (BN_cmp(result, upper) < 0 &&
                BN_cmp(result, lower) >= 0) {
                BN_copy(out, result);
            } else {
                ok = false;
            }
        }
    }

    BN_free(lower); BN_free(upper); BN_free(Q4); BN_free(gap);
    BN_free(kprime); BN_free(mult); BN_free(result); BN_free(V0);
    return ok;
}

// ================================================================
// Production-path helpers.
// ================================================================

bool dao_mpc_crt::sieve_modulus_mod4(const std::vector<uint32_t>& primes,
                                     BIGNUM* M0_out, BN_CTX*)
{
    if (!M0_out || primes.empty()) return false;
    BN_one(M0_out);
    for (uint32_t r : primes) {
        if (!BN_mul_word(M0_out, r)) return false;
    }
    if (!BN_mul_word(M0_out, 4)) return false;
    return true;
}

bool dao_mpc_crt::crt_reconstruct_with_mod4(
    const std::vector<uint32_t>& primes,
    const std::vector<std::vector<uint32_t>>& shares,
    std::vector<BIGNUM*>& out, BN_CTX* ctx)
{
    out.clear();
    const size_t k = primes.size();
    if (k == 0 || shares.empty()) return false;
    for (const auto& s : shares) if (s.size() != k) return false;
    if (!ctx) return false;

    // M_s = prod(primes). M_s odd since all primes are odd.
    BIGNUM* M_s = BN_new();
    if (!M_s) return false;
    BN_one(M_s);
    for (uint32_t r : primes) {
        if (!BN_mul_word(M_s, r)) { BN_free(M_s); return false; }
    }
    const BN_ULONG m4 = BN_mod_word(M_s, 4);
    if (m4 != 1 && m4 != 3) { BN_free(M_s); return false; }
    // inv(m4, 4) = m4 because 1*1=1 and 3*3=9=1 mod 4.
    const uint32_t inv_m4_mod4 = (uint32_t)m4;

    // Standard CRT over primes → W_s ∈ [0, M_s).
    std::vector<BIGNUM*> W_s;
    if (!crt_reconstruct(primes, shares, W_s, ctx)) {
        BN_free(M_s);
        return false;
    }

    // For each party: W_i = W_s + k*M_s, with k ∈ [0,4) s.t.
    // (W_s + k*M_s) mod 4 = target_mod4.
    // target_mod4 = 3 if party is index 0 (party_id 1), else 0.
    for (size_t i = 0; i < W_s.size(); ++i) {
        const uint32_t target = (i == 0) ? 3u : 0u;
        const BN_ULONG ws4 = BN_mod_word(W_s[i], 4);
        if (ws4 == (BN_ULONG)-1) {
            BN_free(M_s);
            for (auto* x : W_s) BN_free(x);
            return false;
        }
        int64_t diff = (int64_t)target - (int64_t)ws4;
        diff = ((diff % 4) + 4) % 4;
        const uint32_t k = (uint32_t)((diff * (int64_t)inv_m4_mod4) % 4);

        BIGNUM* W = BN_new();
        BIGNUM* tmp = BN_new();
        if (!W || !tmp) {
            if (W) BN_free(W);
            if (tmp) BN_free(tmp);
            BN_free(M_s);
            for (auto* x : W_s) BN_free(x);
            return false;
        }
        if (!BN_copy(tmp, M_s) || !BN_mul_word(tmp, (BN_ULONG)k) ||
            !BN_add(W, W_s[i], tmp)) {
            BN_free(W); BN_free(tmp); BN_free(M_s);
            for (auto* x : W_s) BN_free(x);
            return false;
        }
        BN_free(tmp);

        // Defensive: verify mod-4 and all prime residues.
        if (BN_mod_word(W, 4) != (BN_ULONG)target) {
            BN_free(W); BN_free(M_s);
            for (auto* x : W_s) BN_free(x);
            return false;
        }
        for (size_t j = 0; j < k; ++j) {
            if (BN_mod_word(W, primes[j]) != (BN_ULONG)shares[i][j]) {
                BN_free(W); BN_free(M_s);
                for (auto* x : W_s) BN_free(x);
                return false;
            }
        }
        out.push_back(W);
    }

    BN_free(M_s);
    for (auto* x : W_s) BN_free(x);
    return true;
}

bool dao_mpc_crt::reconstruct_to_contribution(
    const BIGNUM* residue, const BIGNUM* modulus,
    uint32_t lambda, uint32_t sigma, uint32_t committee_size,
    BIGNUM* out, BN_CTX* ctx)
{
    if (!residue || !modulus || !out || !ctx) return false;
    if (committee_size < 3 || lambda == 0 || sigma == 0) return false;
    if (BN_is_zero(modulus) || BN_is_negative(residue)) return false;
    if (BN_cmp(residue, modulus) >= 0) return false;

    BN_CTX_start(ctx);
    BIGNUM* lower_num = BN_CTX_get(ctx);
    BIGNUM* upper_num = BN_CTX_get(ctx);
    BIGNUM* divisor   = BN_CTX_get(ctx);
    BIGNUM* lower     = BN_CTX_get(ctx);
    BIGNUM* upper     = BN_CTX_get(ctx);
    BIGNUM* k_min     = BN_CTX_get(ctx);
    BIGNUM* k_end     = BN_CTX_get(ctx);
    BIGNUM* count     = BN_CTX_get(ctx);
    BIGNUM* offset    = BN_CTX_get(ctx);
    BIGNUM* kk        = BN_CTX_get(ctx);
    BIGNUM* tmp       = BN_CTX_get(ctx);

    bool ok = tmp != nullptr;

    if (ok) ok = BN_one(lower_num) == 1
              && BN_lshift(lower_num, lower_num, lambda) == 1;
    if (ok) ok = BN_one(upper_num) == 1
              && BN_lshift(upper_num, upper_num, lambda + sigma) == 1;
    if (ok) ok = BN_set_word(divisor, committee_size) == 1;

    // L = ceil(2^lambda / n) = (2^lambda + n - 1) / n
    if (ok) ok = BN_copy(tmp, lower_num) != nullptr
              && BN_add_word(tmp, committee_size - 1) == 1
              && BN_div(lower, nullptr, tmp, divisor, ctx) == 1;

    // U = ceil(2^(lambda+sigma) / n)
    if (ok) ok = BN_copy(tmp, upper_num) != nullptr
              && BN_add_word(tmp, committee_size - 1) == 1
              && BN_div(upper, nullptr, tmp, divisor, ctx) == 1;

    // For our parameters residue < M_0 < L, so k_min ≥ 1 always.
    // Compute k_min = ceil((L - residue)/M_0) via the standard
    // (a + b - 1) / b formula, which is correct for a > 0.
    // At production target (kappa=1024) M_0 < L always holds, so the
    // else branch is the only one taken. At smaller targets (128-bit
    // test) M_0 can exceed L, in which case W_i may already be >= L
    // and k_min = 0 is correct. ceil((L - residue)/M_0) is only
    // defined for residue < L.
    if (ok) {
        if (BN_cmp(residue, lower) >= 0) {
            BN_zero(k_min);
            ok = true;
        } else {
            ok = BN_sub(tmp, lower, residue) == 1
              && BN_add(tmp, tmp, modulus) == 1
              && BN_sub_word(tmp, 1) == 1
              && BN_div(k_min, nullptr, tmp, modulus, ctx) == 1;
        }
    }

    // k_end = ceil((U - residue)/M_0)
    if (ok) ok = BN_sub(tmp, upper, residue) == 1
              && BN_add(tmp, tmp, modulus) == 1
              && BN_sub_word(tmp, 1) == 1
              && BN_div(k_end, nullptr, tmp, modulus, ctx) == 1;

    // count = k_end - k_min; must be > 0.
    if (ok) ok = BN_sub(count, k_end, k_min) == 1
              && !BN_is_zero(count)
              && !BN_is_negative(count);

    // Uniform offset in [0, count).
    if (ok) ok = BN_priv_rand_range(offset, count) == 1
              && BN_add(kk, k_min, offset) == 1;

    // out = residue + kk * modulus, must lie in [lower, upper).
    if (ok) ok = BN_mul(tmp, kk, modulus, ctx) == 1
              && BN_add(out, residue, tmp) == 1
              && BN_cmp(out, lower) >= 0
              && BN_cmp(out, upper) < 0;

    BN_CTX_end(ctx);
    return ok;
}

bool dao_mpc_crt::reconstruct_all_to_contributions(
    const std::vector<BIGNUM*>& W, const BIGNUM* M0,
    uint32_t lambda, uint32_t sigma,
    std::vector<BIGNUM*>& p_out, BN_CTX* ctx)
{
    p_out.clear();
    if (W.empty() || !M0 || !ctx) return false;
    const uint32_t n = (uint32_t)W.size();
    for (const BIGNUM* w : W) {
        BIGNUM* p = BN_new();
        if (!p) {
            for (auto* x : p_out) BN_free(x);
            p_out.clear();
            return false;
        }
        if (!reconstruct_to_contribution(w, M0, lambda, sigma, n, p, ctx)) {
            BN_free(p);
            for (auto* x : p_out) BN_free(x);
            p_out.clear();
            return false;
        }
        p_out.push_back(p);
    }
    return true;
}

}} // namespace
