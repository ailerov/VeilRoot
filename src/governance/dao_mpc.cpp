#include "dao_mpc.h"
#include <openssl/bn.h>
#include <cstring>

namespace cryptonote { namespace dao {

uint32_t dao_mpc_field::add(uint32_t a, uint32_t b) const {
    return (uint32_t)(((uint64_t)a + b) % r);
}
uint32_t dao_mpc_field::sub(uint32_t a, uint32_t b) const {
    int64_t d = (int64_t)a - (int64_t)b;
    if (d < 0) d += r;
    return (uint32_t)d;
}
uint32_t dao_mpc_field::mul(uint32_t a, uint32_t b) const {
    return (uint32_t)(((uint64_t)a * b) % r);
}
uint32_t dao_mpc_field::inv(uint32_t a) const {
    if (a == 0) return 0;
    uint64_t e = (uint64_t)r - 2, base = a, out = 1;
    while (e) {
        if (e & 1) out = (out * base) % r;
        base = (base * base) % r;
        e >>= 1;
    }
    return (uint32_t)out;
}

static void u64_to_bn(uint64_t v, BIGNUM* out) {
    uint8_t buf[8];
    for (int k = 7; k >= 0; --k) { buf[k] = (uint8_t)(v & 0xFF); v >>= 8; }
    BN_bin2bn(buf, 8, out);
}

bool dao_mpc_vss::deal(const dao_mpc_field& f, const dao_vss_group& grp,
                       uint32_t secret, uint32_t n, uint32_t t,
                       dao_vss_commitments& commits_out,
                       std::vector<BIGNUM*>& shares_out,
                       std::vector<BIGNUM*>& blindings_out,
                       BN_CTX* ctx)
{
    if (!f.valid() || !grp.valid() || secret >= f.r) return false;
    if (n < t + 1 || n == 0) return false;

    std::vector<uint32_t> a(t + 1), b(t + 1);
    a[0] = secret;
    BIGNUM* rr = BN_new();
    BIGNUM* tmp = BN_new();
    if (!rr || !tmp) { BN_free(rr); BN_free(tmp); return false; }
    BN_set_word(rr, f.r);
    for (uint32_t k = 1; k <= t; ++k) {
        if (!BN_rand_range(tmp, rr)) { BN_free(rr); BN_free(tmp); return false; }
        a[k] = (uint32_t)BN_get_word(tmp);
    }
    for (uint32_t k = 0; k <= t; ++k) {
        if (!BN_rand_range(tmp, rr)) { BN_free(rr); BN_free(tmp); return false; }
        b[k] = (uint32_t)BN_get_word(tmp);
    }
    BN_free(rr); BN_free(tmp);

    commits_out.C.assign(t + 1, {});
    const size_t P_bytes = (size_t)BN_num_bytes(grp.P);
    for (uint32_t k = 0; k <= t; ++k) {
        BIGNUM* ak = BN_new(); BIGNUM* bk = BN_new();
        BIGNUM* ga = BN_new(); BIGNUM* hb = BN_new(); BIGNUM* C = BN_new();
        bool ok = ak && bk && ga && hb && C;
        if (ok) {
            BN_set_word(ak, a[k]); BN_set_word(bk, b[k]);
            ok = BN_mod_exp(ga, grp.g, ak, grp.P, ctx)
              && BN_mod_exp(hb, grp.h, bk, grp.P, ctx)
              && BN_mod_mul(C, ga, hb, grp.P, ctx);
        }
        if (ok) {
            commits_out.C[k].assign(P_bytes, 0);
            BN_bn2binpad(C, commits_out.C[k].data(), (int)P_bytes);
        }
        BN_free(ak); BN_free(bk); BN_free(ga); BN_free(hb); BN_free(C);
        if (!ok) return false;
    }

    shares_out.assign(n, nullptr);
    blindings_out.assign(n, nullptr);
    for (uint32_t i = 1; i <= n; ++i) {
        uint64_t s = 0, ti = 0, pw = 1;
        for (uint32_t k = 0; k <= t; ++k) {
            s  += (uint64_t)a[k] * pw;
            ti += (uint64_t)b[k] * pw;
            if (k < t) pw *= i;
        }
        BIGNUM* sbn = BN_new(); BIGNUM* tbn = BN_new();
        if (!sbn || !tbn) { BN_free(sbn); BN_free(tbn); goto fail; }
        u64_to_bn(s, sbn); u64_to_bn(ti, tbn);
        shares_out[i-1] = sbn; blindings_out[i-1] = tbn;
    }
    for (uint32_t i = 1; i <= n; ++i) {
        if (!verify(f, grp, commits_out, i, shares_out[i-1],
                    blindings_out[i-1], ctx)) goto fail;
    }
    return true;
fail:
    for (auto* x : shares_out) if (x) BN_free(x);
    for (auto* x : blindings_out) if (x) BN_free(x);
    shares_out.clear(); blindings_out.clear();
    return false;
}

bool dao_mpc_vss::verify(const dao_mpc_field& f, const dao_vss_group& grp,
                         const dao_vss_commitments& commits, uint32_t i,
                         const BIGNUM* share, const BIGNUM* blinding,
                         BN_CTX* ctx)
{
    (void)f;
    if (!grp.valid() || !share || !blinding) return false;
    if (commits.C.empty()) return false;
    const uint32_t t = (uint32_t)commits.C.size() - 1;

    BIGNUM* lhs = BN_new(); BIGNUM* rhs = BN_new();
    BIGNUM* ga = BN_new(); BIGNUM* hb = BN_new();
    bool ok = lhs && rhs && ga && hb;
    if (ok) ok = BN_mod_exp(ga, grp.g, share, grp.P, ctx)
              && BN_mod_exp(hb, grp.h, blinding, grp.P, ctx)
              && BN_mod_mul(lhs, ga, hb, grp.P, ctx);
    if (ok) {
        BN_one(rhs);
        uint64_t pw = 1;
        for (uint32_t k = 0; k <= t && ok; ++k) {
            BIGNUM* Ck = BN_bin2bn(commits.C[k].data(),
                                   (int)commits.C[k].size(), nullptr);
            BIGNUM* pwe = BN_new(); BIGNUM* term = BN_new();
            ok = Ck && pwe && term;
            if (ok) {
                u64_to_bn(pw, pwe);
                ok = BN_mod_exp(term, Ck, pwe, grp.P, ctx)
                  && BN_mod_mul(rhs, rhs, term, grp.P, ctx);
            }
            BN_free(Ck); BN_free(pwe); BN_free(term);
            if (k < t) pw *= i;
        }
        if (ok) ok = (BN_cmp(lhs, rhs) == 0);
    }
    BN_free(lhs); BN_free(rhs); BN_free(ga); BN_free(hb);
    return ok;
}

bool dao_mpc_vss::reconstruct(const dao_mpc_field& f,
                              const std::vector<const BIGNUM*>& shares,
                              const std::vector<uint32_t>& indices,
                              uint32_t t, uint32_t& out, BN_CTX* ctx)
{
    (void)ctx;
    if (!f.valid() || shares.size() != indices.size()) return false;
    if (shares.size() < (size_t)t + 1) return false;
    uint64_t acc = 0;
    for (size_t i = 0; i < shares.size(); ++i) {
        uint64_t num = 1, den = 1;
        for (size_t j = 0; j < shares.size(); ++j) {
            if (i == j) continue;
            int64_t xj = (int64_t)indices[j];
            int64_t xi = (int64_t)indices[i];
            int64_t neg_xj = ((-xj) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
            int64_t dij    = ((xi - xj) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
            num = (num * (uint64_t)neg_xj) % f.r;
            den = (den * (uint64_t)dij) % f.r;
        }
        uint64_t inv_den = f.inv((uint32_t)den);
        uint64_t s_mod = (uint64_t)BN_mod_word(shares[i], f.r);
        uint64_t contrib = (((s_mod * num) % f.r) * inv_den) % f.r;
        acc = (acc + contrib) % f.r;
    }
    out = (uint32_t)acc;
    return true;
}

bool dao_mpc_mul::multiply(const dao_mpc_field& f, const dao_vss_group& grp,
                           uint32_t n, uint32_t t,
                           const std::vector<const BIGNUM*>& shares_a,
                           const std::vector<const BIGNUM*>& shares_b,
                           std::vector<BIGNUM*>& shares_out, BN_CTX* ctx)
{
    if (!f.valid() || !grp.valid()) return false;
    if (n != shares_a.size() || n != shares_b.size()) return false;
    if (n < 2 * t + 1) return false;

    std::vector<uint32_t> c(n);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t ai = (uint32_t)BN_mod_word(shares_a[i], f.r);
        uint32_t bi = (uint32_t)BN_mod_word(shares_b[i], f.r);
        c[i] = f.mul(ai, bi);
    }

    std::vector<dao_vss_commitments> deals(n);
    std::vector<std::vector<BIGNUM*>> deal_shares(n);
    std::vector<std::vector<BIGNUM*>> deal_blindings(n);
    shares_out.clear();
    for (uint32_t d = 0; d < n; ++d) {
        if (!dao_mpc_vss::deal(f, grp, c[d], n, t, deals[d],
                               deal_shares[d], deal_blindings[d], ctx))
            goto fail;
    }

    {
        // c_d is degree-2t; reconstruct over 2t+1 points. See
        // combine_c_shares comment for the small-r caveat.
        const uint32_t M = 2 * t + 1;
        std::vector<uint32_t> S(M), L(M);
        for (uint32_t k = 0; k < M; ++k) S[k] = k + 1;
        for (uint32_t jj = 0; jj < M; ++jj) {
            uint64_t num = 1, den = 1;
            for (uint32_t kk = 0; kk < M; ++kk) {
                if (jj == kk) continue;
                int64_t xj = (int64_t)S[jj];
                int64_t xk = (int64_t)S[kk];
                int64_t neg_xk = ((-xk) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
                int64_t diff   = ((xj - xk) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
                num = (num * (uint64_t)neg_xk) % f.r;
                den = (den * (uint64_t)diff) % f.r;
            }
            uint64_t inv_den = f.inv((uint32_t)den);
            L[jj] = (uint32_t)((num * inv_den) % f.r);
        }

        shares_out.assign(n, nullptr);
        for (uint32_t i = 0; i < n; ++i) {
            uint64_t acc = 0;
            for (uint32_t jj = 0; jj < M; ++jj) {
                const BIGNUM* sh = deal_shares[S[jj] - 1][i];
                uint64_t sh_mod = (uint64_t)BN_mod_word(sh, f.r);
                acc = (acc + ((sh_mod * L[jj]) % f.r)) % f.r;
            }
            BIGNUM* out = BN_new();
            if (!out) goto fail;
            u64_to_bn(acc, out);
            shares_out[i] = out;
        }
    }

    for (auto& v : deal_shares)     for (auto* x : v) if (x) BN_free(x);
    for (auto& v : deal_blindings)  for (auto* x : v) if (x) BN_free(x);
    return true;

fail:
    for (auto* x : shares_out) if (x) BN_free(x);
    shares_out.clear();
    for (auto& v : deal_shares)     for (auto* x : v) if (x) BN_free(x);
    for (auto& v : deal_blindings)  for (auto* x : v) if (x) BN_free(x);
    return false;
}

// ---- stepwise GRR ----
bool dao_mpc_mul::local_product(const dao_mpc_field& f,
                                const BIGNUM* a_i, const BIGNUM* b_i,
                                uint32_t& c_i)
{
    if (!f.valid() || !a_i || !b_i) return false;
    uint32_t ai = (uint32_t)BN_mod_word(a_i, f.r);
    uint32_t bi = (uint32_t)BN_mod_word(b_i, f.r);
    c_i = f.mul(ai, bi);
    return true;
}

bool dao_mpc_mul::deal_c(const dao_mpc_field& f, const dao_vss_group& grp,
                         uint32_t c_i, uint32_t n, uint32_t t,
                         dao_vss_commitments& commits_out,
                         std::vector<BIGNUM*>& shares_out,
                         std::vector<BIGNUM*>& blindings_out,
                         BN_CTX* ctx)
{
    return dao_mpc_vss::deal(f, grp, c_i, n, t,
                             commits_out, shares_out, blindings_out, ctx);
}

bool dao_mpc_mul::combine_c_shares(const dao_mpc_field& f,
                                    const std::vector<const BIGNUM*>& my_received_shares,
                                    uint32_t n, uint32_t t,
                                    uint32_t& out_share)
{
    if (!f.valid()) return false;
    if (my_received_shares.size() != n) return false;
    if (n < 2 * t + 1) return false;

    // c_d = a_d * b_d is a degree-2t polynomial evaluation. To
    // reconstruct c(0) = a*b from c_d values, need 2t+1 points.
    // Requires 2t+1 < r for every sieve prime r; enforced by
    // near_primorial_primes for n=3 (2t+1=3, min prime 3) except
    // for r=3 where x_3 = 3 ≡ 0 mod 3 but the Lagrange coefficients
    // collapse correctly (L_1=L_2=0, L_3=1, and c(3)=c(0) mod 3).
    // For n=16 (t=7, 2t+1=15), near_primorial_primes starts at 11,
    // which is insufficient for 2t+1=15 in F_11 and F_13. Those
    // specific primes are handled by the runner-side gcd check; the
    // sieve itself only guarantees coprimality to primes > 2t+1.
    // See dao_mpc_eratosthenes_test for verification.
    const uint32_t M = 2 * t + 1;
    std::vector<uint32_t> S(M), L(M);
    for (uint32_t k = 0; k < M; ++k) S[k] = k + 1;
    for (uint32_t jj = 0; jj < M; ++jj) {
        uint64_t num = 1, den = 1;
        for (uint32_t kk = 0; kk < M; ++kk) {
            if (jj == kk) continue;
            int64_t xj = (int64_t)S[jj];
            int64_t xk = (int64_t)S[kk];
            int64_t neg_xk = ((-xk) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
            int64_t diff   = ((xj - xk) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
            num = (num * (uint64_t)neg_xk) % f.r;
            den = (den * (uint64_t)diff) % f.r;
        }
        uint64_t inv_den = f.inv((uint32_t)den);
        L[jj] = (uint32_t)((num * inv_den) % f.r);
    }

    uint64_t acc = 0;
    for (uint32_t jj = 0; jj < M; ++jj) {
        const BIGNUM* sh = my_received_shares[S[jj] - 1];
        if (!sh) return false;
        uint64_t sh_mod = (uint64_t)BN_mod_word(sh, f.r);
        acc = (acc + ((sh_mod * L[jj]) % f.r)) % f.r;
    }
    out_share = (uint32_t)acc;
    return true;
}

// ---- additive conversion ----
// Lagrange coefficients at 0 over the first t+1 points (indices
// 1..t+1). Requires t+1 < r so those points are distinct and nonzero
// mod r. Zero coefficients for indices > t+1; a degree-t polynomial
// is fully determined by its first t+1 evaluations.
//
// Inference of t: t = (n+1)/2 - 1, so t+1 = (n+1)/2. This is the
// only valid t for our committees (honest-majority threshold).
static bool lagrange_coeffs_tplus1(const dao_mpc_field& f, uint32_t n,
                                   std::vector<uint32_t>& out)
{
    if (!f.valid() || n < 3) return false;
    const uint32_t tp1 = (n + 1) / 2;
    if (tp1 >= f.r) return false;   // precondition t+1 < r
    out.assign(n, 0);
    for (uint32_t i = 1; i <= tp1; ++i) {
        uint64_t num = 1, den = 1;
        for (uint32_t j = 1; j <= tp1; ++j) {
            if (i == j) continue;
            int64_t neg_j = ((-(int64_t)j) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
            int64_t diff  = (((int64_t)i - (int64_t)j) % (int64_t)f.r + (int64_t)f.r) % (int64_t)f.r;
            num = (num * (uint64_t)neg_j) % f.r;
            den = (den * (uint64_t)diff) % f.r;
        }
        uint64_t inv_den = f.inv((uint32_t)den);
        out[i-1] = (uint32_t)((num * inv_den) % f.r);
    }
    // out[i-1] = 0 for i > tp1.
    return true;
}

bool dao_mpc_mul::to_additive_shares(const dao_mpc_field& f, uint32_t n,
                                     const std::vector<const BIGNUM*>& shamir_shares,
                                     std::vector<uint32_t>& additive_out)
{
    if (!f.valid() || shamir_shares.size() != n) return false;
    std::vector<uint32_t> lc;
    if (!lagrange_coeffs_tplus1(f, n, lc)) return false;
    additive_out.assign(n, 0);
    for (uint32_t i = 0; i < n; ++i) {
        if (!shamir_shares[i]) return false;
        uint64_t s_mod = (uint64_t)BN_mod_word(shamir_shares[i], f.r);
        additive_out[i] = (uint32_t)((s_mod * lc[i]) % f.r);
    }
    return true;
}

// ---- balanced-tree n-way product ----
bool dao_mpc_mul::multiply_tree(const dao_mpc_field& f,
                                 const dao_vss_group& grp,
                                 uint32_t n, uint32_t t,
                                 const std::vector<std::vector<const BIGNUM*>>& shares_in,
                                 std::vector<BIGNUM*>& shares_out, BN_CTX* ctx)
{
    shares_out.clear();
    if (!f.valid() || !grp.valid()) return false;
    if (shares_in.empty()) return false;
    for (const auto& v : shares_in) if (v.size() != n) return false;
    if (n < 2 * t + 1) return false;

    // Layer of shared operands. Each entry is a vector of n BIGNUM*
    // shares (index i = party i's share of that operand). Ownership:
    // the caller owns shares_in; this function owns intermediates and
    // frees them as it goes, and returns ownership of the final layer
    // to the caller via shares_out.
    using layer_t = std::vector<std::vector<const BIGNUM*>>;

    // Copy inputs into a mutable layer of BIGNUM* we will free. We
    // duplicate on the fly so we can uniformly BN_free intermediate
    // results without touching caller-owned pointers.
    std::vector<std::vector<BIGNUM*>> owned;
    owned.reserve(shares_in.size());
    for (const auto& v : shares_in) {
        std::vector<BIGNUM*> copy(n, nullptr);
        for (uint32_t i = 0; i < n; ++i) {
            copy[i] = BN_dup(v[i]);
            if (!copy[i]) {
                for (auto& vv : owned) for (auto* x : vv) if (x) BN_free(x);
                for (auto* x : copy) if (x) BN_free(x);
                return false;
            }
        }
        owned.push_back(std::move(copy));
    }

    while (owned.size() > 1) {
        std::vector<std::vector<BIGNUM*>> next;
        next.reserve((owned.size() + 1) / 2);
        for (size_t i = 0; i + 1 < owned.size(); i += 2) {
            std::vector<const BIGNUM*> a(owned[i].begin(), owned[i].end());
            std::vector<const BIGNUM*> b(owned[i + 1].begin(), owned[i + 1].end());
            std::vector<BIGNUM*> out;
            if (!dao_mpc_mul::multiply(f, grp, n, t, a, b, out, ctx)) {
                for (auto& vv : owned) for (auto* x : vv) if (x) BN_free(x);
                for (auto& vv : next)  for (auto* x : vv) if (x) BN_free(x);
                return false;
            }
            // Free the two inputs consumed at this node.
            for (auto* x : owned[i])     BN_free(x);
            for (auto* x : owned[i + 1]) BN_free(x);
            next.push_back(std::move(out));
        }
        if (owned.size() & 1) {
            // Forward the last unpaired operand unchanged.
            next.push_back(std::move(owned.back()));
        }
        // Free the consumed pairs. Only the odd-forwarded entry is
        // still live; it was moved out above, so its old slot in
        // owned is now empty but still iterated for cleanup below.
        for (size_t i = 0; i + 1 < owned.size(); i += 2) {
            // Already freed above.
        }
        // Clear owned entries that were moved-from or consumed.
        owned.clear();
        owned = std::move(next);
    }

    // Single remaining layer. Hand ownership to caller.
    shares_out = std::move(owned[0]);
    return true;
}

// ================================================================
// FABBWithErrors.Share — pairwise zero-sum masking.
// ================================================================

bool dao_mpc_randomize::generate_pair_masks(const dao_mpc_field& f,
                                             uint32_t n,
                                             std::vector<dao_pair_mask>& out)
{
    out.clear();
    if (!f.valid() || n < 2) return false;
    BIGNUM* rmod = BN_new();
    if (!rmod) return false;
    BN_set_word(rmod, f.r);
    bool ok = true;
    for (uint32_t i = 1; i <= n && ok; ++i) {
        for (uint32_t j = i + 1; j <= n && ok; ++j) {
            BIGNUM* rho = BN_new();
            if (!rho) { ok = false; break; }
            if (!BN_priv_rand_range(rho, rmod)) { BN_free(rho); ok = false; break; }
            dao_pair_mask m;
            m.i = i;
            m.j = j;
            m.rho = (uint32_t)BN_get_word(rho);
            BN_free(rho);
            out.push_back(m);
        }
    }
    BN_free(rmod);
    if (!ok) { out.clear(); return false; }
    return true;
}

bool dao_mpc_additive::to_additive_shares(
    const dao_mpc_field& f, uint32_t n,
    const std::vector<const BIGNUM*>& shamir_shares,
    std::vector<uint32_t>& out)
{
    return dao_mpc_mul::to_additive_shares(f, n, shamir_shares, out);
}

static bool apply_masks_full(const dao_mpc_field& f, uint32_t party,
                             const std::vector<dao_pair_mask>& masks,
                             uint32_t& in_out)
{
    for (const auto& m : masks) {
        if (m.i < 1 || m.j < 1 || m.i >= m.j) return false;
        if (m.rho >= f.r) return false;
        if (party == m.i) in_out = f.add(in_out, m.rho);
        else if (party == m.j) in_out = f.sub(in_out, m.rho);
    }
    return true;
}

bool dao_mpc_additive::to_additive_shares_masked(
    const dao_mpc_field& f, uint32_t n,
    const std::vector<const BIGNUM*>& shamir_shares,
    const std::vector<dao_pair_mask>& masks,
    std::vector<uint32_t>& out)
{
    if (!f.valid() || n < 2) return false;
    const size_t expected = (size_t)n * (n - 1) / 2;
    if (masks.size() != expected) return false;
    // Every (i,j) i<j pair must be present exactly once.
    std::vector<std::vector<bool>> seen(n + 1, std::vector<bool>(n + 1, false));
    for (const auto& m : masks) {
        if (m.i < 1 || m.j < 1 || m.i >= m.j || m.j > n) return false;
        if (m.rho >= f.r) return false;
        if (seen[m.i][m.j]) return false;
        seen[m.i][m.j] = true;
    }

    std::vector<uint32_t> base;
    if (!dao_mpc_additive::to_additive_shares(f, n, shamir_shares, base))
        return false;
    if (base.size() != n) return false;

    out = base;
    for (uint32_t i = 1; i <= n; ++i) {
        if (!apply_masks_full(f, i, masks, out[i - 1])) return false;
    }
    return true;
}

bool dao_mpc_additive::to_additive_shares_masked_party(
    const dao_mpc_field& f, uint32_t me, uint32_t n,
    const std::vector<const BIGNUM*>& shamir_shares,
    const std::vector<dao_pair_mask>& my_masks,
    uint32_t& out)
{
    if (!f.valid() || me < 1 || me > n) return false;
    std::vector<uint32_t> base;
    if (!dao_mpc_additive::to_additive_shares(f, n, shamir_shares, base))
        return false;
    out = base[me - 1];
    for (const auto& m : my_masks) {
        if (m.i < 1 || m.j < 1 || m.i >= m.j || m.j > n) return false;
        if (m.rho >= f.r) return false;
        // Only accept masks incident to `me`.
        if (m.i != me && m.j != me) return false;
        if (me == m.i) out = f.add(out, m.rho);
        else           out = f.sub(out, m.rho);
    }
    return true;
}

}} // namespace
