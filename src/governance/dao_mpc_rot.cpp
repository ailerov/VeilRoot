#include "dao_mpc_rot.h"
#include <openssl/sha.h>
#include <cstring>

namespace cryptonote { namespace dao {

uint32_t dao_rot_k_of(uint32_t r)
{
    uint32_t k = 0;
    while ((1ull << k) < r) ++k;
    return k;
}

bool frot_simulate_cross_terms(
    uint32_t r, uint32_t a_i, uint32_t b_j,
    dao_rot_cross_terms& out, BN_CTX* ctx)
{
    if (r < 2 || a_i >= r || b_j >= r || !ctx) return false;
    const uint32_t k = dao_rot_k_of(r);

    // P_i's bit decomposition of a_i.
    std::vector<uint32_t> bits(k);
    uint32_t a = a_i;
    for (uint32_t h = 0; h < k; ++h) { bits[h] = a & 1u; a >>= 1; }

    // P_j samples q0, q1 uniformly in F_r.
    std::vector<uint32_t> q0(k), q1(k);
    BIGNUM* rmod = BN_new();
    BIGNUM* tmp  = BN_new();
    if (!rmod || !tmp) { BN_free(rmod); BN_free(tmp); return false; }
    BN_set_word(rmod, r);
    for (uint32_t h = 0; h < k; ++h) {
        if (!BN_priv_rand_range(tmp, rmod)) {
            BN_free(rmod); BN_free(tmp); return false;
        }
        q0[h] = (uint32_t)BN_get_word(tmp);
        if (!BN_priv_rand_range(tmp, rmod)) {
            BN_free(rmod); BN_free(tmp); return false;
        }
        q1[h] = (uint32_t)BN_get_word(tmp);
    }
    BN_free(rmod); BN_free(tmp);

    // P_i selects s[h] = bits[h] ? q1[h] : q0[h].
    std::vector<uint32_t> s(k);
    for (uint32_t h = 0; h < k; ++h)
        s[h] = bits[h] ? q1[h] : q0[h];

    // P_j sends d[h] = q0[h] - q1[h] + b_j mod r.
    std::vector<uint32_t> d(k);
    for (uint32_t h = 0; h < k; ++h) {
        int64_t v = (int64_t)q0[h] - (int64_t)q1[h] + (int64_t)b_j;
        v %= (int64_t)r;
        if (v < 0) v += r;
        d[h] = (uint32_t)v;
    }

    // P_i computes t[h] = s[h] + bits[h] * d[h] mod r.
    std::vector<uint32_t> t(k);
    for (uint32_t h = 0; h < k; ++h) {
        uint64_t v = (uint64_t)s[h] + (uint64_t)bits[h] * d[h];
        t[h] = (uint32_t)(v % r);
    }

    // c_ij_i = inner_product(g, t) mod r, g = (2^0, 2^1, ..., 2^{k-1}).
    uint64_t acc_i = 0;
    for (uint32_t h = 0; h < k; ++h)
        acc_i = (acc_i + (uint64_t)t[h] * (1ull << h)) % r;
    out.c_ij_i = (uint32_t)acc_i;

    // c_ij_j = -inner_product(g, q0) mod r.
    uint64_t acc_j = 0;
    for (uint32_t h = 0; h < k; ++h)
        acc_j = (acc_j + (uint64_t)q0[h] * (1ull << h)) % r;
    out.c_ij_j = (uint32_t)((r - acc_j) % r);

    return true;
}

bool generate_triple_rot(
    uint32_t r, uint32_t n,
    std::vector<dao_abb_triple>& out, BN_CTX* ctx)
{
    out.clear();
    if (r < 2 || n < 2 || !ctx) return false;
    dao_mpc_field f; f.r = r;

    // Step 1: local randoms a_i, b_i.
    std::vector<uint32_t> a(n), b(n);
    BIGNUM* rmod = BN_new();
    BIGNUM* tmp  = BN_new();
    if (!rmod || !tmp) { BN_free(rmod); BN_free(tmp); return false; }
    BN_set_word(rmod, r);
    for (uint32_t i = 0; i < n; ++i) {
        if (!BN_priv_rand_range(tmp, rmod) ||
            !BN_priv_rand_range(tmp, rmod))
        { BN_free(rmod); BN_free(tmp); return false; }
        a[i] = (uint32_t)BN_get_word(tmp);
        // Note: get_word consumes tmp; refill for b.
        if (!BN_priv_rand_range(tmp, rmod))
        { BN_free(rmod); BN_free(tmp); return false; }
        b[i] = (uint32_t)BN_get_word(tmp);
    }
    BN_free(rmod); BN_free(tmp);

    // Step 2-3: pairwise FROT for cross-term shares.
    // c_sender[i][j] = P_i's share in pair (i,j) [i sender, j receiver]
    // c_receiver[j][i] = P_j's share in pair (i,j) [j receiver]
    std::vector<std::vector<uint32_t>> c_sender(n, std::vector<uint32_t>(n, 0));
    std::vector<std::vector<uint32_t>> c_receiver(n, std::vector<uint32_t>(n, 0));
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) continue;
            dao_rot_cross_terms ct;
            if (!frot_simulate_cross_terms(r, a[i], b[j], ct, ctx))
                return false;
            c_sender[i][j]   = ct.c_ij_i;
            c_receiver[j][i] = ct.c_ij_j;
        }
    }

    // Step 4: local accumulation.
    out.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t ci = f.mul(a[i], b[i]);
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) continue;
            ci = f.add(ci, c_sender[i][j]);
            ci = f.add(ci, c_receiver[i][j]);
        }
        out[i].a.value = a[i];
        out[i].b.value = b[i];
        out[i].c.value = ci;
    }

    // Post-condition: sum(a)*sum(b) == sum(c).
    uint32_t sa = 0, sb = 0, sc = 0;
    for (uint32_t i = 0; i < n; ++i) {
        sa = f.add(sa, a[i]);
        sb = f.add(sb, b[i]);
        sc = f.add(sc, out[i].c.value);
    }
    if (f.mul(sa, sb) != sc) { out.clear(); return false; }

    return true;
}

bool generate_triples_rot_batch(
    uint32_t r, uint32_t n, uint32_t count,
    std::vector<std::vector<dao_abb_triple>>& out, BN_CTX* ctx)
{
    out.clear();
    if (count == 0) return false;
    out.resize(n);
    for (uint32_t k = 0; k < count; ++k) {
        std::vector<dao_abb_triple> one;
        if (!generate_triple_rot(r, n, one, ctx)) {
            out.clear();
            return false;
        }
        for (uint32_t i = 0; i < n; ++i) out[i].push_back(one[i]);
    }
    return true;
}

uint64_t dao_rot_bytes_per_party_per_triple(uint32_t r, uint32_t n)
{
    if (r < 2 || n < 2) return 0;
    const uint64_t k = dao_rot_k_of(r);
    return (uint64_t)(n - 1) * (128ull * k + k * k);
}

// ================================================================
// F_Rand-based Combine (step 5).
// ================================================================

bool frand_common(const dao_rot_frand_ctx& ctx, uint32_t attempt,
                  uint32_t modulus, uint32_t& r)
{
    if (modulus < 2) return false;

    std::vector<uint8_t> buf;
    // Domain separator first (length-extension hygiene).
    static const char dom[] = "VeilRoot-ROT-FRAND-V1";
    buf.insert(buf.end(), dom, dom + sizeof(dom));   // includes NUL
    buf.insert(buf.end(), ctx.proposal_id, ctx.proposal_id + 32);
    buf.insert(buf.end(), ctx.committee_id_hash, ctx.committee_id_hash + 32);
    auto p32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) buf.push_back((uint8_t)(v >> (8*i)));
    };
    auto p16 = [&](uint16_t v) {
        for (int i = 0; i < 2; ++i) buf.push_back((uint8_t)(v >> (8*i)));
    };
    p32(ctx.candidate_id);
    buf.push_back(ctx.factor);
    p16(ctx.crt_index);
    p16(ctx.mul_level);
    p16(ctx.mul_node);
    p32(ctx.triple_index);
    p32(attempt);

    uint8_t h[32];
    SHA256(buf.data(), buf.size(), h);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)h[i]) << (8*i);
    r = (uint32_t)(v % modulus);
    return true;
}

bool sample_nonzero_common_field_element(const dao_rot_frand_ctx& ctx,
                                         uint32_t modulus, uint32_t& r)
{
    if (modulus < 2) return false;
    for (uint32_t attempt = 0; attempt < DAO_ROT_MAX_FRAND_ATTEMPTS; ++attempt) {
        uint32_t v = 0;
        if (!frand_common(ctx, attempt, modulus, v)) return false;
        if (v != 0) { r = v; return true; }
    }
    return false;
}

bool combine_triple(const dao_mpc_field& field, uint32_t common_r,
                    uint32_t raw_a_i, uint32_t raw_b_i, uint32_t raw_c_i,
                    uint32_t& a_i, uint32_t& b_i, uint32_t& c_i)
{
    if (!field.valid() || common_r == 0) return false;
    if (common_r >= field.r) return false;
    if (raw_a_i >= field.r || raw_b_i >= field.r || raw_c_i >= field.r)
        return false;
    a_i = field.mul(common_r, raw_a_i);
    b_i = raw_b_i;
    c_i = field.mul(common_r, raw_c_i);
    return true;
}

bool generate_triple_rot_full(uint32_t field_modulus, uint32_t n,
                              const dao_rot_frand_ctx& ctx,
                              std::vector<dao_abb_triple>& out,
                              BN_CTX* bn_ctx)
{
    out.clear();
    if (field_modulus < 2 || n < 2 || !bn_ctx) return false;
    dao_mpc_field f; f.r = field_modulus;

    // Steps 1-4: Multiply phase.
    std::vector<dao_abb_triple> raw;
    if (!generate_triple_rot(field_modulus, n, raw, bn_ctx)) return false;
    if (raw.size() != n) return false;

    // Step 5: Combine, scalar nonzero r.
    uint32_t r = 0;
    if (!sample_nonzero_common_field_element(ctx, field_modulus, r))
        return false;

    out.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t ai = 0, bi = 0, ci = 0;
        if (!combine_triple(f, r, raw[i].a.value, raw[i].b.value,
                            raw[i].c.value, ai, bi, ci)) {
            out.clear();
            return false;
        }
        out[i].a.value = ai;
        out[i].b.value = bi;
        out[i].c.value = ci;
    }

    // Post-condition: sum(a)*sum(b) == sum(c).
    uint32_t sa = 0, sb = 0, sc = 0;
    for (uint32_t i = 0; i < n; ++i) {
        sa = f.add(sa, out[i].a.value);
        sb = f.add(sb, out[i].b.value);
        sc = f.add(sc, out[i].c.value);
    }
    if (f.mul(sa, sb) != sc) { out.clear(); return false; }
    return true;
}

// ================================================================
// Pi_InputTuple (Fig. 18 ACM / Fig. 14 ePrint revision).
// ================================================================

bool input_tuple_generate(const dao_mpc_field& field, uint32_t n,
                          uint32_t owner, dao_input_tuple& out,
                          BN_CTX* ctx)
{
    out = dao_input_tuple{};
    if (!field.valid() || n < 2 || owner < 1 || owner > n || !ctx)
        return false;

    BIGNUM* rmod = BN_new();
    BIGNUM* tmp  = BN_new();
    if (!rmod || !tmp) { BN_free(rmod); BN_free(tmp); return false; }
    BN_set_word(rmod, field.r);

    // Step 1: P_owner samples r <- F.
    if (!BN_priv_rand_range(tmp, rmod)) {
        BN_free(rmod); BN_free(tmp); return false;
    }
    const uint32_t r = (uint32_t)BN_get_word(tmp);

    // Step 2 (concrete): pairwise private rho_i for every i != owner.
    out.shares.assign(n, 0);
    uint32_t accum = 0;
    for (uint32_t i = 1; i <= n; ++i) {
        if (i == owner) continue;
        if (!BN_priv_rand_range(tmp, rmod)) {
            BN_free(rmod); BN_free(tmp); out = dao_input_tuple{}; return false;
        }
        const uint32_t rho = (uint32_t)BN_get_word(tmp);
        out.shares[i - 1] = rho;
        accum = field.add(accum, rho);
    }
    out.shares[owner - 1] = field.sub(r, accum);
    out.r = r;

    BN_free(rmod); BN_free(tmp);

    // Post-condition: sum of shares == r.
    uint32_t s = 0;
    for (uint32_t i = 0; i < n; ++i) s = field.add(s, out.shares[i]);
    if (s != r) { out = dao_input_tuple{}; return false; }
    return true;
}

bool input_mask_broadcast(const dao_mpc_field& field,
                          uint32_t x, uint32_t r, uint32_t& eps_out)
{
    if (!field.valid() || x >= field.r || r >= field.r) return false;
    eps_out = field.sub(x, r);
    return true;
}

bool input_share_apply(const dao_mpc_field& field,
                       uint32_t party_index,
                       uint32_t share_of_r, uint32_t eps,
                       uint32_t& share_of_x_out)
{
    if (!field.valid() || party_index < 1) return false;
    if (share_of_r >= field.r || eps >= field.r) return false;
    // eps to party 1's share only. All other shares unchanged.
    if (party_index == 1) {
        share_of_x_out = field.add(share_of_r, eps);
    } else {
        share_of_x_out = share_of_r;
    }
    return true;
}

uint64_t input_tuple_count(uint32_t candidates, uint32_t factors,
                           uint32_t primes, uint32_t n)
{
    return (uint64_t)candidates * (uint64_t)factors
         * (uint64_t)primes * (uint64_t)n;
}

// ================================================================
// Figure 19 Multiply driven by Figure 18 input tuples.
// ================================================================

bool generate_triple_rot_with_inputs(uint32_t field_modulus, uint32_t n,
                                     std::vector<dao_abb_triple>& out,
                                     BN_CTX* ctx)
{
    out.clear();
    if (field_modulus < 2 || n < 2 || !ctx) return false;
    dao_mpc_field f; f.r = field_modulus;

    // ---- Figure 18: two input tuples per party (a_i and b_i) ----
    // a[i] and b[i] are independent private values the owner chooses
    // to input; they must not equal the tuple's r, otherwise eps = 0
    // and the input mechanism is not exercised.
    std::vector<dao_input_tuple> ta(n), tb(n);
    std::vector<uint32_t> a(n), b(n);
    BIGNUM* rmod = BN_new();
    BIGNUM* tmp  = BN_new();
    if (!rmod || !tmp) { BN_free(rmod); BN_free(tmp); return false; }
    BN_set_word(rmod, f.r);
    for (uint32_t i = 0; i < n; ++i) {
        if (!input_tuple_generate(f, n, i + 1, ta[i], ctx)) {
            BN_free(rmod); BN_free(tmp); return false;
        }
        if (!input_tuple_generate(f, n, i + 1, tb[i], ctx)) {
            BN_free(rmod); BN_free(tmp); return false;
        }
        if (!BN_priv_rand_range(tmp, rmod)) {
            BN_free(rmod); BN_free(tmp); return false;
        }
        a[i] = (uint32_t)BN_get_word(tmp);
        if (!BN_priv_rand_range(tmp, rmod)) {
            BN_free(rmod); BN_free(tmp); return false;
        }
        b[i] = (uint32_t)BN_get_word(tmp);
    }
    BN_free(rmod); BN_free(tmp);

    // ---- ABBWithErrors.Input: broadcast eps, derive shares ----
    std::vector<uint32_t> eps_a(n), eps_b(n);
    for (uint32_t i = 0; i < n; ++i) {
        if (!input_mask_broadcast(f, a[i], ta[i].r, eps_a[i])) return false;
        if (!input_mask_broadcast(f, b[i], tb[i].r, eps_b[i])) return false;
    }
    // a_sh[owner][party] = party's share of owner's a value.
    std::vector<std::vector<uint32_t>> a_sh(
        n, std::vector<uint32_t>(n, 0));
    std::vector<std::vector<uint32_t>> b_sh(
        n, std::vector<uint32_t>(n, 0));
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (!input_share_apply(f, j + 1, ta[i].shares[j],
                                   eps_a[i], a_sh[i][j]))
                return false;
            if (!input_share_apply(f, j + 1, tb[i].shares[j],
                                   eps_b[i], b_sh[i][j]))
                return false;
        }
    }
    // Conformance: each reconstructed value must equal the owner's input.
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t sa = 0, sb = 0;
        for (uint32_t j = 0; j < n; ++j) {
            sa = f.add(sa, a_sh[i][j]);
            sb = f.add(sb, b_sh[i][j]);
        }
        if (sa != a[i] || sb != b[i]) return false;
    }

    // ---- Figure 19 Multiply (same arithmetic as generate_triple_rot) ----
    std::vector<std::vector<uint32_t>> c_sender(
        n, std::vector<uint32_t>(n, 0));
    std::vector<std::vector<uint32_t>> c_receiver(
        n, std::vector<uint32_t>(n, 0));
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) continue;
            dao_rot_cross_terms ct;
            if (!frot_simulate_cross_terms(f.r, a[i], b[j], ct, ctx))
                return false;
            c_sender[i][j]   = ct.c_ij_i;
            c_receiver[j][i] = ct.c_ij_j;
        }
    }
    std::vector<uint32_t> c(n, 0);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t ci = f.mul(a[i], b[i]);
        for (uint32_t j = 0; j < n; ++j) {
            if (i == j) continue;
            ci = f.add(ci, c_sender[i][j]);
            ci = f.add(ci, c_receiver[i][j]);
        }
        c[i] = ci;
    }

    // ---- Assemble raw triple from input shares + c accumulation ----
    out.resize(n);
    for (uint32_t j = 0; j < n; ++j) {
        uint32_t aj = 0, bj = 0;
        for (uint32_t i = 0; i < n; ++i) {
            aj = f.add(aj, a_sh[i][j]);
            bj = f.add(bj, b_sh[i][j]);
        }
        out[j].a.value = aj;
        out[j].b.value = bj;
        out[j].c.value = c[j];
    }

    // Post-condition.
    uint32_t sa = 0, sb = 0, sc = 0;
    for (uint32_t i = 0; i < n; ++i) {
        sa = f.add(sa, out[i].a.value);
        sb = f.add(sb, out[i].b.value);
        sc = f.add(sc, out[i].c.value);
    }
    if (f.mul(sa, sb) != sc) { out.clear(); return false; }
    return true;
}

bool combine_triple_vector(const dao_mpc_field& field, uint32_t common_r,
                           const std::vector<dao_abb_triple>& raw,
                           std::vector<dao_abb_triple>& out)
{
    out.clear();
    if (!field.valid() || raw.empty()) return false;
    out.resize(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (!combine_triple(field, common_r,
                            raw[i].a.value, raw[i].b.value, raw[i].c.value,
                            out[i].a.value, out[i].b.value, out[i].c.value))
            { out.clear(); return false; }
    }
    return true;
}

// ---- dao_triple_store ----

bool dao_triple_store::insert(uint32_t sid, const dao_abb_triple& t)
{
    if (consumed_.count(sid)) return false;
    if (unconsumed_.count(sid)) return false;
    unconsumed_[sid] = t;
    return true;
}

bool dao_triple_store::consume(uint32_t sid, dao_abb_triple& t)
{
    auto it = unconsumed_.find(sid);
    if (it == unconsumed_.end()) return false;
    t = it->second;
    unconsumed_.erase(it);
    consumed_.insert(sid);
    return true;
}

bool dao_triple_store::contains(uint32_t sid) const
{
    return unconsumed_.count(sid) > 0 || consumed_.count(sid) > 0;
}

}} // namespace
