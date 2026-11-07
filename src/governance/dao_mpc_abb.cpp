#include "dao_mpc_abb.h"

namespace cryptonote { namespace dao {

bool dao_mpc_abb::initialize(const dao_abb_session& s, uint32_t r)
{
    if (r < 3) return false;
    session_ = s;
    r_ = r;
    return true;
}

bool dao_mpc_abb::beaver_multiply(
    const dao_mpc_field& f,
    uint32_t party_id, uint32_t committee_size,
    const dao_abb_share& x_i, const dao_abb_share& y_i,
    const dao_abb_triple& triple_i,
    uint32_t opening_e, uint32_t opening_rho,
    dao_abb_share& z_i)
{
    if (!f.valid()) return false;
    if (party_id < 1 || party_id > committee_size) return false;
    if (opening_e >= f.r || opening_rho >= f.r) return false;
    if (x_i.value >= f.r || y_i.value >= f.r) return false;
    if (triple_i.a.value >= f.r || triple_i.b.value >= f.r
        || triple_i.c.value >= f.r) return false;

    // z_i = c_i + e * b_i + rho * a_i + delta_{i,1} * e * rho
    uint32_t zi = triple_i.c.value;
    zi = f.add(zi, f.mul(opening_e, triple_i.b.value));
    zi = f.add(zi, f.mul(opening_rho, triple_i.a.value));
    if (party_id == 1) {
        zi = f.add(zi, f.mul(opening_e, opening_rho));
    }
    z_i.value = zi;
    return true;
}

bool generate_consistent_triples_trusted_dealer(
    uint32_t n, uint32_t r, uint32_t count,
    std::vector<std::vector<dao_abb_triple>>& out, BN_CTX* ctx)
{
    out.clear();
    if (n < 3 || r < 3 || count == 0 || !ctx) return false;
    out.assign(n, std::vector<dao_abb_triple>(count));

    dao_mpc_field f; f.r = r;
    BIGNUM* rmod = BN_new();
    BIGNUM* tmp  = BN_new();
    if (!rmod || !tmp) { BN_free(rmod); BN_free(tmp); return false; }
    BN_set_word(rmod, r);

    for (uint32_t k = 0; k < count; ++k) {
        std::vector<uint32_t> a_i(n), b_i(n), c_i(n);
        for (uint32_t i = 0; i < n; ++i) {
            if (!BN_priv_rand_range(tmp, rmod)) {
                BN_free(rmod); BN_free(tmp); return false;
            }
            a_i[i] = (uint32_t)BN_get_word(tmp);
            if (!BN_priv_rand_range(tmp, rmod)) {
                BN_free(rmod); BN_free(tmp); return false;
            }
            b_i[i] = (uint32_t)BN_get_word(tmp);
        }
        uint32_t a_sum = 0, b_sum = 0;
        for (uint32_t i = 0; i < n; ++i) {
            a_sum = f.add(a_sum, a_i[i]);
            b_sum = f.add(b_sum, b_i[i]);
        }
        const uint32_t c_total = f.mul(a_sum, b_sum);

        uint32_t accum = 0;
        for (uint32_t i = 0; i + 1 < n; ++i) {
            if (!BN_priv_rand_range(tmp, rmod)) {
                BN_free(rmod); BN_free(tmp); return false;
            }
            c_i[i] = (uint32_t)BN_get_word(tmp);
            accum = f.add(accum, c_i[i]);
        }
        c_i[n - 1] = f.sub(c_total, accum);

        for (uint32_t i = 0; i < n; ++i) {
            out[i][k].a.value = a_i[i];
            out[i][k].b.value = b_i[i];
            out[i][k].c.value = c_i[i];
        }
    }

    BN_free(rmod); BN_free(tmp);
    return true;
}

}} // namespace
