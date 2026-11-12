#pragma once
#include <cstdint>
#include <vector>
#include <openssl/bn.h>
#include "dao_mpc.h"

namespace cryptonote { namespace dao {

// Eratosthenes FABBWithErrors interface.
//
// PRODUCTION STATUS:
//   - beaver_multiply: correct, per paper Fig.17. Ships.
//   - generate_consistent_triples_trusted_dealer: TEST/BENCHMARK ONLY.
//     Trusted-dealer triple generation, insecure against malicious
//     party 1. Used to MEASURE the online-only beaver cost separately
//     from preprocessing cost.
//   - Distributed triple generation (MASCOT/KOS-style OT): NOT
//     IMPLEMENTED. Awaiting spec. Current production baseline uses
//     dao_mpc_mul::multiply (VSS-based GRR) for triples — slow but
//     actively secure. Replacing it is the wall-clock fix.
//
// Active security of the FULL pipeline comes from the runner-level
// delayed consistency + masked GCD checks. ABB itself is
// semi-honest.

struct dao_abb_share { uint32_t value = 0; };

struct dao_abb_triple {
    dao_abb_share a;   // additive share of masking value a
    dao_abb_share b;   // additive share of masking value b
    dao_abb_share c;   // additive share of a*b
};

// Session binding for one ABB operation. Prevents triple replay
// across (proposal, candidate, factor, crt_index, tree node).
struct dao_abb_session {
    uint32_t candidate_id = 0;
    uint8_t  factor       = 0;   // 0 = P, 1 = Q
    uint16_t crt_index    = 0;
    uint16_t mul_level    = 0;
    uint16_t mul_node     = 0;
};

class dao_mpc_abb {
public:
    dao_mpc_abb() = default;

    // Bind this ABB instance to a session and field.
    bool initialize(const dao_abb_session& session, uint32_t field_modulus);

    // Beaver multiplication (Eratosthenes Fig.17).
    // Inputs:
    //   f                field descriptor
    //   party_id         1-based, 1..committee_size
    //   committee_size   n
    //   x_i, y_i         this party's additive shares of x and y
    //   triple_i         this party's share of a preprocessed triple
    //   opening_e        public opened value of (x - a) mod r
    //   opening_rho      public opened value of (y - b) mod r
    // Output: z_i, this party's additive share of x*y.
    // Behaviour: designated party (party_id == 1) absorbs the public
    // e*rho term. Every other party contributes only locally.
    static bool beaver_multiply(
        const dao_mpc_field& f,
        uint32_t party_id, uint32_t committee_size,
        const dao_abb_share& x_i,
        const dao_abb_share& y_i,
        const dao_abb_triple& triple_i,
        uint32_t opening_e,
        uint32_t opening_rho,
        dao_abb_share& z_i);

    uint32_t field_modulus() const { return r_; }
    const dao_abb_session& session() const { return session_; }

private:
    dao_abb_session session_;
    uint32_t        r_ = 0;
};

// TEST/BENCHMARK ONLY. Trusted-dealer triple generation.
// Produces n*count consistent random triples: for each k,
// sum_i out[i][k].a = a_k, sum_i out[i][k].b = b_k,
// sum_i out[i][k].c = a_k * b_k mod r.
// NOT SECURE: caller sees all shares of a, b, c. Used only to
// measure online Beaver cost in isolation from preprocessing.
bool generate_consistent_triples_trusted_dealer(
    uint32_t n, uint32_t r, uint32_t count,
    std::vector<std::vector<dao_abb_triple>>& out, BN_CTX* ctx);

}} // namespace
