#pragma once
#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include <openssl/bn.h>
#include "dao_mpc.h"
#include "dao_mpc_abb.h"

namespace cryptonote { namespace dao {

// Eratosthenes Figure 19 triple generation, steps 1-4.
//
// PRODUCTION STATUS:
//   - Steps 1-4: shipped, source-specified. Fully correct.
//   - Step 5 (FRand Combine): NOT shipped. Awaiting spec.
//     See frot_cross_terms / generate_triple_rot doc below.
//   - FROT backend: in-process simulation for tests. Real FROT
//     (MP-SPDZ Semi or SoftSpokenOT) plugs in via the interface
//     later; arithmetic is identical.
//
// Active-security comes from the runner-level delayed consistency +
// masked GCD checks, not from the sampling multiplications.

struct dao_rot_cross_terms {
    uint32_t c_ij_i = 0;   // P_i's share of a_i * b_j (sender side)
    uint32_t c_ij_j = 0;   // P_j's share of a_i * b_j (receiver side)
};

// ceil(log2(r)) — bit length of field modulus.
uint32_t dao_rot_k_of(uint32_t r);

// Simulated in-process FROT for one ordered pair (sender P_i with a_i,
// receiver P_j with b_j). Returns c_ij_i, c_ij_j such that
// c_ij_i + c_ij_j == a_i * b_j mod r. Semi-honest, correctness only;
// does NOT provide OT privacy (both parties simulated in one process).
bool frot_simulate_cross_terms(
    uint32_t r, uint32_t a_i, uint32_t b_j,
    dao_rot_cross_terms& out, BN_CTX* ctx);

// Full triple generation for one field r: Figure 19 steps 1-4 only.
// Produces n additive shares of (a, b, c) with sum(a)*sum(b) == sum(c).
// No FRand combine.
bool generate_triple_rot(
    uint32_t r, uint32_t n,
    std::vector<dao_abb_triple>& out, BN_CTX* ctx);

// Batch: count triples per field r.
bool generate_triples_rot_batch(
    uint32_t r, uint32_t n, uint32_t count,
    std::vector<std::vector<dao_abb_triple>>& out, BN_CTX* ctx);

// Communication cost per party per triple:
//   (n - 1) * (128 * k + k^2) bits
uint64_t dao_rot_bytes_per_party_per_triple(uint32_t r, uint32_t n);

// Session-bound triple store. Refuses double consumption. Replay
// prevention at the storage layer; the actual session binding
// (proposal/candidate/factor/crt/node) is the caller's responsibility
// via the session_id key.
// ================================================================
// F_Rand-based Combine (Eratosthenes Figure 19, step 5).
//
// Scalar multiplication by a common random r.
//   a_i' = r * raw_a_i
//   b_i' = raw_b_i
//   c_i' = r * raw_c_i
// r is nonzero (rejection-sampled), same for all committee members.
// The hatted branch of Figure 19 is a MASCOT vestige and is NOT
// exposed as an additional consumable triple.
//
// Session context. Production should mix chain entropy (e.g., block
// hash at proposal activation) into proposal_id before use, for
// defense-in-depth. This in-process version derives r deterministically
// from SHA-256(session_ctx || attempt); no single party chooses r.
// ================================================================

struct dao_rot_frand_ctx {
    uint8_t  proposal_id[32]      = {};
    uint8_t  committee_id_hash[32] = {};
    uint32_t candidate_id         = 0;
    uint8_t  factor               = 0;   // 0=P, 1=Q
    uint16_t crt_index            = 0;
    uint16_t mul_level            = 0;
    uint16_t mul_node             = 0;
    uint32_t triple_index         = 0;
};

constexpr uint32_t DAO_ROT_MAX_FRAND_ATTEMPTS = 64;

// Common random field element for all committee members.
bool frand_common(const dao_rot_frand_ctx& ctx, uint32_t attempt,
                  uint32_t modulus, uint32_t& r);

// Nonzero sampling (VeilRoot safeguard for small fields).
bool sample_nonzero_common_field_element(const dao_rot_frand_ctx& ctx,
                                         uint32_t modulus, uint32_t& r);

// Beaver Combine step (scalar).
bool combine_triple(const dao_mpc_field& field, uint32_t common_r,
                    uint32_t raw_a_i, uint32_t raw_b_i, uint32_t raw_c_i,
                    uint32_t& a_i, uint32_t& b_i, uint32_t& c_i);

// Production triple: Multiply (steps 1-4) + Combine (step 5).
// Returns the combined triple. Hatted branch not exposed.
bool generate_triple_rot_full(uint32_t field_modulus, uint32_t n,
                              const dao_rot_frand_ctx& ctx,
                              std::vector<dao_abb_triple>& out,
                              BN_CTX* bn_ctx);

// ================================================================
// Pi_InputTuple — Eratosthenes Appendix C (Fig. 18 ACM / Fig. 14
// ePrint revision). Verbatim:
//
//   Input: On Input (Input, Pj) from all parties do the following:
//     1. Pj samples r <- F
//     2. All parties output [r] and Pj outputs r.
//
// Concrete realization of step 2: Pj samples rho_i <- F for every
// i != j, delivers rho_i to P_i over a pairwise private channel, and
// sets its own share to r - sum_{i!=j} rho_i. Then sum_i [r]_i = r.
// Pj is the input owner; there is no trusted dealer.
//
// Consumption (Pi_ABBWithErrors, same appendix):
//   To share x_i, P_i takes (r_i, [r_i]) and:
//     1. Broadcast eps <- x_i - r_i
//     2. [x_i] <- [r_i] + eps
//
// Counts for a batch: I = C * 2 * L * n input tuples (two per party
// per prime per factor: one for a_i, one for b_i).
// ================================================================

struct dao_input_tuple
{
    uint32_t              r = 0;   // known to the OWNER only
    std::vector<uint32_t> shares;  // n additive shares; sum == r mod field
};

// Step 1 + concrete step 2. `owner` is 1-based.
bool input_tuple_generate(const dao_mpc_field& field, uint32_t n,
                          uint32_t owner, dao_input_tuple& out,
                          BN_CTX* ctx);

// ABBWithErrors.Input, line 1: eps = x - r (broadcast).
bool input_mask_broadcast(const dao_mpc_field& field,
                          uint32_t x, uint32_t r, uint32_t& eps_out);

// ABBWithErrors.Input, line 2. Correct semantic of "[x]_i = [r]_i +
// eps" for additive shares that sum to the value: eps is added to a
// SINGLE designated party's share (party_index == 1), not to every
// share. Then sum_i([x]_i) = sum_i([r]_i) + eps = r + (x - r) = x.
// Adding eps to every share would give sum = r + n*eps, not x.
bool input_share_apply(const dao_mpc_field& field,
                       uint32_t party_index,   // 1-based; eps lands here iff == 1
                       uint32_t share_of_r, uint32_t eps,
                       uint32_t& share_of_x_out);

// Input-tuple count for a batch: C * factors * L * n.
uint64_t input_tuple_count(uint32_t candidates, uint32_t factors,
                           uint32_t primes, uint32_t n);

// Figure 19 Multiply with Figure 18 input tuples consumed for a and b.
// Produces the raw (pre-Combine) triple. The a/b components are the
// ABB input shares of each party's a_i / b_i; the c component is the
// FROT accumulation. Equivalent in distribution to generate_triple_rot,
// but exercises the input path the wire protocol uses.
bool generate_triple_rot_with_inputs(uint32_t field_modulus, uint32_t n,
                                     std::vector<dao_abb_triple>& out,
                                     BN_CTX* ctx);

// Apply Combine to a whole raw triple vector (scalar r, nonzero).
bool combine_triple_vector(const dao_mpc_field& field, uint32_t common_r,
                           const std::vector<dao_abb_triple>& raw,
                           std::vector<dao_abb_triple>& out);

class dao_triple_store
{


public:
    bool insert(uint32_t session_id, const dao_abb_triple& t);
    bool consume(uint32_t session_id, dao_abb_triple& t);
    bool contains(uint32_t session_id) const;
    size_t unconsumed() const { return unconsumed_.size(); }
    size_t consumed()   const { return consumed_.size(); }

private:
    std::map<uint32_t, dao_abb_triple> unconsumed_;
    std::set<uint32_t>                 consumed_;
};

}} // namespace
