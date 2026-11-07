#pragma once
#include <cstdint>
#include <vector>
#include <openssl/bn.h>
#include "dao_dkg.h"

namespace cryptonote { namespace dao {

struct dao_mpc_field
{
    uint32_t r = 0;
    bool valid() const { return r > 2; }
    uint32_t add(uint32_t a, uint32_t b) const;
    uint32_t sub(uint32_t a, uint32_t b) const;
    uint32_t mul(uint32_t a, uint32_t b) const;
    uint32_t inv(uint32_t a) const;
};

// Pedersen VSS of an F_r secret over the existing Schnorr group
// (dao_vss_group). All coefficients sampled in [0, r); commitments
// C_k = g^{a_k} * h^{b_k} mod P; shares/blindings are small integers
// < r * n^t and therefore < P_prime for any reachable parameter set.
struct dao_mpc_vss
{
    static bool deal(const dao_mpc_field& f, const dao_vss_group& grp,
                     uint32_t secret, uint32_t n, uint32_t t,
                     dao_vss_commitments& commits_out,
                     std::vector<BIGNUM*>& shares_out,
                     std::vector<BIGNUM*>& blindings_out,
                     BN_CTX* ctx);

    static bool verify(const dao_mpc_field& f, const dao_vss_group& grp,
                       const dao_vss_commitments& commits, uint32_t i,
                       const BIGNUM* share, const BIGNUM* blinding,
                       BN_CTX* ctx);

    static bool reconstruct(const dao_mpc_field& f,
                            const std::vector<const BIGNUM*>& shares,
                            const std::vector<uint32_t>& indices,
                            uint32_t t, uint32_t& out, BN_CTX* ctx);
};

// Gennaro-Rabin-Rabin secure multiplication with VSS degree reduction.
// Honest majority required: n >= 2t + 1.
struct dao_mpc_mul
{
    static bool multiply(const dao_mpc_field& f, const dao_vss_group& grp,
                         uint32_t n, uint32_t t,
                         const std::vector<const BIGNUM*>& shares_a,
                         const std::vector<const BIGNUM*>& shares_b,
                         std::vector<BIGNUM*>& shares_out, BN_CTX* ctx);

    // Stepwise decomposition of the same Gennaro-Rabin-Rabin protocol.
    // Each party runs these three calls independently, exchanging only
    // the committed VSS shares and public commitments with peers. The
    // wire version of the sieve round drives exactly these three steps
    // against dkg_transport. This in-process triple is the isolation
    // test for that later integration.

    // Step 1 (party i): c_i = a_i * b_i mod r. No peer input.
    static bool local_product(const dao_mpc_field& f,
                              const BIGNUM* a_i, const BIGNUM* b_i,
                              uint32_t& c_i);

    // Step 2 (party i): VSS-deal of c_i to all n parties at degree t.
    // Alias of dao_mpc_vss::deal exposed at the GRR layer for symmetry.
    static bool deal_c(const dao_mpc_field& f, const dao_vss_group& grp,
                       uint32_t c_i, uint32_t n, uint32_t t,
                       dao_vss_commitments& commits_out,
                       std::vector<BIGNUM*>& shares_out,
                       std::vector<BIGNUM*>& blindings_out,
                       BN_CTX* ctx);

    // Step 3 (party i): given c_d(i) from every dealer d = 1..n,
    // Lagrange-combine over the fixed size-(2t+1) subset {1,..,2t+1}
    // to obtain this party's degree-t share of a*b. Deterministic
    // given n, t.
    static bool combine_c_shares(const dao_mpc_field& f,
                                 const std::vector<const BIGNUM*>& my_received_shares,
                                 uint32_t n, uint32_t t,
                                 uint32_t& out_share);

    // Convert n Shamir shares (degree-t sharing of v at points 1..n)
    // into n additive shares whose plain sum is v mod r. Uses the
    // n-point Lagrange coefficients at 0. Required by the CRT sieve:
    // the sieved contribution must be an additive-share sum so that
    // the aggregate modulus inherits coprimality to the sieve primes.
    static bool to_additive_shares(const dao_mpc_field& f, uint32_t n,
                                    const std::vector<const BIGNUM*>& shamir_shares,
                                    std::vector<uint32_t>& additive_out);

    // Balanced-tree n-way product of independent shares. Input:
    // shares[k][i] = party i's share of the k-th operand in F_r,
    // k = 0..m-1. Output: out[i] = party i's degree-t share of
    // (prod_k input_k). Depth = ceil(log2(m)). Uses one
    // dao_mpc_mul::multiply per internal node. Odd layers pad by
    // forwarding the unpaired value unchanged (identity for multiply
    // at that layer is already encoded: the accumulated product is
    // passed through, no special-case constant required).
    //
    // In-process only. The wire version will drive one level at a
    // time through dkg_transport with a dao_sieve_entry_id per node.
    static bool multiply_tree(const dao_mpc_field& f, const dao_vss_group& grp,
                              uint32_t n, uint32_t t,
                              const std::vector<std::vector<const BIGNUM*>>& shares_in,
                              std::vector<BIGNUM*>& shares_out, BN_CTX* ctx);
};

// One pairwise zero-sum mask for edge (i, j) with i < j. Party i adds
// rho; party j subtracts. Sum over all edges = 0 in F_r.
// In-process generation is via generate_pair_masks(). Wire delivery
// binds each rho to (proposal, candidate, factor, crt_index,
// multiplication_node, i, j) via the caller's message envelope; a
// failed delivery aborts the candidate, never substitutes zero.
struct dao_pair_mask
{
    uint32_t i = 0;    // 1-based, i < j
    uint32_t j = 0;
    uint32_t rho = 0;  // in F_r
};

struct dao_mpc_randomize
{
    // Generate n*(n-1)/2 fresh pair masks via BN_priv_rand_range.
    static bool generate_pair_masks(const dao_mpc_field& f, uint32_t n,
                                    std::vector<dao_pair_mask>& out);
};

struct dao_mpc_additive
{
    // Baseline (unmasked) additive shares via Lagrange-on-Shamir.
    // Sum_i out[i] == f(0) mod r. Dim n-1, not full FABB distribution.
    static bool to_additive_shares(const dao_mpc_field& f, uint32_t n,
                                    const std::vector<const BIGNUM*>& shamir_shares,
                                    std::vector<uint32_t>& out);

    // Full FABBWithErrors.Share: baseline + pairwise zero-sum masks.
    // Sum is preserved. Distribution is uniform over the fixed-sum
    // subspace when the honest parties' edges form a connected
    // subgraph (true for honest-majority t < n/2).
    // masks must contain exactly n*(n-1)/2 entries, one per (i,j) i<j.
    static bool to_additive_shares_masked(
        const dao_mpc_field& f, uint32_t n,
        const std::vector<const BIGNUM*>& shamir_shares,
        const std::vector<dao_pair_mask>& masks,
        std::vector<uint32_t>& out);

    // Party-local variant for wire: uses only masks incident to `me`.
    static bool to_additive_shares_masked_party(
        const dao_mpc_field& f, uint32_t me, uint32_t n,
        const std::vector<const BIGNUM*>& shamir_shares,
        const std::vector<dao_pair_mask>& my_masks,
        uint32_t& out);
};

}} // namespace
