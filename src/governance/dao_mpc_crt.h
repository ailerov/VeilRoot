#pragma once
#include <cstdint>
#include <vector>
#include <openssl/bn.h>

namespace cryptonote { namespace dao {

// Eratosthenes / Chen style CRT distributed sieving primitives.
//
// PRODUCTION STATUS as of this commit:
//   - near_primorial_primes(): ships, used by production construction.
//   - sieve_product(): ships.
//   - sample_party_residues(): ships (each party samples u in [1,r)).
//   - crt_reconstruct(): ships.
//   - lift_to_range(): TEST-ONLY scaffolding. Chen's canonical CRT
//     reconstruction already yields contributions in the required
//     range with no additional lift; Eratosthenes uses [2^lambda,
//     2^{lambda+sigma}). This function does not match either. Do NOT
//     use in production. Removal scheduled once the corrected range
//     construction lands.
//
// BLOCKED, awaiting paper / expert:
//   - FABBWithErrors.Share additive-sharing distribution (current
//     to_additive_shares only proves the sum identity, not the
//     required distribution).
//   - Delayed consistency algorithm and bounds (a, v in zhat).
//   - Eratosthenes lift parameters (lambda, sigma).
struct dao_mpc_crt
{
    // Chen's near-primorial construction. Returns the ascending list
    // of odd primes {3, 5, 7, ...} such that the running product stays
    // strictly below 2^{kappa - floor(log2(n)) - 1}. For
    // kappa=1024, n in {3, 16}, this yields the published ~130
    // components with maximum prime 739.
    static bool near_primorial_primes(uint32_t kappa, uint32_t n,
                                      std::vector<uint32_t>& out);

    // Odd primes strictly less than B, ascending. Excludes 2.
    static bool sieved_primes(uint32_t B, std::vector<uint32_t>& out);

    // Q = prod primes.
    static bool sieve_product(const std::vector<uint32_t>& primes,
                              BIGNUM* Q_out, BN_CTX* ctx);

    // For each party i in [1..n], each prime r_j, draw u in [1, r_j-1].
    // out[i-1][j] = u_i^{r_j}. All strictly nonzero.
    static bool sample_party_residues(const std::vector<uint32_t>& primes,
                                      uint32_t n,
                                      std::vector<std::vector<uint32_t>>& out);

    // Given per-party residue vectors (each entry in [0, r_j)), CRT-reconstruct
    // each party's U_i in [0, Q). out has n BIGNUMs; caller owns.
    static bool crt_reconstruct(const std::vector<uint32_t>& primes,
                                const std::vector<std::vector<uint32_t>>& shares,
                                std::vector<BIGNUM*>& out, BN_CTX* ctx);

    // Lift U in [0, Q) into [2^{bits-1}, 2^{bits}) with U' === target_mod4 (mod 4),
    // preserving U' === U (mod r_j) for every sieved prime. Q must be odd.
    static bool lift_to_range(const BIGNUM* U, const BIGNUM* Q,
                              uint32_t bits, uint32_t target_mod4,
                              BIGNUM* out, BN_CTX* ctx);

    // ================================================================
    // PRODUCTION PATH (per Eratosthenes, expert confirmed):
    //
    // 1. M_s = prod(sieve primes), M_0 = 4*M_s.
    // 2. W_i = CRTRec({a_i^(r)}, 3*delta_{i,1} mod 4) in [0, M_0).
    // 3. p_i = W_i + k_i * M_0, with k_i uniform such that
    //    p_i in [L, U), L = ceil(2^lambda/n), U = ceil(2^(lambda+sigma)/n).
    // 4. Sum_i p_i in [2^lambda, 2^(lambda+sigma)).
    //
    // Reference parameters: lambda=1024, sigma=80 for a 2048-bit
    // minimum modulus (upper bound 2208-bit).
    // ================================================================

    // M_0 = 4 * prod(primes).
    static bool sieve_modulus_mod4(const std::vector<uint32_t>& primes,
                                   BIGNUM* M0_out, BN_CTX* ctx);

    // W_i = CRTRec({a_i^(r)}, 3*delta_{i,1} mod 4) in [0, M_0).
    // Out: n BIGNUMs, caller owns.
    static bool crt_reconstruct_with_mod4(
        const std::vector<uint32_t>& primes,
        const std::vector<std::vector<uint32_t>>& shares,
        std::vector<BIGNUM*>& out, BN_CTX* ctx);

    // p = W + k*M_0 uniform in [L, U). Exact helper from expert.
    // residue must be W (already including mod-4). modulus must be M_0.
    static bool reconstruct_to_contribution(
        const BIGNUM* residue, const BIGNUM* modulus,
        uint32_t lambda, uint32_t sigma, uint32_t committee_size,
        BIGNUM* out, BN_CTX* ctx);

    // All n parties: given W_i and M_0, produce p_i for each.
    static bool reconstruct_all_to_contributions(
        const std::vector<BIGNUM*>& W, const BIGNUM* M0,
        uint32_t lambda, uint32_t sigma,
        std::vector<BIGNUM*>& p_out, BN_CTX* ctx);
};

// Session binding for one sieve operation. Placed in the body of a
// typed sieve message, not in dkg_msg_header. Every sieve message
// must carry this so the recipient can bind it to the agreed
// (proposal, candidate, factor, crt modulus, product-tree node).
struct dao_sieve_entry_id
{
    uint32_t candidate_id           = 0;   // within a batch
    uint8_t  factor                 = 0;   // 0 = P, 1 = Q
    uint16_t crt_modulus_index      = 0;   // index into near-primorial list
    uint16_t multiplication_level   = 0;   // depth in balanced tree
    uint16_t multiplication_node    = 0;   // position at that level
};


}} // namespace
