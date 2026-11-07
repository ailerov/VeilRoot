#pragma once
#include <cstdint>
#include <vector>
#include <openssl/bn.h>
#include "dao_dkg.h"
#include "dao_mpc.h"
#include "dao_mpc_crt.h"

namespace cryptonote { namespace dao {

// One sieve factor (P or Q) over a dkg_transport.
//
// Runs the full pipeline at the given prime set:
//   1. Each party samples u_i per prime, VSS-deals it.
//   2. Wire: broadcast commits, unicast shares for every prime.
//   3. Successive multiplies acc_k = acc_{k-1} × u_k (VSS-based GRR).
//   4. Lagrange-to-additive over the final sharing.
//   5. CRT with mod-4 (party 1 = 3, others = 0).
//   6. Uniform lift to [L, U) = [ceil(2^1024/n), ceil(2^1104/n)).
//
// Uses raw transport try_recv/try_recv_own. Bypasses dkg_party (which
// would reject the sieve message types).
//
// Messages:
//   SIEVE_COMMIT (type 0x90): broadcast, sender_id, phase=100+factor,
//     round=prime_idx, tag32=multiply_level, vec_a=commitments.
//   SIEVE_SHARE  (type 0x91): unicast, same header, bytes_a=share,
//     bytes_b=blinding.
//
// Returns this party's contribution p_i (or q_i) in [L, U).
// Both factors (P then Q) in one call, with a shared pending buffer
// so messages from the second factor's sieve that arrive during the
// first factor's drain are not lost. The caller supplies an empty
// pending deque; it is cleared between calls.
//
// lambda, sigma: contribution range [ceil(2^lambda/n), ceil(2^(lambda+sigma)/n)).
// Caller computes primes = near_primorial_primes(lambda, n).
bool dkg_run_sieve_both_runner(
    dkg_transport* transport,
    uint32_t committee_size,
    uint32_t threshold,
    uint32_t local_party_id,
    const uint8_t committee_id_hash[32],
    uint32_t candidate_id,
    const std::vector<uint32_t>& primes,
    const dao_vss_group& vss_grp,
    uint32_t lambda,
    uint32_t sigma,
    uint32_t phase_timeout_s,
    BIGNUM* out_p,
    BIGNUM* out_q,
    BN_CTX* ctx,
    const char** fail_stage_out = nullptr);

}} // namespace
