// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DAO V2 distributed key generation.
//
// Construction: Nishide-Sakurai, "Distributed Paillier Cryptosystem
// without Trusted Dealer", WISA 2010, LNCS 6513, pp. 44-60.
//
// Frozen parameters (docs/DAO-V2-IMPLEMENTATION-SPEC.md §4):
//   committee_size = 16
//   t              = 7
//   threshold      = 8
//   Delta          = 16!
//
// Frozen protocol structure:
//
//   Modulus generation §3.1-§3.3:
//     P1 contributes p1, q1 with p1 = q1 = 3 mod 4.
//     P2..P16 contribute pi, qi with pi = qi = 0 mod 4.
//     N = (sum pi)(sum qi), BGW multiplication §3.2.
//     Distributed biprimality §3.3.
//     Distributed trial-division small-factor test §4.1.
//
//   Threshold key derivation §5:
//     lambda shares, beta shares, SecretKeyShares.
//     theta from the joint shares.
//     Verification keys per Appendix B.
//
//   Partial-decryption ZK proof per Appendix C.
//
// Architecture:
//   dao_dkg_message         typed protocol messages
//   dao_dkg_party           per-party state machine
//   dao_dkg_driver          orchestrates 16 parties
//   dao_dkg_transport       abstract delivery (inproc or network)
//
// Cryptographic equations:
//   Q_i proof (Appendix B specialised to §3.3):
//     For i >= 2:  C0_i = (g^4)^(x_i) * h^(y_i) mod P'
//                  Q_i  = g_bar^(x_i) mod N
//     For i == 1:  C0'_1 = g^(N+1) / C0_1
//                         = (g^4)^(x_1) * h^(y_1) mod P'
//                  Q_1 = g_bar^(x_1) mod N
//   Biprimality acceptance:
//     R = Q_1 / (Q_2 * ... * Q_16) mod N
//     accept iff R == +1 or R == -1
//   Trial division §4.1:
//     gamma = (p-1) * Ra + r * Rb
//     Ra in [0, K*p_max],  Rb in [0, K^2*p_max^2]
//     p_max = n * 3 * 2^(k-1)
//     accept iff gcd(gamma, r) == 1
//   Partial decryption (dao_threshold.h):
//     c_i = c^(2 * Delta * f(i)) mod N^2
//   Final normalization (dao_threshold.h):
//     M = L(C) * (-4 * Delta^2 * theta')^(-1) mod N

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <openssl/bn.h>

#include "governance/dao_paillier.h"
#include "governance/dao_threshold.h"

namespace cryptonote {
namespace dao {

// Committee parameters DAO_DKG_COMMITTEE_SIZE, DAO_DKG_SHARING_DEGREE,
// DAO_DKG_THRESHOLD are declared in dao_threshold.h, which is included
// above. Do not redeclare them here.

// Small public odd primes for the §4.1 trial-division test.
// r = 2 is excluded: p = q = 3 mod 4 already satisfies the factor-2
// condition.
constexpr uint32_t DAO_DKG_SMALL_PRIMES[] = { 3, 5, 7, 11, 13 };
constexpr size_t   DAO_DKG_SMALL_PRIME_COUNT = 5;

// §4.1 repetition count per public prime.
constexpr uint32_t DAO_DKG_TRIAL_DIVISION_REPS = 64;

// §3.3 Q_i proof Fiat-Shamir round counts.
constexpr uint32_t DAO_DKG_QPROOF_ROUNDS_PROD = 128;
constexpr uint32_t DAO_DKG_QPROOF_ROUNDS_TEST = 32;

// Delta = 16!, process-lifetime singleton.
const BIGNUM* dao_dkg_delta();

// Required minimum bits for the VSS group modulus P', per §5 step 2-3
// and §30 of the DKG spec:
//
//   theta_max = 2 * n * Delta * K * (1 + K) * N_max^2
//   P' > 2 * theta_max
//
// Returns the minimum bit length that a safe P' must have for the
// given configuration. The driver uses this to select P'.
uint32_t dao_dkg_required_vss_bits(uint32_t k_bits,
                                   uint32_t target_N_bits,
                                   uint32_t security_bits);

// ====================================================================
// Messages
// ====================================================================

enum class dkg_msg_type : uint8_t
{
    epoch_start              = 0x01,
    phase_complete           = 0x02,
    dkg_abort                = 0x03,

    polynomial_commitment_p  = 0x10,
    polynomial_commitment_q  = 0x11,
    polynomial_commitment_h  = 0x12,
    polynomial_share         = 0x13,
    share_complaint          = 0x14,

    bgw_product_share        = 0x20,

    biprimality_base         = 0x30,
    biprimality_Q            = 0x31,
    biprimality_Q_proof      = 0x32,

    trial_division_commit    = 0x40,
    trial_division_share     = 0x41,
    trial_division_result    = 0x42,
    trial_division_ra_commit = 0x43,
    trial_division_rb_commit = 0x44,
    trial_division_ra_share  = 0x45,
    trial_division_rb_share  = 0x46,
    trial_division_gamma     = 0x47,

    candidate_N              = 0x52,
    candidate_accept         = 0x50,
    candidate_reject         = 0x51,

    beta_commit              = 0x60,
    beta_share               = 0x61,
    r_commit                 = 0x62,
    r_share                  = 0x63,
    beta_range_proof         = 0x69,
    r_range_proof            = 0x6A,
    h_theta_share            = 0x64,
    theta_share              = 0x65,
    theta_tilde_broadcast    = 0x66,
    v_commit                 = 0x67,
    v_reveal                 = 0x68,
    verification_key         = 0x70,
    verification_key_proof   = 0x71,
    key_record_ready         = 0x72,

};

// Domain separator for the committee identifier hash.
constexpr const char* DAO_DKG_COMMITTEE_DOMAIN = "VeilRoot-DAO-DKG-COMMITTEE-V1";

// ====================================================================
// Beta/R range proof (Gap 1)
//
// Bit decomposition over the Pedersen VSS group. For a value x in
// [0, 2^L):
//
//   x = sum_j b_j 2^j,  b_j in {0,1}
//   B_j = g^(b_j) * h^(rho_j) mod P
//   C_x = g^x * h^(rho_x) mod P
//   D   = C_x / prod_j B_j^(2^j) = h^(rho_x - sum_j rho_j 2^j)
//
// Per bit: two-branch Schnorr OR proof that b_j is 0 or 1.
// Link:    Schnorr proof of knowledge of delta such that D = h^delta.
// ====================================================================

constexpr uint32_t DAO_RANGE_VALUE_TAG_BETA = 1;
constexpr uint32_t DAO_RANGE_VALUE_TAG_R    = 2;

struct dao_bit_or_proof
{
    std::vector<uint8_t> A_0;
    std::vector<uint8_t> A_1;
    std::vector<uint8_t> c_0;
    std::vector<uint8_t> c_1;
    std::vector<uint8_t> z_0;
    std::vector<uint8_t> z_1;
};

struct dao_range_proof
{
    uint32_t bits = 0;
    std::vector<std::vector<uint8_t>> bit_commitments;   // B_j
    std::vector<dao_bit_or_proof>     bit_proofs;        // one per bit
    std::vector<uint8_t>              link_a;            // A
    std::vector<uint8_t>              link_z;            // z

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

// Prove that C_x = g^x * h^rho_x commits to x in [0, 2^bits).
//
// `value_tag` distinguishes beta from R in the Fiat-Shamir transcript.
// C_x must be the same Pedersen commitment that the corresponding VSS
// deal publishes, so that the range proof binds to the same object.
// dao_range_prove / dao_range_verify are declared below the
// dao_vss_group definition.

struct dkg_msg_header
{
    uint8_t  version      = 1;
    uint32_t epoch        = 0;
    uint32_t candidate_id = 0;              // monotone within epoch
    uint8_t  committee_id_hash[32] = {};    // H(domain || epoch || member ids)
    uint32_t sender_id    = 0;              // 1..committee_size
    uint32_t recipient_id = 0;              // 0 = broadcast
    uint32_t phase        = 0;
    uint32_t round        = 0;
    uint64_t sequence     = 0;
    dkg_msg_type type     = dkg_msg_type::dkg_abort;
};

struct dkg_msg
{
    dkg_msg_header hdr;
    std::vector<uint8_t> bytes_a;
    std::vector<uint8_t> bytes_b;
    std::vector<uint8_t> bytes_c;
    std::vector<uint8_t> bytes_d;
    std::vector<std::vector<uint8_t>> vec_a;
    uint32_t tag32 = 0;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

// ====================================================================
// Canonical DKG transcript (Gap 4)
// ====================================================================
//
// Records every accepted protocol message exactly once. Duplicate
// deliveries (broadcast fan-out, replays) collapse at hash time.
// Failed candidate attempts are included.
//
// hash = SHA-256(
//     "VeilRoot-DAO-DKG-TRANSCRIPT-V1" ||
//     concat(sorted canonical accepted messages) )
//
// Sort key: candidate_id, phase, round, sender_id, recipient_id,
//           message_type, sequence, canonical_serialized_bytes.

class dkg_transcript
{
public:
    dkg_transcript() = default;

    void append(const dkg_msg& m);
    void hash(std::vector<uint8_t>& out) const;

private:
    struct entry
    {
        uint32_t             candidate_id = 0;
        uint32_t             phase        = 0;
        uint32_t             round        = 0;
        uint32_t             sender_id    = 0;
        uint32_t             recipient_id = 0;
        uint8_t              type         = 0;
        uint64_t             sequence     = 0;
        std::vector<uint8_t> canonical;
    };
    std::vector<entry> entries_;
};

// ====================================================================
// Transport
// ====================================================================

using dkg_tamper_hook = std::function<void(dkg_msg&)>;

class dkg_transport
{
public:
    virtual ~dkg_transport() = default;
    virtual bool send(const dkg_msg& m) = 0;
    virtual bool recv(dkg_msg& m) = 0;
    virtual bool try_recv(dkg_msg& m) = 0;
    virtual void shutdown() = 0;
};

// ====================================================================
// Pedersen VSS over the integers (§2.2-§2.3)
// ====================================================================

struct dao_vss_group
{
    BIGNUM* P       = nullptr;  // prime, P = 2*P_prime + 1
    BIGNUM* P_prime = nullptr;  // prime, (P-1)/2, the subgroup order
    BIGNUM* g       = nullptr;  // generator of the order-P_prime subgroup
    BIGNUM* h       = nullptr;  // second generator, log_g(h) unknown

    dao_vss_group() = default;
    ~dao_vss_group();
    dao_vss_group(const dao_vss_group&) = delete;
    dao_vss_group& operator=(const dao_vss_group&) = delete;
    bool valid() const { return P && P_prime && g && h; }
};

bool dao_vss_group_generate(dao_vss_group& out, unsigned int bits = 2048);

struct dao_vss_commitments
{
    std::vector<std::vector<uint8_t>> C;
};

// If `constant_blinding_out` is non-null, the caller receives the
// constant coefficient of the blinding polynomial (b[0]). This is the
// blinding of commitments_out.C[0] and is needed to prove range
// knowledge over the committed secret. Caller owns the result.
bool dao_vss_deal(const dao_vss_group& grp,
                  const BIGNUM* secret,
                  uint32_t n,
                  uint32_t degree,
                  dao_vss_commitments& commitments_out,
                  std::vector<BIGNUM*>& shares_out,
                  std::vector<BIGNUM*>& blindings_out,
                  BIGNUM** constant_blinding_out = nullptr);

bool dao_vss_verify_share(const dao_vss_group& grp,
                          const dao_vss_commitments& commitments,
                          uint32_t n,
                          uint32_t i,
                          const BIGNUM* share,
                          const BIGNUM* blinding);

// ====================================================================
// Gap 1 — beta/R range proof declarations
// ====================================================================

bool dao_range_prove(const dao_vss_group& grp,
                     uint32_t epoch,
                     uint32_t party_id,
                     uint32_t value_tag,
                     const BIGNUM* x,
                     const BIGNUM* rho_x,
                     const BIGNUM* C_x,
                     uint32_t bits,
                     dao_range_proof& proof_out);

bool dao_range_verify(const dao_vss_group& grp,
                      uint32_t epoch,
                      uint32_t party_id,
                      uint32_t value_tag,
                      const BIGNUM* C_x,
                      const dao_range_proof& proof);

// ====================================================================
// Verification keys (§5, Appendix B) and partial decryption (App C)
// ====================================================================

struct dao_partial_decryption
{
    uint32_t             member_index = 0;
    std::vector<uint8_t> c_i;
};

struct dao_partial_decryption_proof
{
    uint32_t             member_index = 0;
    std::vector<uint8_t> E;
    std::vector<uint8_t> Z;
};

bool dao_choose_verification_base(const PaillierPublicKey& pk,
                                  std::vector<uint8_t>& V_K_out);

bool dao_derive_verification_key(const PaillierPublicKey& pk,
                                 const std::vector<uint8_t>& V_K,
                                 const BIGNUM* share,
                                 std::vector<uint8_t>& V_K_i_out);

bool dao_dkg_sample_r(const PaillierPublicKey& pk, BIGNUM* r_out);

bool dao_partial_decryption_prove(const PaillierPublicKey& pk,
                                  const std::vector<uint8_t>& V_K,
                                  const std::vector<uint8_t>& V_K_i,
                                  uint32_t member_index,
                                  const std::vector<uint8_t>& c_bytes,
                                  const std::vector<uint8_t>& c_i_bytes,
                                  const BIGNUM* share,
                                  const BIGNUM* randomness,
                                  dao_partial_decryption_proof& proof_out);

bool dao_partial_decryption_verify(const PaillierPublicKey& pk,
                                   const std::vector<uint8_t>& V_K,
                                   const std::vector<uint8_t>& V_K_i,
                                   uint32_t member_index,
                                   const std::vector<uint8_t>& c_bytes,
                                   const std::vector<uint8_t>& c_i_bytes,
                                   const dao_partial_decryption_proof& proof);

// ====================================================================
// Public tally-key record
// ====================================================================

struct dao_tally_key_record
{
    uint32_t             version        = 1;
    uint32_t             epoch          = 0;
    uint32_t             committee_size = DAO_DKG_COMMITTEE_SIZE;
    uint32_t             threshold      = DAO_DKG_THRESHOLD;
    uint32_t             t              = DAO_DKG_SHARING_DEGREE;
    std::vector<uint8_t> committee_id_hash;   // 32 bytes
    std::vector<uint8_t> delta;               // 32 bytes, canonical big-endian

    std::vector<uint8_t> N;                   // 256 bytes
    std::vector<uint8_t> G;                   // 256 bytes, canonical big-endian (N+1)

    std::vector<uint8_t> theta;               // 256 bytes, canonical big-endian

    std::vector<uint8_t> V;                   // 512 bytes, verification base
    std::vector<std::vector<uint8_t>> V_K_i;  // one per member, 512 bytes each

    // VSS group public parameters.
    std::vector<uint8_t> vss_P;
    std::vector<uint8_t> vss_P_prime;
    std::vector<uint8_t> vss_g;
    std::vector<uint8_t> vss_h;

    uint64_t             activation_height = 0;
    std::vector<uint8_t> dkg_transcript_hash;  // 32 bytes

    std::vector<uint8_t> key_id;               // 32 bytes, canonical id

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

// ====================================================================
// Party and driver
// ====================================================================

class dkg_party;

std::unique_ptr<dkg_party> dkg_party_create(uint32_t party_id,
                                            uint32_t committee_size,
                                            uint32_t threshold,
                                            uint32_t epoch);

struct dkg_result
{
    bool                 ok                       = false;
    bool                 candidate_accepted       = false;
    uint32_t             epoch                    = 0;
    std::vector<uint8_t> N;
    std::vector<uint8_t> theta;
    std::vector<uint8_t> V;
    std::vector<std::vector<uint8_t>> V_K_i;
    std::vector<uint8_t> key_id;
    uint32_t             candidate_attempts       = 0;
    uint32_t             biprimality_failures     = 0;
    uint32_t             trial_division_failures  = 0;
    uint32_t             beta_phase_retries       = 0;

    // Populated on success.
    dao_tally_key_record record;

    bool to_record(std::vector<uint8_t>& out) const;

#ifdef VEILROOT_DAO_DKG_TESTING
    // Test-only oracle fields. Populated only when the library is
    // built with VEILROOT_DAO_DKG_TESTING defined.
    std::vector<uint8_t> test_p;   // sum of party p_i values
    std::vector<uint8_t> test_q;   // sum of party q_i values
    std::vector<uint8_t> test_phi; // N + 1 - p - q
    std::vector<uint8_t> test_beta;   // sum of beta_i
    std::vector<uint8_t> test_theta_tilde;
    std::vector<std::vector<uint8_t>> test_SK;  // F(j) per party
#endif
};

struct dkg_config
{
    uint32_t committee_size = DAO_DKG_COMMITTEE_SIZE;
    uint32_t threshold      = DAO_DKG_THRESHOLD;
    uint32_t epoch          = 1;

    uint32_t k              = 60;
    uint32_t target_N_bits  = 128;

    uint32_t security_bits  = 32;   // K = 2^security_bits
    uint32_t qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;

    uint32_t max_attempts   = 2000;

    uint64_t test_seed      = 0;
};

using dkg_transport_factory =
    std::function<std::unique_ptr<dkg_transport>(uint32_t party_id)>;

bool dkg_run(const dkg_config& cfg, dkg_result& out);

bool dkg_run_with_transport(const dkg_config& cfg,
                            const dkg_transport_factory& factory,
                            dkg_result& out);

// ====================================================================
// In-process transport (dao_dkg_transport.h defines dkg_inproc_network)
// ====================================================================

struct dkg_inproc_network;

dkg_inproc_network dkg_make_inproc_network(uint32_t n,
                                           dkg_tamper_hook hook = nullptr);

// ====================================================================
// Test-only helpers
// ====================================================================

#ifdef VEILROOT_DAO_DKG_TESTING
bool dkg_party_test_get_lambda_share(const dkg_party& p, BIGNUM* out);
#endif

// ====================================================================
// §3.3 Q_i proof (Appendix-B-style equality of discrete logs)
//
// Statement for i >= 2:
//     C0_i = (g^4)^x * h^y    mod P'
//     Q_i  = g_bar^x          mod N
//
// Statement for i == 1:
//     C0'_1 = g^(N+1) / C0_1 = (g^4)^x * h^y   mod P'
//     Q_1   = g_bar^x                          mod N
//
// Both are proofs of equality of discrete logs across two groups.
// ====================================================================

struct dao_Q_proof_repetition
{
    std::vector<uint8_t> A;   // P' byte size, big-endian
    std::vector<uint8_t> B;   // N byte size, big-endian
    uint8_t              c = 0;
    std::vector<uint8_t> zx;
    std::vector<uint8_t> zy;
};

struct dao_Q_proof
{
    uint32_t member_index = 0;
    std::vector<dao_Q_proof_repetition> reps;
};

bool dao_Q_prove(const dao_vss_group& grp,
                 const BIGNUM* N,
                 const BIGNUM* g4,        // g^4 mod P'
                 const BIGNUM* h,
                 const BIGNUM* g_bar,     // mod N
                 const BIGNUM* C0,        // (g^4)^x * h^y mod P'
                 const BIGNUM* Q,         // g_bar^x mod N
                 const BIGNUM* x,
                 const BIGNUM* y,
                 uint32_t member_index,
                 uint32_t rounds,
                 dao_Q_proof& proof_out);

bool dao_Q_verify(const dao_vss_group& grp,
                  const BIGNUM* N,
                  const BIGNUM* g4,
                  const BIGNUM* h,
                  const BIGNUM* g_bar,
                  const BIGNUM* C0,
                  const BIGNUM* Q,
                  const dao_Q_proof& proof);

} // namespace dao
} // namespace cryptonote