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
#include <string>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"

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

// Production cryptographic parameters for the DKG ceremony.
// These values are frozen by the V2 implementation spec (N = 2048,
// Paillier ciphertext 512 bytes). Test builds use a reduced modulus
// so the ceremony runs at unit-test scale.
constexpr uint32_t DAO_DKG_K_BITS_PROD        = 60;
constexpr uint32_t DAO_DKG_TARGET_N_BITS_PROD = 2048;
constexpr uint32_t DAO_DKG_SECURITY_BITS_PROD = 32;

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
    transcript_leaf          = 0x73,

    // Dynamic tally-share Reset (separate ceremony from DKG).
    reshare_start            = 0x74,
    reshare_commit           = 0x75,
    reshare_share            = 0x76,
    reshare_proof            = 0x77,
    reshare_complete         = 0x78,
    reshare_abort            = 0x79,
    reshare_vki_set          = 0x7A,
    reshare_ready            = 0x7B,
    reshare_manifest         = 0x7C,
    reshare_manifest_ack     = 0x7D,

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
// Gap 3 — Theta(i) correctness proofs
// ====================================================================

struct dao_theta_mul_proof
{
    std::vector<uint8_t> T1;    // group element mod P
    std::vector<uint8_t> T2;    // group element mod P
    std::vector<uint8_t> z_b;   // scalar mod P'
    std::vector<uint8_t> z_rho; // scalar mod P'
    std::vector<uint8_t> z_k;   // scalar mod P'

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

struct dao_theta_open_proof
{
    std::vector<uint8_t> T;       // group element mod P
    std::vector<uint8_t> z_theta; // scalar mod P'
    std::vector<uint8_t> z_r;     // scalar mod P'

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
        // True when `canonical` holds the 32-byte transcript leaf hash
        // representing a private (targeted) message rather than the
        // full serialized message bytes.
        bool                 private_leaf = false;
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
// Gap 3 - Theta(i) correctness proofs
// ====================================================================

bool dao_theta_mul_prove(
    const dao_vss_group& grp,
    uint32_t epoch,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* N,
    const BIGNUM* C_phi_i,
    const BIGNUM* C_beta_i,
    const BIGNUM* beta_i,
    const BIGNUM* r_beta_i,
    const BIGNUM* k,
    const BIGNUM* C_prod,
    dao_theta_mul_proof& proof);

bool dao_theta_mul_verify(
    const dao_vss_group& grp,
    uint32_t epoch,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* N,
    const BIGNUM* C_phi_i,
    const BIGNUM* C_beta_i,
    const BIGNUM* C_prod,
    const dao_theta_mul_proof& proof);

bool dao_theta_open_prove(
    const dao_vss_group& grp,
    uint32_t epoch,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* C_theta_i,
    const BIGNUM* theta_i,
    const BIGNUM* r_theta_i,
    dao_theta_open_proof& proof);

bool dao_theta_open_verify(
    const dao_vss_group& grp,
    uint32_t epoch,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* C_theta_i,
    const BIGNUM* theta_i,
    const dao_theta_open_proof& proof);


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
//
// This record describes the STABLE public Paillier key epoch and the
// BOOTSTRAP SHAREHOLDER SET that generated it. It does NOT describe
// the temporary tally committee. The temporary tally committee is
// selected at a proposal's voting end as a subset of this bootstrap
// shareholder set; its members use the DKG shares they already hold.
// See dao_tally_session_cycle.h.
//
// Field names below retain their historical spelling for wire
// compatibility. Read them with bootstrap semantics:
//   committee_size      -> bootstrap_shareholder_count
//   threshold           -> bootstrap_threshold
//   t                   -> bootstrap_sharing_degree
//   committee_members   -> bootstrap_shareholder_members
//   committee_id_hash   -> bootstrap_shareholder_set_hash
//   V_K_i               -> bootstrap_shareholder verification keys
//
// The whitepaper forbids a permanent GOVERNANCE committee. It does not
// forbid the underlying distributed key-share custodians from
// persisting. Those custodians are what this record names.
// ====================================================================

struct dao_tally_key_record
{
    uint32_t             version        = 1;
    uint32_t             epoch          = 0;
    uint32_t             committee_size = DAO_DKG_COMMITTEE_SIZE;
    uint32_t             threshold      = DAO_DKG_THRESHOLD;
    uint32_t             t              = DAO_DKG_SHARING_DEGREE;
    std::vector<uint8_t> committee_id_hash;   // 32 bytes; bootstrap shareholder set hash

    // Ordered bootstrap shareholder public keys. Exactly committee_size
    // entries. Together with the epoch and the domain string this is
    // what committee_id_hash commits to. Not the temporary tally
    // committee.
    std::vector<std::vector<uint8_t>> committee_members;  // 32 bytes each

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

    // The running node's own secret share SK_i = N*F1(i) - theta_tilde,
    // signed-encoded. Populated only when cfg.local_party_id is nonzero
    // and the corresponding party completed phase 10. This value must
    // be persisted by the caller to the local node store and is never
    // written to consensus state or transmitted.
    std::vector<uint8_t> local_secret_share;

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
    // Default committee is the maximum (16). Callers that run a
    // different size must set committee_size AND threshold to
    // dao_dkg_expected_threshold(committee_size).
    uint32_t committee_size = DAO_DKG_MAX_COMMITTEE_SIZE;
    uint32_t threshold      = DAO_DKG_THRESHOLD;
    uint32_t epoch          = 1;

    // Ordered committee member public keys. Must contain exactly
    // committee_size distinct entries. The canonical committee_id_hash
    // is SHA256(domain || epoch || ordered member keys). A real
    // committee is never identified merely by indexes 1..n.
    std::vector<crypto::public_key> member_ids;

    uint32_t k              = 60;
    uint32_t target_N_bits  = 128;

    uint32_t security_bits  = 32;   // K = 2^security_bits
    uint32_t qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;

    uint32_t max_attempts   = 2000;

    uint64_t test_seed      = 0;

    // Per-phase wall-clock budget in the distributed runner. On
    // expiry the runner aborts and wait() returns false. 120 s is
    // adequate for the 512-bit test group; production FFDHE-2048
    // ceremonies calibrate this value.
    uint32_t phase_timeout_seconds = 120;

    // Identity of the party running this DKG instance on the current
    // node, 1..committee_size. Zero means "no local identity", in
    // which case the driver does not export any secret share.
    // Production nodes set this to their own committee index and
    // persist the returned share locally (see
    // dkg_result::local_secret_share).
    uint32_t local_party_id = 0;

#ifdef VEILROOT_DAO_DKG_TESTING
    // Test-only fixed contributions for arbitrary committee sizes.
    // When both vectors have committee_size entries (decimal strings),
    // the runner uses them in place of the built-in 3-party and 16-
    // party constants. The caller is responsible for choosing values
    // whose sums are prime, so that the biprimality check succeeds on
    // the first attempt.
    std::vector<std::string> test_p_i_dec;
    std::vector<std::string> test_q_i_dec;
#endif
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
// Distributed (P2P) DKG
//
// One committee node runs one dkg_p2p_runner. The runner owns a single
// dkg_party, a dkg_p2p_transport, and a worker thread that walks the
// DKG phase sequence defined in docs/DAO-V2-DKG.md §14. All committee
// members run the same code in parallel; no coordinator exists.
//
// Driver-level decisions (choose_g_bar, biprimality_check,
// lagrange_interpolate_zero, theta_tilde mod N, gcd(theta,N)==1,
// V derivation) are replicated locally on every node, because they are
// deterministic functions of the broadcast message stream. Two honest
// nodes with the same cfg.epoch, cfg.committee_size, cfg.member_ids,
// and vss group parameters therefore produce byte-identical key
// records from the same message set.
//
// Requires cfg.local_party_id in [1, cfg.committee_size].
// ====================================================================

struct dkg_p2p_callbacks
{
    // Targeted unicast to one committee member, addressed by public
    // key. Returns false if no connection to that peer is available.
    std::function<bool(const crypto::public_key&, const std::string&)> send_to;

    // Unreliable broadcast to all currently-connected peers.
    std::function<void(const std::string&)>                            broadcast;
};

// End-to-end encryption for targeted DKG messages.
// The outer P2P transport may broadcast the ciphertext to every peer;
// only the committee member whose public key is embedded in the
// envelope can decrypt it.
bool encrypt_dkg_private_payload(
    const std::string& plaintext,
    const crypto::public_key& sender_pub,
    const crypto::public_key& recipient_pub,
    std::string& envelope);

bool decrypt_dkg_private_payload(
    const std::string& envelope,
    const crypto::public_key& sender_pub,
    const crypto::secret_key& recipient_priv,
    std::string& plaintext);

bool is_dkg_private_payload(const std::string& payload);

class dkg_p2p_runner
{
public:
    dkg_p2p_runner(const dkg_config& cfg,
                   const dao_vss_group& vss,
                   const dkg_p2p_callbacks& cb);
    ~dkg_p2p_runner();

    dkg_p2p_runner(const dkg_p2p_runner&) = delete;
    dkg_p2p_runner& operator=(const dkg_p2p_runner&) = delete;

    // Start the worker thread. Idempotent.
    bool start();

    // Stop the worker and wait. Idempotent.
    void stop();

    // Deliver one inbound dkg_msg. Safe from any thread.
    void on_message(const dkg_msg& m);

    // Block until the ceremony finishes. timeout_s == 0 means no
    // timeout. Returns out.ok on success. If timeout_s is nonzero and
    // the ceremony has not finished within that window, returns false
    // and the runner is left in a stopped state.
    bool wait(dkg_result& out, uint32_t timeout_s = 0);

    bool running()  const;
    bool finished() const;
    uint32_t epoch() const;
    uint32_t local_party_id() const;
    const dkg_config* config() const;

private:
    struct impl;
    std::unique_ptr<impl> p_;
};

// Convenience blocking entry point. Equivalent to:
//   dkg_p2p_runner r(cfg, vss, cb);
//   r.start();
//   bool ok = r.wait(out);
bool dkg_run_distributed(const dkg_config& cfg,
                         const dao_vss_group& vss,
                         const dkg_p2p_callbacks& cb,
                         dkg_result& out);

// Committee-index derivation for a given node identity.
//
// A node's persistent identity is its public key (loaded from LMDB by
// Blockchain::init via committee_privkey). Committee membership is an
// epoch-local list of ordered public keys. The local party index in a
// DKG ceremony is derived by matching the node's own public key
// against the ordered list. Returns 0 if the node is not in the list.
//
// This is the ONLY way the runner learns its local_party_id. Do not
// persist a party index as node identity.
uint32_t dao_dkg_party_index_for(
    const std::vector<crypto::public_key>& member_ids,
    const crypto::public_key& self_pk);

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