# VeilRoot DAO V2 — Implementation Specification

Status: FROZEN for the V2 consensus implementation.
Authority: the DAO whitepaper defines user-visible governance. This document
freezes the engineering specification underneath it. Where this document
and the whitepaper disagree on a numeric parameter, this document wins for
V2; the whitepaper is amended separately and only after V2 is audited.

No consensus code may deviate from this document. Amendments require an
explicit new revision with a documented consensus activation.

REVISION 2 (DAO V2). Changes from Revision 1:

  - Section 3: quorum denominator changed from minted supply to
    circulating supply, evaluated at the voting-end height against
    historical consensus state.
  - Section 4: tally committee range generalised to 3..16 members;
    threshold derived as T = ceil(n/2), t = T-1. Delta remains 16!.
    n = 16 continues to yield 8-of-16 exactly.
  - Section 27: tally-key records carry the actual committee size,
    threshold, and t for their epoch, not fixed 16/8/7.
  - Section 29: tally certificate requires T valid shares where T
    comes from the proposal's tally-key record.
  - Section 30: partial-decryption count is the epoch threshold T.
  - Section 37: activation mechanism is a network consensus constant
    routed through the existing hardfork/version machinery; the concrete
    mainnet height is set at release time and is not 0.
  - Sections 38, 39: added 3-member committee tests and the 3-node
    mainnet end-to-end test. Retained 16-member cryptographic tests.

Revision 2 supersedes Revision 1 in full.

REVISION 3 (DAO V2). Changes from Revision 2:

  - Section 3: quorum comparison corrected. Quorum is decided by
    aggregate participation coins (actual VNS amount), not by voting
    weight. YES_weight > NO_weight remains the separate majority rule.
    The two quantities are never substituted for one another. This
    restores the V1 semantic split: participation_balance governs
    quorum, voting_weight governs majority.
  - Section 18: V2 ballot gains a participation-balance channel:
    per-input balance_commitment and balance_signature; top-level C_B,
    E_B, proof_B.
  - Section 20: verification steps extended for the balance channel.
  - Section 29: tally certificate includes B decryption and
    participation_coins_total.
  - Section 30: final tally decrypts E_W, E_S and E_B; quorum uses
    participation_coins_total.
  - Section 38: participation-versus-weight independence tests added.

Revision 3 supersedes Revision 2 in full. Any disagreement is resolved
in favour of this revision.

REVISION 4 (DAO V2 lifecycle correction):

- The tally committee is dynamically selected at voting-end/tally time
  from the canonical eligible-node state.
- No committee is permanently appointed.
- The Paillier public key used by votes is established by the
  dealer-free bootstrap DKG and remains the public encryption key
  for its key epoch.
- Committee membership and Paillier public-key identity are distinct
  concepts.
- At tally time the selected committee receives a fresh threshold
  sharing of the existing private Paillier key using the published
  dynamic-secret-sharing Reset construction, without reconstructing
  the complete private key.
- Existing ballots remain encrypted under the same public modulus N.
  No ballot is re-encrypted.
- The selected tally committee is temporary and is discarded after
  completion of its tally session.
- Historical public key records remain available for historical
  vote/tally validation.
- Secret shares never enter blockchain state.
- `tally_key_epoch` identifies the public Paillier key epoch.
  The dynamic committee/share session is a separate lifecycle object.

Revision 4 is additive to Revision 3. It does not alter the numeric
parameters of Revisions 2 and 3. The dynamic Reset construction is
not yet implemented; this revision records the target architecture.

---

## 1. Governance weight

For each eligible output:

    raw_age_days = (vote_height - output_height) / 720
    age_days     = min(raw_age_days, 7300)          // 20-year cap
    f_i          = floor(log2(age_days + 1))        // integer only
    W_i          = amount_i * f_i                    // exact, 128-bit

Type: `governance_weight_t = boost::multiprecision::uint128_t`.

Constants:

    DAO_BLOCKS_PER_DAY = 720     (120-second target block time)
    DAO_AGE_MAX_DAYS   = 7300    (20 years)
    W_MAX              = 240000000000000000000
                        (20,000,000 VNS × 10^12 × 12)

W_MAX is the maximum possible aggregate weight of the whole supply at the
age cap. It is not a definition of voting power; it is an upper bound
derived from the maximum eligible monetary amount and the age function.

No floating point anywhere in consensus. No clamping. No truncation.

Voting weight is mathematically and conceptually separate from monetary
VNS supply. The supply cap provides one external bound on amount; it does
not define voting power.

---

## 2. Vote height

Voting weight is computed at the block height at which the vote is
included, not at proposal creation.

Consensus requires:

    proof.vote_height == block_height_of_inclusion

A vote whose `vote_height` does not match its block inclusion height is
invalid. This includes mempool admission: a vote constructed for height H
is not admitted into the mempool for any height other than H.

Wallet behavior:

- construct for `chain_height + 1`;
- submit;
- if not included at that height, discard and rebuild automatically.

Stale vote transactions are invalid rather than silently re-weighted.

---

## 3. Quorum

    quorum_threshold =
        (quorum_percent * circulating_supply_at_voting_end) / 100

    quorum_percent = 10

where

    circulating_supply_at_voting_end =
        minted_supply_at_voting_end
        - treasury_balance_at_voting_end
        - burned_fees_at_voting_end

All three quantities are historical consensus state at the proposal's
voting-end height, not current DB state. They are read from the
`supply_history` table. Underflow in the subtraction is a consensus
error, not a wrap.

The comparison is:

    participation_coins_total >= quorum_threshold

where

    participation_coins_total =
        aggregate actual VNS amount represented by accepted DAO V2
        votes, recovered from the encrypted participation-balance
        aggregate E_B.

Acceptance also requires:

    YES_weight > NO_weight

where

    YES_weight, NO_weight =
        recovered from the encrypted weight aggregate E_W and the
        encrypted signed-weight aggregate E_S.

Quorum uses participation coins. Majority uses voting weight. The two
quantities are never substituted for one another. This preserves the
V1 distinction between total_yes_amount/total_no_amount (raw VNS for
quorum) and total_yes_weight/total_no_weight (voting weight for
majority).

Both conditions are independent. A proposal may fail either one.

---

## 4. Committee

Committee parameters for each epoch:

    MIN_COMMITTEE_SIZE = 3
    MAX_COMMITTEE_SIZE = 16

    n = min(number_of_eligible_nodes, MAX_COMMITTEE_SIZE)

    if n < MIN_COMMITTEE_SIZE:
        no valid tally committee exists for this epoch

    threshold T = ceil(n / 2)
    sharing_degree t = T - 1
    Delta = 16! = 20,922,789,888,000

The threshold follows directly from the selected distributed threshold
Paillier construction (Nishide-Sakurai, WISA 2010). That construction
defines a (t+1, n) threshold system and requires t < n/2. For each n in
the permitted range:

    n=3  -> T=2, t=1
    n=4  -> T=2, t=1
    n=5  -> T=3, t=2
    n=6  -> T=3, t=2
    n=7  -> T=4, t=3
    n=8  -> T=4, t=3
    n=9  -> T=5, t=4
    n=10 -> T=5, t=4
    n=11 -> T=6, t=5
    n=12 -> T=6, t=5
    n=13 -> T=7, t=6
    n=14 -> T=7, t=6
    n=15 -> T=8, t=7
    n=16 -> T=8, t=7

n = 16 reproduces the prior 8-of-16 parameterisation exactly.

Delta remains 16! for every committee size n <= 16. The interpolation
denominators for member indices 1..n divide n!, and n! divides 16!.

Committee selection occurs at tally time.

For a proposal whose voting period has ended, the protocol evaluates
the canonical eligible-node state at the voting-end height, deterministically
orders eligible nodes using the existing stake-age ranking and public-key
tie break, and selects the top n nodes, where:

    n = min(number_of_eligible_nodes, MAX_COMMITTEE_SIZE)

with:

    MIN_COMMITTEE_SIZE <= n <= MAX_COMMITTEE_SIZE
    threshold T = ceil(n / 2)
    sharing degree t = T - 1.

Committee membership is therefore temporary protocol state. It is not
a permanent appointment and is not fixed at DAO activation. The
committee is bound to the epoch's public key record by the canonical
hash described in the DKG specification. Code MUST NOT use fixed
member indexes 1..16 as committee identities.

---

## 5. Cryptographic construction

Standard Paillier, which is the `s = 1` member of the Damgård–Jurik family.

Parameters:

    modulus N              RSA modulus, 2048 bits
    DJ parameter s         1
    generator g            1 + N
    plaintext space        Z_N
    ciphertext space       Z_(N^2)
    ciphertext size        512 bytes, fixed width

References:

1. Paillier, Eurocrypt 1999.
2. Damgård, Jurik, Nielsen, 2001.
3. Damgård, Jurik, 2000/008 (threshold variant, ZK techniques).
4. Nishide, Sakurai, Distributed Paillier without Trusted Dealer, WISA 2010.
5. Hazay, Mikkelsen, Rabin, Toft, Nicolosi — malicious distributed RSA
   generation and threshold Paillier.
6. Klinger, Wüller, Traverso, Meyer — hierarchical and dynamic threshold
   Paillier without trusted dealer.

No new threshold-Paillier algebra. Any construction not directly cited
above requires an explicit new revision of this document.

---

## 6. Big-integer backend

Protocol arithmetic is implemented in VeilRoot on top of OpenSSL BIGNUM.

OpenSSL BIGNUM may be used only for:

- big-integer representation;
- modular arithmetic;
- modular exponentiation;
- modular inverse;
- gcd;
- primality and RSA generation primitives.

Protocol-specific algorithms (Paillier encryption, DJ proofs, DKG, share
verification, partial decryption, decryption proofs) live behind
`src/governance/dao_paillier.{h,cpp}` and `src/governance/dao_dkg.{h,cpp}`.

No BIGNUM calls are scattered through consensus or wallet code. All
secret-dependent modular exponentiation uses OpenSSL constant-time
variants where available. All secret material is zeroized on scope exit.

---

## 7. Canonical encodings

All integers crossing the wire have fixed-width canonical encodings:

    N (modulus)              256 bytes, big-endian, no leading-zero strip
    N^2                      512 bytes, big-endian
    Paillier ciphertext      512 bytes, big-endian
    group element mod N^2    512 bytes

No decimal strings. No variable-length BIGNUM or mpz output. No native
endianness. No struct padding. No compiler-dependent representation.

Every encoding rejection is a consensus failure, not a normalization.

---

## 8. Paillier encryption

    Enc(m; r) = (1+N)^m * r^N mod N^2
    m in Z_N
    r in Z_N*

Requirements:

- reject `r` when `gcd(r, N) != 1`.
- reject m >= N.
- verify ciphertext is in Z_(N^2)* (ciphertext validity check).
- homomorphic aggregation is multiplication mod N^2:

      Enc(m1) * Enc(m2) mod N^2 = Enc(m1 + m2)

- never aggregate by integer addition.
- ciphertext validity is checked before any aggregation.

Independent unit tests are required before this layer touches consensus.

---

## 9. Signed plaintext encoding

`W_total >= 0`, `S_total` may be negative.

Encoding:

    if S >= 0:  m_S = S
    if S <  0:  m_S = N - |S|

Decoding after threshold decryption of m_S:

    if m_S <= N/2:  S = m_S
    else:           S = m_S - N

Consensus additionally requires:

    0 <= W_total <= W_MAX
    |S_total| <= W_total
    (W_total + S_total) mod 2 == 0

Final values:

    YES = (W_total + S_total) / 2
    NO  = (W_total - S_total) / 2

No individual vote is ever decrypted.

---

## 10. Two ciphertexts, not four

The V2 ballot carries exactly two Paillier ciphertexts:

    E_W = Enc(W_total)
    E_S = Enc(S_total)

Pedersen commitments remain the binding public commitments:

    C_W = W_total * H + R_W * G
    C_S = S_total * H + R_S * G

The Paillier/Pedersen consistency proofs establish equality between the
encrypted integers and the values committed to by `C_W` and `C_S`.

The prior plan of four ciphertexts (`Enc(W)`, `Enc(R_W)`, `Enc(S)`,
`Enc(R_S)`) is discarded. Blinding values are not carried as ciphertexts.
Their correctness is enforced by the consistency proofs.

---

## 11. Consistency proofs

For W:

    exists W, R_W, r_W with
        C_W = W*H + R_W*G
        E_W = Enc(W; r_W)

For S:

    exists S, R_S, r_S with
        C_S = S*H + R_S*G
        E_S = Enc(S; r_S)

Standard Sigma protocols in Fiat-Shamir form. The proof transcript binds:

- DAO V2 version;
- proposal ID;
- proposal submission height;
- actual vote height;
- tally-key epoch/id;
- every ring input;
- every absolute output index;
- every output height as resolved from consensus state;
- every derived age factor;
- every proposal-scoped nullifier;
- C_W;
- C_S;
- E_W;
- E_S.

Modification of any bound value invalidates the proof.

---

## 12. Hidden direction

The V2 wire object contains no plaintext direction.

The ballot proves via OR proof:

    S = +W  OR  S = -W

using the same W and S that are bound to weighted CLSAG, `C_W`, `C_S`,
`E_W`, `E_S`.

The current OR proof implementation in
`src/governance/dao_vote_or_proof.{h,cpp}` is the V2 direction proof.
Its `extra_binding` field carries the canonical hashes of `E_W` and `E_S`
in V2. It is otherwise unchanged.

A malicious wallet cannot submit `E_W = Enc(100)` while
`E_S = Enc(-50)` when the actual weighted vote is 100. The consistency
proofs and the OR proof share the same transcript binding and cannot be
satisfied together with inconsistent values.

---

## 13. Weighted CLSAG

Mandatory. Not replaced by a weaker signature.

For each hidden eligible output:

    C_i        RingCT Pedersen amount commitment, from chain
    f_i        deterministic age factor
    Q_i        = f_i * C_i
    V_i        = Q_l + rho_l * G   (only real index known to wallet)
    C'_i       = Q_i - V_i
    z_l        = -rho_l
    N_l        = x_l * H_vote(P_l, proposal_id)
    J_l        = z_l * H_vote(P_l, proposal_id)
    H_i        = H_vote(P_i, proposal_id)

Round equations:

    L_i = s_i G + c_i ( mu_P * P_i + mu_C * C'_i )
    R_i = s_i H_i + c_i ( mu_P * I + mu_C * J )

Real response:

    s_l = alpha - c_l ( mu_P * x_l + mu_C * z_l )

Implementation lives in `src/governance/dao_clsag.{h,cpp}`. Ordinary
`rct::CLSAG_Gen` and `verRctCLSAGSimple` are not modified.

---

## 14. Proposal-scoped nullifiers

    N_i = x_i * H_vote(P_i, proposal_id)

Domain-separated hash-to-point:

    H_vote(P, proposal_id) =
        hash_to_curve( "VeilRoot-DAO-VOTE-V2" || proposal_id || P )

The same domain separator is used everywhere in DAO V2. The ordinary
Monero key image is never used as the DAO nullifier. Nullifiers are
deterministic per (output, proposal) and unlinkable across proposals.

---

## 15. Voting authority

The consensus unit is the eligible output.

- Each eligible output authorizes at most one vote per proposal.
- Each vote transaction may contain many eligible outputs.
- The wallet includes all eligible outputs belonging to the wallet.
- Every hidden-output nullifier is recorded.
- The same output cannot appear in another valid vote for the same
  proposal.

No public wallet identity is introduced. No new linkability surface.

---

## 16. Output reference validity

DAO voting is non-consuming: the vote does not spend the referenced
outputs. The proposal-scoped DAO nullifier prevents reuse of the same
authority across votes; it is not a Monero spend key image.

Consensus does NOT require any referenced ring member to be unspent.
Spent status is not a consensus validation condition for a DAO ring
member. This is intentional.

- Every referenced output must exist in canonical parent chain state.
- Output heights, commitments, and public keys are loaded from canonical
  chain state, not from the transaction.
- The ring exists solely to hide which output authorized the vote.
- The wallet should select currently eligible unspent outputs when
  constructing a vote; that is a wallet selection rule, not a consensus
  rule.
- A valid vote referencing an already-spent ring member is accepted by
  consensus.

---

## 17. Aggregate commitment

For all inputs:

    C_W = sum_i V_i = W_total * H + R_W * G
    R_W = sum_i ( f_i * mask_i + rho_i )

The prior aggregate form `R_W = sum_i rho_i` is forbidden. The blinding
of `V_i` includes `f_i * mask_i`; using only `rho_i` would make the
relation `C_W = R_W*G + W_total*H` false.

    C_S = S_total * H + R_S * G

Aggregate commitments are consensus objects.

---

## 18. Wire structure

Replace the V1 structure. The following plaintext fields disappear:

- direction_yes
- participation_balance
- voting_weight
- snapshot_height
- wallet-supplied per-output amounts
- wallet-supplied per-output weights

Conceptual V2 ballot:

    vote_input_v2
    {
        vector<uint64_t> key_offsets;
        rct::key weight_commitment;      // V_i
        rct::clsag weight_signature;     // weighted DAO CLSAG
        rct::key balance_commitment;     // B_i
        rct::clsag balance_signature;    // DAO CLSAG with f_i = 1
    }

    vote_proof_v2
    {
        uint8_t version = 2;
        crypto::hash proposal_id;
        uint64_t vote_height;
        uint64_t tally_key_epoch;

        vector<vote_input_v2> inputs;

        vector<crypto::hash> nullifiers;

        rct::key C_W;
        rct::key C_S;
        rct::key C_B;

        fixed_512_byte E_W;
        fixed_512_byte E_S;
        fixed_512_byte E_B;

        paillier_pedersen_equality_proof proof_W;
        paillier_pedersen_equality_proof proof_S;
        paillier_pedersen_equality_proof proof_B;

        hidden_direction_or_proof direction_proof;

        crypto::hash transcript_hash;
    }

The following are NOT carried in the wire object because consensus
derives them from chain state:

- output amount
- output height
- output commitment
- age factor
- proposal submission height

They are bound by the transcript hash.

Balance channel semantics:

- balance_commitment = B_i = C_i + rho_B_i * G, where C_i is the real
  output's RingCT Pedersen commitment and rho_B_i is fresh. The verifier
  never learns the amount. B_i is not equal to any ring member's C.
- balance_signature is a DAO CLSAG on the same ring with
  age_factors = 1 for every member, and V = balance_commitment.
- balance_signature.I == weight_signature.I for every input. The two
  signatures are bound to the same hidden DAO authority.
- C_B = sum_i B_i.
- E_B = Paillier encryption of participation_coins_total (sum of actual
  VNS amounts of the wallet's eligible outputs) under the proposal's
  historical tally key.
- proof_B is a Paillier/Pedersen equality proof between C_B and E_B,
  with domain "C_B-Enc(B)". It is independent of proof_W and proof_S.

### 18.1 Transaction carrier

A DAO V2 vote is carried in the existing TX_EXTRA_GOVERNANCE (0x40)
/ tx_extra_governance_payload structure.

The governance object type is `governance_object::vote_v2`.

The `governance_payload::data` field contains exactly one canonical
serialized `vote_proof_v2` object. Truncation, trailing bytes, empty
payload, or a mismatched `version` field is invalid.

No separate tx-extra tag is defined for DAO V2 voting.

After DAO V2 activation, `governance_object::vote` is rejected for
DAO voting; before activation it remains valid only under the
historical V1 rules.

---

## 19. Serialization

Strict and canonical.

- V2 starts with version = 2.
- Fixed-size hashes are fixed-size.
- Paillier ciphertext is exactly 512 bytes.
- No leading-zero stripping.
- No alternate integer representation.
- No trailing garbage.
- Maximum vector sizes are consensus-bounded.
- Malformed lengths reject.
- Truncated data rejects.
- Extra data rejects.

`rct::BulletproofPlus` is not used as a generic wire container. Any
Bulletproof or RingCT proof used by DAO V2 has its own typed V2 structure.

---

## 20. Consensus verification order

`VoteProofVerifier::verify()` is real consensus verification. No stubs.

1. strict deserialize.
2. version == 2.
3. proposal exists.
4. voting period is active at block height.
5. vote_height == current block height.
6. tally-key epoch is correct for this proposal.
7. input count within consensus bounds.
8. every ring is structurally valid: non-empty; key_offsets count ==
   ring size; expanded absolute-index count == ring size; CLSAG response
   vector count == ring size; relative-offset expansion cannot overflow;
   absolute indices contain no duplicates. No DAO-specific minimum or
   maximum ring size is defined by this specification.
9. every referenced output exists in canonical parent state, and its
   canonical P/C/height are loaded from chain.
10. (removed; spent status is not a consensus condition — see §16.)
11. ring member indices unique within the input.
12. nullifier count matches input count.
13. nullifiers are non-zero and unique within the transaction.
14. age factors recomputed from canonical output heights.
15. weighted CLSAG verifies for each input.
16. balance CLSAG verifies for each input: same ring, age_factors = 1,
    V = balance_commitment.
17. weight_signature.I == balance_signature.I for every input.
18. aggregate C_W matches sum of per-input weight_commitment.
19. aggregate C_B matches sum of per-input balance_commitment.
20. C_S and C_B are valid curve points.
21. E_W, E_S, E_B are valid Paillier ciphertexts (in Z_(N^2)*).
22. Paillier/Pedersen consistency proof for W verifies.
23. Paillier/Pedersen consistency proof for S verifies.
24. Paillier/Pedersen consistency proof for B verifies.
25. hidden-direction OR proof verifies.
26. transcript hash verifies (binds C_W, C_S, C_B, E_W, E_S, E_B, and
    each input's weight_commitment and balance_commitment).
27. duplicate-nullifier lookup against previous chain state.
28. duplicate-nullifier lookup within the block.
29. only now mutate governance state.

Any failure makes the vote invalid.

---

## 21. Duplicate votes are consensus-invalid

`if (res == vote_result::already_voted) continue;` is forbidden.

A block containing a duplicate DAO voting authority is invalid.
This includes:

- duplicate nullifier in one transaction;
- duplicate nullifier across two transactions in the same block;
- nullifier already present in previous chain state.

The block is rejected; the vote is not skipped.

---

## 22. Dry-run

The dry-run path executes the same cryptographic and consensus
verification as the mutating path. Only state mutation is disabled.

`if (dry_run) return success;` before validation is forbidden.

---

## 23. Database model

Per-vote record:

    proposal_id
    proposal-scoped nullifiers (one per input)
    vote height
    transaction hash

Per-proposal aggregate:

    aggregate_E_W
    aggregate_E_S
    aggregate_C_W
    aggregate_C_S

No plaintext YES/NO, weight, or balance is stored per vote.

The encrypted aggregate is the authoritative running tally during the
voting period.

---

## 24. Aggregate update

For each accepted vote:

    E_W_total = E_W_total * E_W_vote mod N^2
    E_S_total = E_S_total * E_S_vote mod N^2
    C_W_total = C_W_total + C_W_vote
    C_S_total = C_S_total + C_S_vote

Individual votes are never decrypted.

---

## 25. Rollback and reorg

Rollback removes:

- the vote record;
- the proposal-scoped nullifiers for that vote;
- the aggregate contribution of that vote.

Ciphertext rollback uses the multiplicative inverse mod N^2:

    E_W_total = E_W_total * inverse(E_W_vote) mod N^2
    E_S_total = E_S_total * inverse(E_S_vote) mod N^2

Commitment rollback uses curve-point subtraction:

    C_W_total = C_W_total - C_W_vote
    C_S_total = C_S_total - C_S_vote

Rollback by subtracting a plaintext voting weight is forbidden.

Every reorg test must prove:

    state(after A, then rollback A) == state(before A)

byte-for-byte for DAO state, including nullifier sets, aggregate
ciphertexts, aggregate commitments, and vote records.

---

## 26. DKG

No founder private key. No trusted dealer. No node can reconstruct the
full decryption key.

The DAO V2 threshold key lifecycle consists of two distinct operations:

1. Bootstrap key generation:
   Nishide-Sakurai dealer-free distributed Paillier key generation
   establishes the Paillier public key and the initial private-key
   sharing.

2. Dynamic tally-share transition:
   at tally time the currently selected committee receives a new
   threshold sharing of the same private Paillier key, without
   reconstructing the key.

The dynamic transition follows the published dynamic/verifiable
secret-sharing Reset construction used by:

    Klinger, Wüller, Traverso, Meyer,
    "Hierarchical and dynamic threshold Paillier cryptosystem
    without trusted dealer", 2021.

The Reset operation must preserve the private Paillier key exactly.
It changes the shareholder/access structure, not the public modulus
or the underlying private key.

No trusted dealer.
No complete secret reconstruction.
No ballot re-encryption.
No new Paillier modulus at tally time.

Requirements:

- no reconstruction of the full secret;
- no single node can decrypt alone;
- invalid participants cannot inject unauthorized shares;
- invalid shares detectable;
- public key deterministic from the accepted DKG transcript;
- every share holder can verify its own share;
- partial decryptions are verifiable;
- replayed DKG messages rejected;
- old-epoch shares cannot be used against a new epoch.

The DKG has its own cryptographic test suite.

---

## 27. Key lifecycle

A DAO tally key has two logically separate pieces of state:

PUBLIC KEY EPOCH

    key_epoch
    key_id
    public modulus N
    G
    theta / theta_prime
    public verification parameters

The public key epoch identifies the Paillier encryption domain.
Votes bind to this epoch and key_id.

TALLY SHARE SESSION

    share_session_id
    key_epoch
    proposal_id
    committee_size
    threshold
    t
    committee member identities
    committee verification material
    selection height
    tally height

The share session determines who may perform threshold decryption
for the tally.

The public Paillier key does not change during a dynamic share reset.

The committee/share session may change without changing N.

Historical public key epochs remain available indefinitely.
Private shares are local-only and temporary.

Delta remains 16! for every committee size n <= 16.

When a share session is reset:

- old votes remain valid under their historical public key epoch;
- new votes use the current public key epoch;
- final tally for a proposal uses the epoch recorded in the proposal,
  and the share session bound to that epoch and to the selected
  committee.

Secret shares never enter blockchain state.

---

## 28. Partial decryption

Each tally member produces a partial decryption for the aggregate W and
aggregate S ciphertexts.

Each partial decryption binds to:

- proposal ID;
- key epoch;
- key_id;
- share_session_id / committee_id_hash;
- aggregate ciphertext hash;
- shareholder id/index.

Uses the exact verifiable partial-decryption construction from the
selected threshold Paillier scheme, with its proof. Do not implement an
equation not verified against that scheme.

---

## 29. Tally certificate

Contents:

    proposal_id
    vote_end_height
    tally_key_epoch
    aggregate_ciphertext_hash
    set of valid partial decryptions for E_W
    set of valid partial decryptions for E_S
    set of valid partial decryptions for E_B
    set of partial-decryption proofs
    W_total
    S_total
    participation_coins_total
    YES_weight
    NO_weight
    quorum_threshold
    passed

Valid only when at least T distinct committee members provide valid
shares, where T is the threshold recorded in the share session bound to
the proposal. The certificate must prove that each contributing member
belongs to the exact committee bound by the share session and by
committee_id_hash. A share is not accepted merely because its numerical
index lies in 1..n. A share from an earlier committee session is invalid
even if it refers to the same Paillier public key. Independently
verifiable by every node. Anyone can collect shares and submit the tally
object. No administrator is required.

---

## 30. Final tally algorithm

1. obtain aggregate E_W;
2. obtain aggregate E_S;
3. obtain aggregate E_B;
4. obtain at least T valid partial decryptions for each aggregate, where
   T is read from the proposal's tally-key record;
5. verify each partial-decryption proof;
6. combine per the threshold reconstruction;
7. recover W_total;
8. recover signed S_total;
9. recover participation_coins_total from E_B;
10. require 0 <= W_total <= W_MAX;
11. require |S_total| <= W_total;
12. require (W_total + S_total) even;
13. YES_weight = (W_total + S_total) / 2;
14. NO_weight  = (W_total - S_total) / 2;
15. read supply_history[vote_end_height]; if absent, the tally is not
    ready and must not be finalized;
16. circulating = minted - treasury - burned;
17. quorum_threshold = floor(10 * circulating / 100);
18. quorum_met   = participation_coins_total >= quorum_threshold;
19. majority_met = YES_weight > NO_weight;
20. passed = quorum_met && majority_met;
21. write result to consensus state.

No individual ballot is decrypted. Participation coins (from E_B)
determine quorum. Voting weight (from E_W and E_S) determines majority.
The two quantities are never substituted for one another.

---

## 31. Live tally

Aggregate-only. The public live tally contains:

    proposal_id
    aggregate ciphertext hash
    vote height
    YES
    NO
    certificate

No voter count. No individual weight. No individual direction. No
individual nullifier-direction association.

Live tally is informational. Final tally is authoritative.

---

## 32. Wallet

`wallet2::create_vote_tx()` is replaced.

Steps:

1. locate all currently eligible unspent outputs;
2. canonical output heights;
3. age factors at target vote height;
4. total deterministic weight;
5. ring decoys automatically selected;
6. proposal-scoped nullifiers;
7. weighted CLSAG per input;
8. C_W;
9. hidden YES/NO chosen internally;
10. C_S;
11. encrypt W;
12. encrypt S;
13. consistency proofs W and S;
14. hidden-direction OR proof;
15. submit V2 transaction.

Caller supplies only:

    proposal_id
    direction (YES|NO)

No output index, ring member, nullifier, Paillier randomness, or weight
calculation control is exposed in the user-level API.

---

## 33. RPC

Frozen read interface:

    dao_get_proposals
    dao_get_proposal
    dao_get_tally_key
    dao_get_live_tally
    dao_get_final_result
    dao_get_vote_status

Frozen write interface:

    dao_vote(proposal_id, direction)
    optional standard transaction fee parameters

No UTXO selection parameter. No weight parameter. No balance parameter.
No nullifier parameter.

---

## 34. Proposal lifecycle

    SUBMITTED
        ↓
    VOTING
        ↓
    VOTING_ENDED
        ↓
    TALLY_AVAILABLE
        ↓
    PASSED / FAILED
        ↓
    EXECUTED

All transitions are deterministic and protocol-driven. No administrator
RPC is required to advance the protocol.

---

## 35. Automatic execution

After a proposal deterministically passes:

- execution eligibility becomes protocol state;
- execution may occur during block processing;
- execution is performed exactly once;
- `executed = true` is consensus state;
- rollback restores prior state;
- second execution attempt is invalid.

Execution does not depend on parsing arbitrary transaction text supplied
by the caller.

---

## 36. Treasury execution

Deterministic. For every treasury proposal:

    approved amount
    recipient
    proposal ID
    execution height
    resulting treasury balance

are consensus-derived. No treasury output may be released by possession
of a private key outside the DAO rules.

---

## 37. Activation

Activation is a network consensus constant routed through the existing
hardfork/version machinery:

    constexpr uint64_t DAO_V2_ACTIVATION_HEIGHT = <release value>;

The release value is agreed at release time and compiled into every
coordinated node. It is not 0, not the node's current height, and not a
local DB condition.

Before activation:

    V1 DAO vote object -> historical V1 rules apply
    V2 DAO vote object -> invalid

At and after activation:

    V1 DAO vote object -> invalid
    V2 DAO vote object -> active

No ambiguous dual validation. The activation condition is consensus
state, not a local tally-keys row.

---

## 38. Test programme

Required before browser integration:

- Cryptographic unit tests (Paillier, homomorphic addition, signed
  encoding, 69-bit boundary, W_MAX, negative S, threshold combination,
  invalid shares, invalid ciphertexts, malformed modulus, consistency
  proofs, direction proof, weighted CLSAG, nullifiers).
- Fixed independent test vectors for public key, ciphertext, weighted
  commitment, consistency proof, CLSAG, nullifier, OR proof, partial
  decryptions, final tally.
- Tamper tests for every wire field and every proof element.
- Consensus adversarial tests: double vote, same nullifier twice, split
  wallet, spent ring member accepted as decoy/reference (DAO voting is
  non-consuming), duplicate ring member, malformed ring,
  invalid age, inflated W, negative W, oversized W, S outside [-W, W],
  parity violation, wrong proposal, wrong vote height, stale tx,
  same-block spend, reorg after vote, reorg after tally, reorg after
  execution, duplicate certificate, insufficient shares, offline
  committee members, invalid shares, replayed shares across epochs.
- Fuzzing for V2 serialization, payload parsing, Paillier ciphertext
  parsing, proof parsing, tally certificate parsing, DKG messages, vote
  extraction.
- Cross-platform: Linux and Windows/Mingw; identical byte sequences.
- Committee-size coverage: deterministic DKG and threshold-tally tests
  for n=3 (T=2), n=4 (T=2), n=5 (T=3), n=8 (T=4), and n=16 (T=8);
  partial decryption at T shares succeeds, T-1 shares fail; Delta is
  16! in every case. The 16-member cryptographic test vectors are
  retained in full.
- Circulating-supply quorum: a proposal whose voting period ends at
  height H uses the supply snapshot at H, independent of later
  treasury or burn activity.
- Participation-versus-weight independence: large W with small B may
  pass majority and fail quorum; small W with large B may pass quorum
  and fail majority; same B_total with different W_total must produce
  identical quorum outcomes.
- Balance channel tamper: modification of balance_commitment,
  balance_signature, E_B, proof_B, or C_B must fail verification.
- Cross-channel binding: weight_signature.I != balance_signature.I
  must fail verification.

---

## 39. Production gate

The browser team receives a green light only when every item below passes:

    [PASS] Cryptographic specification frozen
    [PASS] Standard Paillier construction implemented
    [PASS] Distributed key generation implemented
    [PASS] No trusted dealer
    [PASS] No complete secret key holder
    [PASS] Weighted CLSAG independently verified
    [PASS] Paillier/Pedersen equality proofs independently verified
    [PASS] Hidden direction independently verified
    [PASS] Duplicate authority rejected by consensus
    [PASS] Vote height deterministic
    [PASS] Stake age deterministic
    [PASS] Encrypted aggregate deterministic
    [PASS] Threshold tally deterministic
    [PASS] Tally certificate independently verifiable
    [PASS] Live tally hides individual ballots
    [PASS] Wallet requires no UTXO manual selection
    [PASS] Browser never handles private keys
    [PASS] Automatic execution deterministic
    [PASS] Reorg tests pass
    [PASS] Database recovery tests pass
    [PASS] Fuzzing passes
    [PASS] Linux/Windows interoperability passes
    [PASS] Multi-node 16-member committee test passes
    [PASS] 8-of-16 threshold test passes (n=16 case)
    [PASS] 3-member committee 2-of-3 threshold test passes (n=3 case)
    [PASS] Malicious/offline committee tests pass
    [PASS] Circulating-supply quorum uses historical snapshot at
           voting-end height
    [PASS] Mainnet-sized integration test passes
    [PASS] Three-node mainnet end-to-end V2 vote and tally test passes
    [PASS] Independent cryptographic review completed

The final item is the security gate. It is not optional and not a future
enhancement.