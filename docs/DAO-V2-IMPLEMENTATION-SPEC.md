# VeilRoot DAO V2 — Implementation Specification

Status: FROZEN for the V2 consensus implementation.
Authority: the DAO whitepaper defines user-visible governance. This document
freezes the engineering specification underneath it. Where this document
and the whitepaper disagree on a numeric parameter, this document wins for
V2; the whitepaper is amended separately and only after V2 is audited.

No consensus code may deviate from this document. Amendments require an
explicit new revision with a documented consensus activation.

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

    quorum_threshold = (10 * minted_supply_at_voting_end) / 100

where `minted_supply_at_voting_end` is the total minted VNS supply at the
block height at which voting ends, in atomic units.

The comparison is:

    YES_weight + NO_weight >= quorum_threshold

Governance weight is not equated with monetary supply in general. The
quorum rule compares an aggregate weight to a numeric threshold. This
rule is taken verbatim from the DAO whitepaper §12 and is retained.

Acceptance also requires:

    YES_weight > NO_weight

Both conditions are independent. A proposal may fail either one.

---

## 4. Committee

Frozen parameters:

    committee_size   = 16
    threshold        = 8-of-16
    sharing_degree   = 7
    Delta            = 16! = 20,922,789,888,000

The threshold is fixed by the security requirements of the selected
distributed threshold Paillier construction (Nishide-Sakurai, WISA 2010).
That construction defines a (t+1, n) threshold system and requires
t < n/2. For n = 16 the maximum t is 7, hence the threshold t+1 = 8.
Any larger threshold is outside the construction's stated security
bound; any smaller threshold reduces the number of corrupted parties
the protocol tolerates.

Any valid 8-of-16 partial decryptions suffice to produce a tally
certificate. The committee is selected dynamically by existing stake-age
eligibility rules at tally time. It is not a permanent administrator set.

The threshold is a protocol parameter frozen here. Code MUST NOT
hard-code a threshold value; it reads this constant.

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

        fixed_512_byte E_W;
        fixed_512_byte E_S;

        weighted_clsag_proof weighted_clsag;

        paillier_pedersen_equality_proof proof_W;
        paillier_pedersen_equality_proof proof_S;

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
16. aggregate C_W matches sum of per-input V_i.
17. C_S is a valid curve point.
18. E_W, E_S are valid Paillier ciphertexts (in Z_(N^2)*).
19. Paillier/Pedersen consistency proof for W verifies.
20. Paillier/Pedersen consistency proof for S verifies.
21. hidden-direction OR proof verifies.
22. transcript hash verifies.
23. duplicate-nullifier lookup against previous chain state.
24. duplicate-nullifier lookup within the block.
25. only now mutate governance state.

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

DKG uses a published distributed-Paillier or distributed-RSA-generation
construction:

- Nishide, Sakurai (WISA 2010) for dealerless distributed Paillier;
- Hazay, Mikkelsen, Rabin, Toft, Nicolosi for malicious-adversary
  distributed RSA generation and threshold Paillier;
- Klinger, Wüller, Traverso, Meyer for dynamic resharing without secret
  reconstruction.

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

DAO cryptographic key state:

    dao_tally_key_epoch
    dao_tally_key_id          (hash of the canonical public key record)
    public modulus N
    threshold T = 8
    committee size N_committee = 16
    activation height

Every vote binds to the epoch and key id. A different public key cannot be
silently substituted.

When a new epoch activates:

- old votes remain valid under their historical epoch;
- new votes use the new epoch;
- final tally for a proposal uses the epoch recorded in the proposal.

Secret shares never enter blockchain state.

---

## 28. Partial decryption

Each tally member produces a partial decryption for the aggregate W and
aggregate S ciphertexts.

Each partial decryption binds to:

- proposal ID;
- key epoch;
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
    set of valid partial decryptions
    set of partial-decryption proofs
    W_total
    S_total
    YES
    NO

Valid only when at least 8 distinct committee members provide valid
shares. Independently verifiable by every node. Anyone can collect shares
and submit the tally object. No administrator is required.

---

## 30. Final tally algorithm

1. obtain aggregate E_W;
2. obtain aggregate E_S;
3. obtain at least 8 valid partial decryptions for each;
4. verify each partial-decryption proof;
5. combine per the threshold reconstruction;
6. recover W_total;
7. recover signed S_total;
8. require 0 <= W_total <= W_MAX;
9. require |S_total| <= W_total;
10. require (W_total + S_total) even;
11. YES = (W_total + S_total) / 2;
12. NO  = (W_total - S_total) / 2;
13. check quorum;
14. check YES > NO;
15. write result to consensus state.

No individual ballot is decrypted.

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

Explicit consensus activation height / version.

Before activation: V1 rules may remain for historical compatibility.
After activation: V1 DAO votes are rejected. No ambiguous dual validation.

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
    [PASS] 8-of-16 threshold test passes
    [PASS] Malicious/offline committee tests pass
    [PASS] Mainnet-sized integration test passes
    [PASS] Independent cryptographic review completed

The final item is the security gate. It is not optional and not a future
enhancement.