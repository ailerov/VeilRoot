# VeilRoot DAO V2 — Distributed Key Generation (DKG) Specification

Status: FROZEN for the V2 threshold implementation.
Authority: `docs/DAO-V2-IMPLEMENTATION-SPEC.md` is the normative
implementation specification. This document freezes the DKG-specific
engineering beneath it. Where the two documents disagree, the
implementation specification wins.

No DKG code may deviate from this document. Amendments require a new
revision with a documented consensus activation.

---

## 1. Frozen parameters

    committee_size   = 16
    threshold        = 8-of-16
    sharing_degree   = 7         (t in the paper's notation)
    Delta            = 16!  =  20,922,789,888,000

In Nishide-Sakurai notation: n = 16, t = 7, threshold = t + 1 = 8.

Delta is the integer clearing factor used throughout the threshold
sharing and Lagrange interpolation. It is 16!, not 11! and not 8!.

---

## 2. Primary reference

The production construction is:

> T. Nishide and K. Sakurai, "Distributed Paillier Cryptosystem without
> Trusted Dealer", WISA 2010, LNCS 6513, pp. 44–60, published 2011.

Section map for the implementation:

| Purpose | Section |
|---|---|
| Threshold Paillier base mathematics, G = N+1, (t+1,n) model | §2.1 |
| Integer secret sharing over Z with Delta clearing | §2.2 |
| Pedersen VSS over a known-order auxiliary group | §2.3 |
| DKG protocol overview, t < n/2 condition | §3.1 |
| Distributed RSA modulus generation (BGW) | §3.2 |
| Prime condition, relaxed safe-prime assumption | §4 |
| Trial-division test of the (p-1)/2, (q-1)/2 small factors | §4.1 |
| Full dealer-free threshold Paillier construction | §5 |
| Verification key generation proof | Appendix B |
| Partial-decryption ZK proof | Appendix C |

Damgård-Jurik 2000/008 is background/reference lineage only. Its special
g, safe-prime structure, and secret-sharing equations MUST NOT be
transplanted into this construction. Hazay et al. is not used as a
second modulus-generation algorithm. Klinger et al. resharing is not
used in V2.

---

## 3. Base ciphertext format

The Paillier ciphertext format from `dao-v2-paillier-core` is retained:

    N       = 2048-bit RSA modulus
    G       = N + 1
    c       = G^m * r^N mod N^2
    c size  = 512 bytes, canonical big-endian, fixed width

The distributed threshold construction produces N, G, the threshold
secret shares, and the public normalization parameter. It does NOT
change the ciphertext format.

---

## 4. Public threshold key record

The canonical public record for one key epoch contains, at minimum:

    version              = 1
    N                    (256 bytes big-endian)
    G                    = N+1, derived
    theta                (public Paillier parameter)
    theta_prime          (public normalization parameter, see §8)
    committee_size       = 16
    threshold            = 8
    sharing_degree       = 7
    V_K                  (global verification base)
    V_K_i                (per-member verification key, i = 1..16)
    member_identities    (16 committee member identifiers)
    epoch                (uint32, monotone)
    epoch_id             (32-byte hash of the canonical record above)

The record is written once at activation and never modified.

---

## 5. Distributed RSA modulus generation

Reference: §3.1, §3.2 of Nishide-Sakurai.

Participants: all 16 committee members.

Protocol: BGW-style distributed computation of N = p·q. No single
member ever learns p or q. The public output is N.

Intermediate prime candidates p and q are shared using the integer
secret sharing of §2.2 and combined via BGW multiplication. A candidate
that fails §4.1 prime-condition test is discarded and the protocol
restarts.

Requirement t < n/2 for the corruption model is satisfied: t = 7,
n = 16, 7 < 8.

---

## 6. Prime-condition test

Reference: §4, §4.1 of Nishide-Sakurai.

The construction does not require safe-prime p, q. It requires that
the odd parts (p-1)/2 and (q-1)/2 do not have small prime factors below
the committee size.

For n = 16, the small primes tested are 3, 5, 7, 11, 13.

The test is performed distributively: each participant publishes a
blinded value gamma = (p-1)/2 + sum of random shares; the small-factor
gcd is checked on gamma; then the blinding is removed. No participant
learns p mod small_prime or q mod small_prime directly.

A candidate that fails the test is discarded and the modulus-generation
phase restarts.

---

## 7. Integer sharing and VSS

Reference: §2.2, §2.3 of Nishide-Sakurai.

Secret sharing is over the integers with Delta clearing, not over Z_N.
Pedersen VSS is used, not Feldman VSS modulo N^2.

Two groups must be distinguished in the implementation:

    Paillier group:        Z*_(N^2)
    Auxiliary VSS group:   subgroup of Z*_P, P a known large prime,
                           with Pedersen generators g and h

The Pedersen commitment to a share value s is g^s * h^r mod P.

Share verification uses the commitments published in the VSS phase.
The exact verification equation is taken verbatim from §2.3 of the
paper. It is NOT reconstructed from Feldman or from an invented form.

---

## 8. Public normalization parameter

Reference: §5 of Nishide-Sakurai.

The distributed construction produces a public blinded parameter,
denoted theta_prime here, that is required for the final tally
normalization. The name "theta_prime" is a VeilRoot label; the paper's
notation is used verbatim in the source once the paper text is in hand.

theta_prime MUST be a first-class public field of the threshold key
record. It MUST NOT be reconstructed at tally time from information
that is not available.

The exact derivation of theta_prime from the distributed setup is
taken from §5 of the paper. It is not derived by this document.

---

## 9. Partial decryption

Reference: §2.1 and §5 of Nishide-Sakurai.

For committee member i with integer share f(i), and a ciphertext c:

    c_i = c^(2 * Delta * f(i)) mod N^2

The factor 2 is the DJ-2000 lineage correction. Delta is the integer
clearing factor from §1 of this document. Delta MUST NOT be omitted.

Do not confuse:

    Delta        (integer clearing factor, 16!)
    f(i)         (member i's integer share)
    s            (the DJ-2000 expansion parameter, unused here)

Each partial decryption is published with:
- the committee member's index i,
- the verification key V_K_i,
- the partial decryption ciphertext c_i,
- the partial-decryption ZK proof (see §11).

---

## 10. Threshold combination

Reference: §2.1 and §5 of Nishide-Sakurai.

For a subset S of size >= threshold (8), define integer Lagrange
coefficients at 0:

    lambda^S_{0,i}
        = product over j in S, j != i of (-j) / (i-j)

and integer multipliers:

    mu_i = Delta * lambda^S_{0,i}

The combination:

    C = product over i in S of c_i^(2 * mu_i) mod N^2

Given c_i = c^(2 * Delta * f(i)) and mu_i = Delta * lambda^S_{0,i},
this evaluates to:

    C = c^(4 * Delta^2 * f(0))

where f(0) is the shared secret. The value 4 * Delta^2 appears
explicitly in the final normalization.

---

## 11. Final normalization

Reference: §5 of Nishide-Sakurai.

    M = L(C) * (-4 * Delta^2 * theta_prime)^(-1) mod N

where L(x) = (x - 1) / N.

The negative sign and the Delta^2 factor are not optional. They are
the result of the correctness derivation of the dealer-free
construction in §5. Do NOT use the ordinary Paillier mu as the
normalization; that is the wrong formula for this threshold
construction.

After M is recovered, signed plaintext decoding per
`DAO-V2-IMPLEMENTATION-SPEC.md` §9 recovers W_total or S_total.

---

## 12. Verification key

Reference: Appendix B of Nishide-Sakurai.

    V_K_i = v^(Delta * f(i)) mod N^2

The base v is the fixed verification generator of the construction. It
is either a designated public value or the paper's G; the exact
choice MUST be read from Appendix B before implementation and recorded
in the source as a single named constant.

The corresponding proof (Appendix B) demonstrates that V_K_i is
consistent with the member's committed share from §7.

---

## 13. Partial-decryption ZK proof

Reference: Appendix C of Nishide-Sakurai.

Statement: the prover knows x = f(i) such that

    V_K_i        = v^(Delta * x) mod N^2
    (c_i)^2      = c^(4 * Delta * x) mod N^2

This is a Chaum-Pedersen equality of discrete logarithms between two
group generators:

    base1  = v^Delta
    target1 = V_K_i
    base2  = c^(4 * Delta)
    target2 = (c_i)^2

The interactive proof is converted to non-interactive form using
Fiat-Shamir. The Fiat-Shamir challenge transcript binds:

    domain "VeilRoot-DAO-DECRYPT-V2"
    || key epoch id
    || proposal id
    || aggregate ciphertext (canonical 512-byte encoding)
    || committee member index i
    || V_K_i (canonical 512-byte encoding)
    || c_i (canonical 512-byte encoding)

No partial decryption is accepted without a valid proof.

---

## 14. DKG phases

    Phase 1   Distributed RSA modulus generation            §3.1, §3.2
    Phase 2   Prime-condition validation                    §4, §4.1
    Phase 3   Distributed computation of the threshold      §5
              Paillier secret
    Phase 4   Integer VSS and share verification            §2.2, §2.3
    Phase 5   Verification-key generation                   §5, App B
    Phase 6   Publish final threshold public-key record     §4
    Phase 7   Activate dao_tally_key_epoch                  impl spec §27

No trusted dealer exists in any phase. No participant obtains the
complete decryption key.

---

## 15. Security assumptions

The construction relies on the assumptions and structural conditions
of Nishide-Sakurai including:
- t < n/2 (satisfied: 7 < 8)
- the relaxed prime condition of §4, replacing safe-prime generation
- the modified DCR-related assumption for the non-safe-prime setting
- the random-oracle model for the non-interactive proofs

These assumptions must not be weakened in code.

---

## 16. What 3a implements (this commit sequence)

`dao-v2-threshold-paillier-algebra`:

    integer share representation
    Lagrange coefficients mu_i
    partial decryption c_i = c^(2 Delta f(i))
    threshold combination C = prod c_i^(2 mu_i)
    final normalization M = L(C) * (-4 Delta^2 theta')^{-1}
    signed plaintext recovery (reuses dao_paillier decode)

3a does NOT include: VSS verification, verification-key proof,
partial-decryption ZK proof, or any network phase. Those are 3b.

3a is tested with a test-only trusted-dealer-style setup that reuses
`PaillierPrivateKey::generate_for_testing()` to produce a Paillier key
and a locally known secret. This setup exists only inside the unit
test suite and never appears in production code paths.

---

## 17. What 3b implements

`dao-v2-threshold-paillier-dkg`:

    full Nishide-Sakurai distributed setup
    VSS with Pedersen commitments and share verification
    distributed RSA modulus generation
    prime-condition test
    verification-key generation with Appendix B proof
    partial-decryption ZK proof (Appendix C)
    key-epoch state machine and activation

No trusted dealer. No local Paillier key generation in the production
path.

---

## 18. Test programme (3a)

Correctness:

    1..7 shares  must NOT decrypt
    8 shares     must decrypt
    all 8-, 9-, ..., 16-member subsets must decrypt

Boundary:

    M = 0
    M = 1
    M = N-1
    signed S = +W
    signed S = -W
    signed S = 0
    W = W_MAX

Malicious:

    wrong share
    wrong member index
    wrong Delta
    duplicate member in subset
    subset size < threshold

Each test uses a small test committee (n = 4, t = 1) for speed where
the size does not affect the property being tested, and n = 16 for the
size-dependent tests.

---

## 19. Test programme (3b)

16-party DKG with:
    16 honest
    15 honest + 1 malicious
    14 honest + 2 malicious
    ... up to 9 honest + 7 malicious (still within t = 7)

Test malicious prime candidates, malicious shares, invalid VSS
commitments, false complaints, replayed messages, wrong epoch, missing
participant, participant restart, DKG restart, failed candidate modulus.

Invariant: no participant ever obtains the complete decryption secret.
This is verified by attempting reconstruction at each phase from each
participant's local state and asserting it fails below threshold.

---

## 20. Frozen decisions

The following are frozen and MUST NOT be re-derived in code:

    committee_size = 16
    threshold      = 8
    sharing_degree = 7
    Delta          = 16!
    N bits         = 2048
    G              = N + 1
    ciphertext     = 512 bytes canonical big-endian
    primary ref    = Nishide-Sakurai WISA 2010
    no libhcs
    no trusted dealer
    no Klinger resharing in V2
    no DJ-2000 special-key equations in this construction
    no Hazay as a second modulus-generation algorithm