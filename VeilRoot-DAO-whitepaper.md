# VEILROOT DAO WHITEPAPER

## A Privacy-Preserving, Permissionless and Protocol-Enforced Governance System for the VeilRoot Name System (by Ailerov Thuypan)

###### *Decentralized Governance Protocol and Economic Architecture*  
*Version 1.0 — June 2026*  
*© 2026 VeilRoot. All rights reserved.*  
*This document describes the VeilRoot DAO protocol, including its governance architecture, economic mechanisms, voting system, treasury mechanism, domain governance, and associated protocol innovations. The protocol design and original material presented herein are the intellectual property of VeilRoot and its author, except where otherwise stated.*

---

## Abstract

The VeilRoot Name System (VNS) is a privacy-focused blockchain designed to provide decentralized naming infrastructure without relying on a central registry, foundation, board, or administrative authority.

Its governance layer extends this principle to protocol control itself.

The Veilroot DAO is a fully permissionless, on-chain governance system through which participants can propose treasury grants, modify protocol parameters, and govern bridge configuration. Governance is enforced by blockchain consensus rather than by trusted administrators.

The system combines:

- privacy-preserving transactions derived from Monero's cryptographic architecture;
- stake-age-weighted voting;
- non-consuming voting, allowing participants to retain their underlying balance and stake age;
- ring-signature-based ownership proofs;
- Pedersen commitments;
- threshold cryptography and Distributed Key Generation;
- homomorphic vote aggregation;
- automatically selected tally committees;
- a consensus-locked treasury;
- deterministic proposal lifecycle management;
- permanently burned governance and network fees; and
- protocol-enforced proposal execution.

The resulting architecture separates **economic ownership**, **voting authority**, **treasury custody**, and **execution authority**. No individual participant, committee member, foundation, or operator possesses unilateral control over the governance system.

The DAO is therefore not merely an application running on top of VNS. It is part of the protocol's consensus machinery.

---

# 1. Introduction

Traditional naming systems depend upon centralized authorities.

A conventional registry determines which names exist, who controls them, when they expire, and under what circumstances they can be modified or removed. Governance of such systems ultimately rests with organizations and administrators.

VeilRoot takes a different approach.

The VeilRoot Name System is designed as a decentralized naming layer in which domain registration, renewal, transfer, health, resolution infrastructure, and protocol parameters are represented through blockchain state and decentralized network infrastructure.

The DAO extends that philosophy to governance.

Rather than placing protocol control in the hands of a foundation or development organization, VNS embeds governance directly into the blockchain.

Anyone capable of satisfying the protocol's participation requirements may submit a proposal or vote. Passed proposals are not dependent upon an administrator voluntarily carrying them out: the blockchain itself recognizes their outcome and controls the conditions under which treasury funds or governed parameters may change.

The governance system therefore establishes a closed protocol loop:

**Participation → Proposal → Vote → Tally → Decision → Execution → State Transition**

This architecture is intended to eliminate the need for trusted governance operators while preserving privacy for individual participants.

The underlying VNS design explicitly rejects a foundation, board, or CEO as the authority responsible for system governance.

---

# 2. Design Principles

The Veilroot DAO is built around several fundamental principles.

## 2.1 Permissionless Governance

Governance participation is not restricted to a predefined group of administrators.

Anyone may submit a proposal by paying the required proposal fee, which is burned permanently. Proposals may request treasury grants, protocol parameter changes, or bridge configuration changes.

There is no requirement for a proposal author to belong to a foundation, committee, development company, or other privileged organization.

---

## 2.2 No Central Governance Authority

The DAO does not depend upon:

- a foundation;
- a board;
- a CEO;
- a permanent governance committee;
- fixed operator identities; or
- manually controlled treasury keys.

Committee membership is selected algorithmically according to protocol-defined eligibility criteria.

---

## 2.3 Voting Does Not Consume Stake

Voting power is derived from economic ownership and the age of that ownership.

Voting does **not** transfer, spend, destroy, or otherwise consume the underlying balance.

The whitepaper defines voting weight as:

**W = B × log₂(A + 1)**

where:

- B is the eligible balance;
- A is the age of the balance in days; and
- W is voting weight.

The protocol explicitly specifies that voting does not consume the underlying UTXO and that voters retain both their balance and its age.

This creates an important distinction between **voting participation** and **economic spending**.

A participant can express a governance preference without sacrificing the capital that gives the participant voting power.

---

## 2.4 Privacy by Architecture

Governance is built on the privacy primitives inherited from the VNS blockchain.

These include:

- ring signatures;
- stealth addressing;
- confidential transaction amounts;
- Bulletproofs;
- Dandelion++;
- Pedersen commitments; and
- threshold cryptography.

The underlying blockchain specification uses ring signatures to conceal which member of a decoy set actually authorized a transaction, while stealth addresses prevent straightforward linkage between transactions.

The DAO extends these principles to voting.

A vote proves the right to participate without publicly revealing the participant's specific underlying output.

---

# 3. Governance Architecture

The DAO can be viewed as six cooperating protocol layers.

### Layer 1 — Proposal

A participant creates a governance proposal.

### Layer 2 — Eligibility

The blockchain determines whether a participant possesses eligible voting stake.

### Layer 3 — Voting

The participant submits a private vote representing either support or opposition.

### Layer 4 — Aggregation

The blockchain aggregates voting commitments without requiring individual vote weights to be publicly disclosed.

### Layer 5 — Tally

A dynamically selected committee performs the threshold decryption required to recover the final aggregate totals.

### Layer 6 — Execution

The resulting governance decision becomes an enforceable protocol state transition.

The resulting architecture deliberately separates:

**who proposes → who votes → who tallies → who executes**

while preventing any one role from becoming an unrestricted administrator.

---

# 4. Proposal System

## 4.1 Proposal Submission

Anyone may submit a proposal.

A proposal requires a symbolic submission fee of:

**0.00001 VNS**

The fee is permanently burned rather than transferred to an administrator or retained in the treasury.

Network transaction fees are likewise subject to the VNS burn model.

The purpose of the proposal fee is therefore not to finance governance operators. It is an economic anti-spam mechanism while maintaining permissionless access.

---

## 4.2 Proposal Types

The protocol defines several classes of governance proposal.

### Treasury Grants

A proposal may request funds from the protocol treasury for a specified recipient and amount.

### Parameter Changes

A proposal may modify governed protocol parameters, including:

- extension tiers;
- premium labels;
- banned labels;
- banned extensions;
- registration fees;
- quorum parameters;
- tally committee parameters; and
- other governance-controlled policy values.

### Bridge Configuration

Governance may control bridge parameters such as:

- committee size;
- threshold;
- bond requirements; and
- slashing parameters.

These categories are explicitly identified in the VNS governance design.

---

# 5. Voting Periods

Each proposal specifies a voting period.

The defined periods are:

- **7 days**
- **14 days**
- **30 days**

The selected period determines the interval during which eligible participants may cast votes.

Once the voting period ends, the proposal transitions into the protocol's tally and decision process.

---

# 6. Voting Power

## 6.1 Stake-Age Weight

Voting power combines economic balance with the age of that balance.

For an eligible output:

**Wᵢ = Bᵢ × log₂(Aᵢ + 1)**

where:

- Bᵢ is the balance represented by the eligible output;
- Aᵢ is its age in days;
- Wᵢ is its voting weight.

For multiple eligible outputs, the participant's voting power is derived from the aggregate eligible balance and corresponding stake-age weights according to the protocol's eligibility rules.

This mechanism provides two dimensions of participation:

**economic stake** and **time commitment**.

A newly acquired balance therefore does not immediately possess the same governance weight as an equivalent balance that has remained committed to the network for a longer period.

---

## 6.2 Non-Consuming Votes

A vote does not spend the underlying balance.

This is a fundamental property of the governance system.

The participant's:

- balance remains;
- UTXO remains;
- stake age remains; and
- economic position remains available for future transactions.

The voting transaction proves eligibility without converting the underlying stake into a governance payment.

The whitepaper explicitly defines this property.

---

# 7. Private Vote Construction

Each vote is represented by a transaction containing cryptographic evidence of voting authority.

The protocol specifies:

1. a ring signature proving ownership of an eligible UTXO without identifying it;
2. a Pedersen commitment representing either positive or negative voting weight;
3. encryption of the commitment's blinding factor under a threshold public key.

The intended vote therefore reveals the participant's decision to the protocol without revealing the participant's underlying output.

Conceptually:

**C_YES = Commit(+W, r)**

and

**C_NO = Commit(-W, r)**

where r is a secret blinding factor.

The cryptographic commitment allows the network to aggregate votes without exposing each participant's private voting weight.

---

# 8. Homomorphic Vote Aggregation

The DAO uses the additive properties of Pedersen commitments.

Individual commitments can be combined into an aggregate commitment:

**C_aggregate = Σᵢ Cᵢ**

which corresponds to the aggregate difference:

**W_YES − W_NO**

without requiring every individual vote weight to be published.

The protocol therefore separates:

**vote authorization**

from

**vote disclosure**.

Individual voters remain private while the final governance result becomes publicly verifiable.

The whitepaper specifies that the blockchain aggregates the commitments to represent:

**Total_Yes − Total_No**

and that the final totals are subsequently recovered through threshold decryption.

---

# 9. Distributed Key Generation

The blinding factor associated with voting commitments is protected by a threshold public key.

The key is generated through Distributed Key Generation during network bootstrap.

No individual tally participant therefore possesses the complete secret necessary to decrypt the aggregate voting information.

Instead, the system distributes authority across the selected tally participants.

This prevents the tally mechanism from degenerating into a single private decryption key controlled by one operator.

---

# 10. Permissionless Tally Committee

At the end of a voting period, the protocol automatically selects the tally committee.

The defined default committee consists of the top **16 eligible participants/nodes by stake-age weight**, subject to the protocol's minimum eligibility requirement.

Committee membership is therefore not permanent.

It is determined from protocol state at the moment when the tally is required.

The broader VNS architecture applies the same principle to bridge committees: selection is automatic, based on eligibility and weight, with no permanent operator identities or whitelists.

---

# 11. Tally Process

The selected tally participants collaboratively use their DKG shares to decrypt the aggregate voting information.

The protocol recovers:

**Total_Yes**

and

**Total_No**

These values, together with the relevant quorum parameters, form the authoritative governance result.

The final result is recorded on-chain.

---

# 12. Proposal Acceptance

A proposal passes only when both required conditions are satisfied.

## Condition 1 — Majority

**Total_Yes > Total_No**

## Condition 2 — Quorum

**Total_Yes + Total_No ≥ Quorum**

The default quorum is defined as **10% of the total minted supply at the voting-end height**.

The DAO may modify the quorum through governance in order to adapt the requirement to changes in the effective votable supply.

Thus, a proposal cannot pass merely because it receives more support than opposition.

It must also demonstrate sufficient participation.

---

# 13. Governance State

A governance decision is not merely an external event.

The result becomes part of blockchain state.

The protocol records:

- the proposal;
- its outcome;
- aggregate voting totals;
- the applicable quorum;
- and the resulting governance state.

This allows independently operating nodes to derive the same governance state from consensus data.

The governance result therefore becomes deterministic protocol state rather than an opinion maintained by an external application.

---

# 14. Treasury Architecture

The VNS blockchain directs a portion of block rewards into a dedicated treasury output.

The documented treasury allocation is:

**18% of the block reward**

with the documented example of approximately **0.117 VNS per block**.

Treasury outputs are not ordinary spendable outputs.

They are consensus-locked.

Treasury funds cannot be released merely because a wallet possesses a key or because an administrator requests a payment.

They require a valid governance execution corresponding to a passed proposal.

---

# 15. Treasury Security

The treasury is therefore governed by a two-stage authorization model:

### Stage 1

The DAO approves a proposal.

### Stage 2

The protocol validates execution of that approved proposal.

This creates a separation between **authorization** and **fund movement**.

A treasury output cannot simply be spent by bypassing governance.

The whitepaper defines treasury funds as cryptographically locked and releasable only following positive DAO authorization.

---

# 16. Proposal Execution

Once a proposal passes, the execution stage becomes available.

The protocol permits an execution transaction referencing the proposal ID.

The blockchain validates the execution against the proposal's governance state.

If valid, execution may:

- release treasury funds;
- modify governed parameters; or
- perform another protocol-defined governance action.

The documented architecture explicitly defines execution as a protocol-controlled transition rather than an administrator-controlled payment.

---

# 17. Automatic Governance

The intended governance lifecycle is therefore:

**Submission → Voting → Tally → Decision → Execution**

No external organization is required to advance the system between these conceptual stages.

The blockchain determines when voting ends, whether quorum was achieved, whether the proposal passed, and whether an execution request is valid.

This is the core distinction between Veilroot's DAO and a conventional multisignature treasury.

A multisignature wallet can still require trusted humans to decide when and whether to act.

Veilroot instead makes the **decision itself part of consensus state**.

---

# 18. Parameter Governance

The DAO is capable of governing protocol policy rather than merely distributing treasury funds.

Governable parameters include:

- extension mappings;
- premium labels;
- banned labels;
- banned extensions;
- registration fees;
- tally committee size;
- voting quorum;
- bridge committee size;
- bridge threshold;
- bridge bond;
- bridge slashing parameters.

The documented design specifies that these parameters are stored in blockchain state and updated atomically after an accepted governance decision.

This creates a self-modifying policy layer while keeping the rules governing modification themselves subject to consensus.

---

# 19. Fee Economics

VNS is designed around utility rather than speculative circulation.

The system defines a maximum supply of approximately:

**20,000,000 VNS**

and uses burning mechanisms for network activity.

The proposal submission fee is explicitly burned.

Registration and other network fees are similarly designed to be removed from circulation rather than accumulated by a central organization.

The governance system therefore does not require proposal fees to finance a governance bureaucracy.

---

# 20. Free Governance Participation

Although submitting a proposal requires a burn fee, casting a governance vote is conceptually different.

Voting is not a payment.

The voter does not transfer the underlying stake to the network.

The economic resource remains under the participant's control while its age and balance contribute to governance weight.

This design aims to make governance participation accessible without requiring participants to sacrifice the capital that gives them voting authority.

---

# 21. Privacy and Governance

Traditional on-chain voting often exposes:

- voter addresses;
- vote amounts;
- voting direction;
- voting history;
- balances;
- and relationships between voters and accounts.

Veilroot's architecture attempts to break these relationships.

The system instead separates:

### Ownership Proof

A ring signature demonstrates eligibility.

### Voting Commitment

A Pedersen commitment represents the vote's weight.

### Threshold Decryption

The tally committee collectively recovers the aggregate result.

### Public Result

The blockchain records the final governance outcome.

Consequently, the network can establish:

> **whether the proposal passed**

without necessarily establishing:

> **which identifiable participant contributed which amount of voting power.**

This distinction is central to the privacy model.

---

# 22. Permissionless Committees

Committee membership is not intended to create a permanent ruling class.

The protocol dynamically selects eligible participants.

The documented VNS design states that committee members are selected from eligible nodes according to stake-age weight and that nodes falling below the required threshold are automatically replaced.

This applies to governance tallying and extends to bridge operation.

The committee is therefore a **temporary protocol role**, not a political office.

---

# 23. Bridge Governance

The DAO also governs the configuration of the VNS bridge.

Bridge-related governance parameters include:

- committee size;
- threshold;
- bond requirements;
- slashing rates;
- and related bridge policy.

The bridge itself is designed to operate without a trusted third party.

The documented architecture specifies threshold signing by the active operator committee, with relay software operating automatically alongside VNS nodes.

Governance therefore controls bridge policy without turning bridge operators into permanent custodians.

---

# 24. Relationship Between Blockchain and NOSTR

The VeilRoot architecture intentionally separates authoritative blockchain state from dynamic network information.

Nostr provides the dynamic discovery layer.

It stores information such as:

- service descriptors;
- onion addresses;
- IP fingerprints;
- heartbeat events;
- TLS information;
- and related optional metadata.

The blockchain remains the authoritative source for governance, ownership, registration state, and consensus-controlled parameters.

Nostr provides dynamic service information without requiring the blockchain to contain constantly changing network metadata.

---

# 25. Governance and the Name System

The DAO is not an isolated financial subsystem.

It governs infrastructure directly relevant to the VeilRoot Name System.

Governance can affect:

- namespace extensions;
- premium labels;
- prohibited labels;
- registration pricing;
- domain policy;
- bridge policy;
- and treasury-funded development.

This allows the naming system to evolve without requiring a central registrar to modify its rules.

---

# 26. Dynamic Domain Infrastructure

VeilRoot's naming architecture includes a health mechanism intended to prevent indefinite domain squatting.

Registered domains depend upon continued network health and heartbeat activity.

The broader protocol combines blockchain registration with Nostr-based heartbeat infrastructure, including configurable heartbeat intervals and cryptographic references to registration state.

Governance can therefore evolve policy surrounding the naming system while the underlying blockchain maintains authoritative registration state.

---

# 27. Security Model

The DAO is designed to address several fundamental governance attacks.

## 27.1 Double Voting

A participant must not be able to count the same voting authority more than once for a proposal.

Cryptographic nullifiers and vote validation mechanisms are used to prevent duplicate participation.

---

## 27.2 Sybil Resistance

Governance weight is derived from economic stake and stake age rather than identity.

Creating additional identities does not automatically create additional voting power.

---

## 27.3 Vote Privacy

Ring signatures prevent straightforward identification of the specific output used to establish voting authority.

---

## 27.4 Vote Manipulation

Pedersen commitments prevent individual vote weights from simply being rewritten after publication.

Homomorphic aggregation allows votes to be combined while preserving commitment integrity.

---

## 27.5 Tally Manipulation

Threshold cryptography prevents a single tally participant from possessing unilateral authority over the encrypted aggregate.

---

## 27.6 Treasury Theft

Treasury outputs are consensus-locked and require valid governance execution.

A conventional transaction cannot simply redirect them.

---

## 27.7 Governance Replay

An accepted proposal must not be executable repeatedly.

Proposal execution state therefore forms part of the governance state machine.

---

# 28. Governance Invariants

The following invariants define essential properties of the system.

### Invariant 1

A participant cannot count the same governance authority twice for the same proposal.

### Invariant 2

Casting a vote does not consume the underlying voting stake.

### Invariant 3

A proposal cannot pass without satisfying quorum.

### Invariant 4

A proposal cannot pass unless:

**Yes > No**

### Invariant 5

A rejected proposal cannot authorize treasury execution.

### Invariant 6

A proposal cannot execute more than once.

### Invariant 7

Treasury funds cannot be spent without valid governance authorization.

### Invariant 8

Governance parameters cannot change outside the protocol's authorized state transitions.

### Invariant 9

Committee membership is determined by protocol rules rather than permanent appointment.

### Invariant 10

Independent nodes must derive the same final governance state from the same blockchain history.

These invariants are more important than any individual wallet or RPC implementation.

The implementation is considered correct only insofar as it preserves them.

---

# 29. Governance State Machine

A proposal can be represented conceptually as:

```text
                    ┌─────────────┐
                    │  SUBMITTED  │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │    ACTIVE   │
                    │    VOTING   │
                    └──────┬──────┘
                           │
                     voting ends
                           │
                           ▼
                    ┌─────────────┐
                    │    TALLY    │
                    └──────┬──────┘
                           │
                 ┌─────────┴─────────┐
                 │                   │
                 ▼                   ▼
          ┌─────────────┐     ┌─────────────┐
          │   REJECTED  │     │    PASSED   │
          └─────────────┘     └──────┬──────┘
                                      │
                                      ▼
                               ┌─────────────┐
                               │  EXECUTABLE │
                               └──────┬──────┘
                                      │
                                      ▼
                               ┌─────────────┐
                               │  EXECUTED   │
                               └─────────────┘
```

The important property is that every transition is determined by protocol state rather than human discretion.

---

# 30. Consensus-Enforced Governance

The DAO's strongest architectural property is that governance decisions ultimately become consensus decisions.

A node does not merely display:

> “The DAO voted yes.”

It validates the cryptographic and economic conditions that make the decision legitimate.

Similarly, a node does not merely display:

> “The treasury should pay this grant.”

It validates whether the corresponding proposal actually passed and whether the proposed execution is authorized.

Governance therefore becomes an extension of blockchain consensus.

---

# 31. Why This Model Is Different

Many governance systems separate the blockchain from governance.

The blockchain records transactions.

A separate governance application interprets votes.

A multisignature wallet controls funds.

Human operators execute decisions.

Veilroot attempts to collapse these layers into one deterministic protocol.

The same blockchain state determines:

- who may participate;
- how much voting power exists;
- which votes are valid;
- whether quorum exists;
- whether a proposal passes;
- which governance parameters are active;
- and whether treasury execution is authorized.

This reduces the gap between **governance intent** and **protocol behavior**.

---

# 32. Economic Alignment

Stake-age weighting is intended to reward sustained participation rather than purely short-term acquisition.

The model gives governance weight to two variables:

**Economic Commitment × Time Commitment**

The logarithmic age function prevents age from increasing voting power without bound while still recognizing persistent ownership.

This creates a governance model in which long-term participation contributes additional influence without requiring the participant to permanently lock or surrender the underlying balance.

---

# 33. Treasury Sustainability

The treasury receives a defined share of block rewards and is protected from arbitrary expenditure.

The documented design identifies the treasury as the primary source of funding for contributors and developers, with approximately 31,000 VNS emitted annually under the described parameters.

Treasury governance therefore creates a mechanism for decentralized funding without requiring a permanent centralized treasury manager.

The community decides which eligible expenditures are authorized.

The protocol enforces the resulting decision.

---

# 34. No Permanent Governance Keys

A central objective of the architecture is to avoid a governance master key.

There is no single key that should be capable of:

- changing arbitrary parameters;
- draining the treasury;
- appointing permanent committees; or
- overriding voting results.

Authority is instead distributed among:

- economic participants;
- cryptographic proofs;
- threshold committees;
- blockchain consensus;
- and deterministic state transitions.

---

# 35. Protocol Evolution

The DAO permits the network to evolve without requiring a hard-coded central authority for every policy decision.

For example, if the network determines that a registration tier should change, the community can propose a parameter modification.

If the proposal satisfies the voting rules, the parameter becomes governed blockchain state.

The same mechanism can be used for future protocol policy changes permitted by the governance framework.

This provides an upgrade path while preserving permissionless control.

---

# 36. Governance Transparency

Privacy of individual voters does not mean opacity of governance outcomes.

The protocol records the final governance decision.

The publicly verifiable state includes:

- proposal identity;
- proposal outcome;
- aggregate yes weight;
- aggregate no weight;
- quorum requirement;
- and applicable governance state.

Thus:

**individual participation is private; collective decision is public.**

This distinction is fundamental to the system's design.

---

# 37. Threat Model

The DAO assumes that individual participants may be malicious.

It therefore does not rely on every participant behaving honestly.

Instead, security is derived from protocol rules.

Relevant adversarial scenarios include:

- duplicate voting;
- fabricated voting authority;
- Sybil identities;
- malicious proposal authors;
- malicious tally participants;
- attempts to replay executions;
- attempts to bypass treasury authorization;
- malformed governance transactions;
- attempts to manipulate quorum;
- and attempts to alter governed parameters outside accepted proposals.

The intended security model is therefore **adversarial by default**.

---

# 38. Decentralization Model

The system has no single point at which governance authority resides.

Instead:

| Function | Authority |
|---|---|
| Proposal creation | Permissionless participants |
| Vote eligibility | Protocol rules |
| Vote authorization | Cryptographic proof |
| Vote aggregation | Blockchain |
| Tally | Dynamically selected committee |
| Decision | Consensus rules |
| Treasury authorization | Passed proposal |
| Treasury execution | Consensus validation |
| Parameter changes | DAO |
| Bridge configuration | DAO |

This structure is intended to prevent administrative concentration.

---

# 39. Relationship to the VNS Monetary Model

VNS is not designed as a conventional speculative currency.

The documented architecture describes VNS as a utility token whose principal economic role is associated with network operation and naming infrastructure, with fees burned rather than accumulated for speculative circulation.

The DAO consequently exists primarily to govern the infrastructure rather than to create a financial investment vehicle.

Governance weight is tied to participation in the network's economic security rather than to ownership of a publicly traded governance token.

---

# 40. Governance Philosophy

The central philosophy can be summarized as follows:

> **Those who commit economic resources and time to the network may participate in deciding how the network evolves, while the protocol itself enforces the resulting decisions.**

The design deliberately avoids both extremes:

- unrestricted centralized administration; and
- governance in which votes have no direct connection to protocol execution.

Instead, governance authority is embedded directly into consensus.

---

# 41. Implementation Architecture

The DAO is implemented as a set of cooperating protocol components.

### Blockchain Layer

Responsible for consensus validation, block processing, treasury state, and governance state transitions.

### Governance Layer

Responsible for proposal lifecycle, voting, tallying, execution, and governed parameters.

### Database Layer

Persists proposal state, voting state, execution state, governance parameters, and associated records.

### Wallet Layer

Constructs proposal and voting transactions while preserving the privacy and non-consuming properties of governance participation.

### RPC Layer

Provides controlled interfaces for proposal creation, voting, governance inspection, and execution.

### Network Layer

Propagates governance transactions and blockchain state between independently operating nodes.

The architecture is therefore not dependent upon a single governance application.

A node reconstructs governance state from the blockchain.

---

# 42. Protocol Correctness

A governance implementation should not be judged merely by whether a wallet command succeeds.

Correctness requires the complete protocol pipeline to remain coherent:

**Wallet → Transaction → Mempool → Block → Consensus Validation → Governance State → Tally → Execution**

Every stage must preserve the same proposal identity, voting authority, economic weight, and governance state.

A successful RPC call alone is therefore not evidence of a valid governance implementation.

---

# 43. Future Governance Extensions

The architecture permits additional governance-controlled capabilities without changing the fundamental model.

Potential extensions include:

- additional proposal classes;
- additional parameter namespaces;
- more sophisticated quorum policies;
- additional committee roles;
- expanded treasury expenditure categories;
- bridge policy evolution;
- protocol feature activation;
- and future cryptographic improvements.

Any extension should preserve the fundamental invariants of permissionless participation, privacy, deterministic validation, and consensus-enforced execution.

---

# 44. Limitations and Scope

The DAO specification defines the intended governance architecture.

Individual implementation components may evolve as the VNS software matures.

In particular, cryptographic implementations must be evaluated against the formal protocol requirements rather than treated as equivalent merely because they produce a syntactically valid transaction.

Production deployment requires:

- independent cryptographic review;
- consensus testing;
- adversarial testing;
- chain-reorganization testing;
- database recovery testing;
- treasury accounting verification;
- vote replay testing;
- and multi-node interoperability testing.

The security properties claimed by this document ultimately depend upon those mechanisms being correctly implemented and validated.

---

# 45. Conclusion

The Veilroot DAO is designed as a governance system in which **privacy, economic participation, decentralized selection, and protocol enforcement are combined into a single consensus architecture**.

Its defining characteristics are:

- permissionless proposal creation;
- permanently burned proposal fees;
- stake-age-weighted voting;
- non-consuming voting;
- private voting authorization;
- Pedersen commitment aggregation;
- threshold-decrypted tallying;
- dynamically selected committees;
- quorum-based proposal acceptance;
- consensus-locked treasury funds;
- protocol-controlled execution;
- DAO-controlled parameters;
- and the absence of a permanent central governance authority.

The resulting system does not require participants to trust a foundation to count votes, a committee to control the treasury, or an administrator to execute an accepted decision.

Instead, the intended model is:

**Economic Participation → Private Governance → Cryptographic Tally → Consensus Decision → Protocol Execution**

Veilroot therefore treats governance not as an application layered above the blockchain, but as a native component of the blockchain itself.

The objective is not merely to create a DAO that can vote.

The objective is to create a protocol in which **the rules governing the network can be changed only through the same decentralized, privacy-preserving, consensus-enforced machinery that governs the network itself.**

---