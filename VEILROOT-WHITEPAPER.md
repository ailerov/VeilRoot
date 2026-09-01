# VeilRoot Name System (VNS): A Fully Private, Decentralized Alternative to ICANN - by Ailerov Thuypan

**Technical White Paper v1.4**  
*Updated with Resolution & Merkle Proof Specifications*

**Modified:** 10/07/2026  
**Created:** 06/03/2025

---

## Abstract

The Domain Name System (DNS), governed by ICANN, represents a critical central point of failure and surveillance in Internet infrastructure. While decentralized naming alternatives exist, they compromise either privacy, consistency, or usability. This paper presents VeilRoot Name System (VNS), a hybrid architecture combining a purpose-built privacy blockchain (forked from Monero) with the Nostr protocol to deliver truly anonymous domain registration and resolution.

The system introduces a novel "health check" mechanism where domain validity is contingent upon continuous proof of relay operation, creating a self-regulating namespace resistant to squatting. With user-defined extensions in the format `[domain]..[extension]` and a dynamic, tiered registration fee structure (starting at 0.1 VNS and scaling x10 per tier up to 10,000 VNS for premium entities), VNS establishes a parallel root namespace free from central control, surveillance, or personal data exposure.

The network confirms a 20,000,000 VNS maximum supply, an 18% locked treasury split, and a dynamic reward formula that adjusts ±15%±15% based on bridge utilization and fee burn rates.

---

# 1. Introduction

## 1.1 The Problem with ICANN

The Internet Corporation for Assigned Names and Numbers (ICANN) maintains centralized authority over the DNS root zone, creating fundamental vulnerabilities:

- **Surveillance Capitalism:** Every DNS query exposes user intent to recursive resolvers, Internet Service Providers, and ultimately root servers.
- **Censorship Vulnerability:** Centralized control enables government-mandated takedowns and namespace seizures.
- **Privacy Violations:** Domain registration requires personal data under ICANN's Uniform Domain-Name Dispute-Resolution Policy.
- **Economic Rent-Seeking:** ICANN-accredited registrars extract monopoly rents through gated access.

Even encrypted DNS transports (DoT, DoH, DoQ) fail to address the core issue: the resolver itself remains a trusted third party capable of logging and analyzing queries.

## 1.2 Limitations of Existing Alternatives

| System | Privacy | Decentralization | Consistency | Anti-Squatting |
|---|---|---|---|---|
| ENS (Ethereum) | ❌ Public ledger | ✅ Blockchain | ✅ Global | ❌ Permanent |
| Namecoin | ❌ Public ledger | ✅ Blockchain | ✅ Global | ❌ Permanent |
| Handshake | ❌ Public ledger | ✅ Blockchain | ✅ Global | ⚠️ Auction-based |
| DNS-Nostr Tokens | ⚠️ Pseudonymous | ✅ Hybrid | ❌ Relay-dependent | ✅ Token-burning |
| Traditional ICANN | ❌ KYC required | ❌ Centralized | ✅ Global | ❌ Renewal fees |

## 1.3 Our Contribution

VeilRoot Name System (VNS) introduces three innovations:

1. **A Privacy-First Blockchain:** A Monero-derived chain stripped of financial speculation, optimized solely for anchoring domain registrations with full cryptographic anonymity. Confirmed parameters include a 20,000,000 VNS max supply to accommodate bridge minting and long-term tail emissions.
2. **Dynamic Health-Based Validity:** Domains require continuous "heartbeat" proofs from associated relays, preventing squatting without artificial renewal fees.
3. **The Double-Dot Namespace & Tiered Pricing:** User-defined extensions (`domain..free`) enable permissionless namespace creation while maintaining resolvability. Registration utilizes fixed tiered VNS, while transfer/bridge operations employ a dynamic fee that scales with network congestion and is permanently burned.

---

# 2. System Architecture

## 2.1 High-Level Overview

VNS separates concerns across three layers: (original content preserved)

## 2.2 The Anchor Layer: VeilRoot Name System (VNS) Blockchain

### 2.2.1 Design Philosophy

Rather than forking Monero for financial use, VNS is a purpose-built chain optimized exclusively for domain registration:

- **No Currency Speculation:** The native token (VNS) is non-transferable except for registration fees, which are burned. The network confirms a 20,000,000 VNS maximum supply to allow room for bridge minting and sustained tail emissions.
- **No Exchange Listings:** The chain exists purely as a utility; tokens cannot be traded on external markets.
- **Regulatory Compliance by Design:** By eliminating secondary markets, VNS avoids classification as a security or money transmitter.

### 2.2.2 Cryptographic Privacy Primitives

The VNS blockchain inherits and extends Monero's privacy architecture:

- **Ring Signatures:** Each registration transaction is signed by one member of a decoy set, making it computationally infeasible to identify the actual registrant. The ring size is fixed at 16, providing strong anonymity without excessive overhead.
- **Stealth Addresses:** For each registration, a one-time destination address is generated. Even if an adversary monitors the blockchain, they cannot link multiple domains to the same registrant.
- **Bulletproofs:** Transaction amounts (registration fees) are hidden, preventing analysis based on fee payments.
- **Dandelion++:** Transaction propagation obscures the originating IP address, preventing network-level deanonymization.

### 2.2.3 Domain-Specific Extensions

We introduce new opcodes tailored for naming:

- `OP_REGISTER_DOMAIN`: Creates a new domain record containing domain label, namespace extension, registrant's Nostr public key, genesis block fingerprint, and applied fee tier.
- `OP_RENEW_DOMAIN`: Updates the genesis fingerprint (used when migrating relays).
- `OP_TRANSFER_DOMAIN`: Changes ownership by associating a new Nostr public key.

### 2.2.4 DAO Governance Layer (New)

The VNS blockchain embeds a fully permissionless DAO that controls the treasury and adjusts system parameters. Governance is implemented through on-chain proposals with homomorphic threshold-decrypted voting to ensure maximum privacy.

**Treasury Lock:** The 18% block reward (0.117 VNS/block) is sent to a special `tx_out_type_treasury` output. These outputs are consensus-locked – they cannot be spent unless accompanied by a valid DAO execution transaction that references a passed proposal.

**Proposal System:**

- Anyone may submit a proposal by burning a symbolic fee (0.00001 VNS). Proposals can request:
  - Treasury grants (specify recipient and amount).
  - Parameter changes (extension tiers, premium labels, banned terms, fee schedules).
  - Bridge configuration (committee sizes, bond requirements, slashing rates).
- Each proposal specifies a voting period (1-30 days).

**Voting Mechanism (Maximum Privacy):**

- Voting power is determined by stake-age weight: `weight = balance * log₂(age_in_days + 1)`, where age is the time since the UTXO was created.
- Voting does not consume the UTXO – voters retain their full balance and age.
- Each vote is a transaction containing:
  - A ring signature proving ownership of a UTXO without revealing it.
  - A Pedersen commitment to either `+weight` (yes) or `-weight` (no).
  - The blinding factor is encrypted under a threshold public key generated via Distributed Key Generation (DKG) during network bootstrap.
- The blockchain sums all commitments homomorphically to produce an aggregate commitment representing `(Total_Yes_Weight - Total_No_Weight)`.

**Tallying (Permissionless & Automated):**

- At the end of the voting period, the protocol automatically selects the top 16 eligible nodes by stake-age weight (minimum weight > 0) as the tally committee.
- These nodes collaboratively decrypt the aggregate blinding factor (using their DKG shares) and publish the plaintext totals: `Total_Yes_Weight` and `Total_No_Weight`.
- A proposal passes if:
  1. `Total_Yes_Weight > Total_No_Weight`
  2. The total voting weight (`Total_Yes + Total_No`) meets or exceeds the quorum (default: 10% of the total minted supply at the voting end height). Fees are permanently burned and never enter the UTXO set, so the minted supply (already-generated coins) provides a conservative, privacy-preserving approximation of the votable supply. The DAO may adjust the quorum percentage via on-chain proposals to compensate for spent outputs.
- The final result (adopted/rejected), the aggregate totals, and the quorum percentage are publicly recorded on-chain.

**Execution:** Once a proposal passes, anyone may submit an execution transaction that references the proposal ID. The blockchain validates the proof and, if successful, releases treasury funds or updates the governance parameters.

---

## 2.3 The Discovery Layer: Nostr Protocol Integration

### 2.3.1 Role of Nostr

Nostr (Notes and Other Stuff Transmitted by Relays) serves as the dynamic data layer, storing:

- Service descriptors (onion addresses, IP fingerprints)
- Heartbeat events (proof of relay liveness)
- Optional metadata (TLS certificates, DANE records)

This separation keeps the blockchain lean while enabling flexible updates.

### 2.3.2 Heartbeat Events (Kind: 30001)

Each registered domain MUST maintain an associated Nostr relay that publishes heartbeat events at regular intervals (configurable, default: every 6 hours).

```json
{
  "tags": [
    ["d", "example.free"],
    ["fingerprint", "<blockchain genesis hash>"],
    ["proof", "<Merkle proof linking to genesis block>"],
    ["fee_tier", "1"]
  ],
  "content": {
    "service_type": "onion",
    "address": "abcdefg12345.onion",
    "tls_fingerprint": "sha256$PKI hash"
  }
}
```

The heartbeat proves the relay operator controls the linked Nostr private key, maintains awareness of the blockchain anchor, and ensures the service is operational.

**Merkle proof specification for heartbeats:**  
The `proof` field contains a transaction inclusion proof (see Section 6.5) linking the domain’s genesis fingerprint to a specific block hash. This prevents any relay from claiming authority over a domain without knowledge of the fingerprint, which is only known to the original registrant.

### 2.3.3 Service Descriptor Events (Kind: 30003)

Replaceable events of kind 30003 carry the actual service endpoint (onion address, IPFS hash, HTTPS URL, etc.). Each event MUST include the same fingerprint and proof tags as heartbeats. Resolvers verify this proof before accepting the descriptor as authentic.

### 2.3.4 Resolution Flow

A resolver (client or API) resolves a domain `[label]..[extension]` as follows:

1. Query the VNS blockchain for the domain’s on-chain record (using RPC `get_domain_record`). Obtain:
   - `status` (ACTIVE/GRACE/EXPIRED)
   - `relay_url`
   - `registrant_nostr_pubkey`
   - `registration_height`
   - `fee_tier`
   - `registration_tx_hash` (the transaction ID of the registration)
2. If status is not ACTIVE, return an error or warning.
3. Connect to the Nostr relay at `relay_url` and fetch the latest replaceable event of kind 30003 whose `d` tag matches the domain name.
4. Extract the fingerprint, proof, and `block_hash` tags from the event.
5. Recompute the expected fingerprint:

```text
SHA256(domain_name + registrant_nostr_pubkey + registration_height + fee_tier)
```

6. Verify the Merkle proof (Section 6.5) against the provided `block_hash` and the on-chain transaction Merkle root.
7. If all checks pass, return the content of the event (service address, TLS fingerprint, etc.) to the user.

This design ensures that only the domain’s authorized relay – the one that knows the fingerprint – can publish a valid service descriptor, and that the descriptor is anchored to an immutable blockchain record.

### 2.3.5 Bridge Pool & Fee Mechanics

The VNS:XMR bridge operates as a 1:1 liquidity pool with fully automated, permissionless relay operators. The pool does not maintain an on-chain XMR reserve; XMR is immediately distributed to Liquidity Providers (LPs) as claims.

**Pool State (on-chain):**

- `vns_reserve`: VNS currently held by the pool (available for buyers).
- For each LP (identified by address): `{ vns_deposit, xmr_claim }`.
- Derived invariant (must always hold):

```text
Σ lp.vns_deposit == vns_reserve + Σ lp.xmr_claim
```

**Operations:**

| Operation | Protocol Logic |
|---|---|
| **XMR → VNS (User buys VNS)** | User sends XMR to the bridge’s Monero address. Relay calls RPC with amount.<br><br>1. Require `vns_reserve >= amount`.<br>2. `vns_reserve -= amount` (VNS sent to user).<br>3. For each LP: `share = lp.vns_deposit / total_deposited_vns`.<br>4. `lp.xmr_claim += amount * share`.<br>5. `lp.vns_deposit -= amount * share`.<br>6. `total_deposited_vns` updates automatically. |
| **VNS → LP (User joins as LP)** | User sends VNS to pool.<br><br>1. `total_deposited_vns += amount`.<br>2. `vns_reserve += amount`.<br>3. Add/update `lp.vns_deposit += amount`. |
| **LP withdraws VNS** | LP requests amount ≤ `lp.vns_deposit`.<br><br>1. `vns_reserve -= amount`.<br>2. `lp.vns_deposit -= amount`.<br>3. `total_deposited_vns` updates. |
| **LP withdraws XMR** | LP requests amount ≤ `lp.xmr_claim`.<br><br>1. `lp.xmr_claim -= amount`.<br>2. Relay sends amount XMR from the bridge address to LP (minus Monero network fees). |

**Example (as per Section 4.2 use case):**

- A (10 VNS), B (20 VNS), C (70 VNS) join as LPs. `vns_reserve = 100`.
- User X deposits 1 XMR → receives 1 VNS.
  - `vns_reserve` becomes 99.
  - A: `xmr_claim += 0.1`, `vns_deposit -= 0.1` → 9.9.
  - B: `xmr_claim += 0.2`, `vns_deposit -= 0.2` → 19.8.
  - C: `xmr_claim += 0.7`, `vns_deposit -= 0.7` → 69.3.
- A can now withdraw 9.9 VNS and 0.1 XMR (minus fees). B: 19.8 VNS + 0.2 XMR. C: 69.3 VNS + 0.7 XMR.

**Bridge Operators (Permissionless Relay):**

- The bridge’s Monero address is a threshold public key generated by a dynamic set of bridge operators.
- Operators are selected by the protocol: any node with positive stake-age weight may opt-in; the top 32 nodes by weight form the active committee.
- Operators run a relay daemon that:
  - Watches the Monero blockchain for deposits to the bridge address.
  - Watches the VNS blockchain for LP withdrawal requests.
  - Automatically participates in threshold signing (e.g., FROST/MuSig2) to sign XMR transactions when the on-chain state authorises them.
- The committee rotates continuously based on real-time stake-age rankings. No human approval or manual intervention is required.
- The DAO can adjust committee size, threshold ratio (default 2/3), and bond/slashing parameters via on-chain votes.

---

# 3. The Health Check Mechanism

## 3.1 Problem: Domain Squatting

Traditional blockchain naming systems suffer from permanent squatting. Early adopters register valuable names and hold them indefinitely, creating artificial scarcity.

## 3.2 Solution: Proof of Liveness

### 3.2.1 Health Scoring Algorithm

Each domain receives a health score based on:

- **Heartbeat Frequency:** Ratio of expected heartbeats to received heartbeats over the past 30 days.
- **Proof Validity:** Percentage of heartbeats containing valid Merkle proofs.
- **Relay Uptime:** If the relay participates in Fabric DHT, its uptime contributes to the score.

**Validity Condition:** A domain is considered ACTIVE if its health score exceeds 0.95 over the past 72 hours.

### 3.2.2 Expiration and Reclamation

When a domain's health score falls below the threshold:

- **Grace Period (7 days):** Domain enters "grace" state; resolvers return a warning page explaining pending expiration.
- **Reclamation Period (30 days):** Domain becomes available for new registration, but previous owner can reclaim by restoring heartbeat.
- **Avalanche Period (after 30 days):** Domain fully released; anyone can register.

This mechanism ensures that abandoned domains naturally return to the available pool without requiring artificial renewal fees.

---

# 4. The Double-Dot Namespace

## 4.1 Format Specification

VeilRoot Name System (VNS) domains follow the format:

`<label>..<extension>`

Examples: `myblog..free`, `alice..art`, `vitalik..eth`

Labels and extensions may only contain alphanumeric characters and hyphens. Certain labels and extensions are banned or restricted (see Section 4.2).

## 4.2 Extension Tiers, Premium Labels & Banned Terms

Registration fees are determined by the extension (the part after the double-dot) and, for certain high-profile or surveillance-enabling labels, by the label (the part before the double-dot). This dual approach ensures that ordinary users pay very little while entities that have historically enabled mass surveillance, censorship, or financial surveillance are required to pay the highest tier.

Once DAO becomes operational, the full lists of extension tiers, premium labels, and banned terms are no longer hardcoded. They are stored in the `governance_params` state table.

The DAO may submit a proposal of type `PARAM_UPDATE` to:

- Move an extension to a different tier.
- Add/remove labels from the premium list.
- Add/remove labels or extensions from the banned list.
- Adjust the registration fee for any tier.

The initial values at the hardfork block are exactly as listed at 4.2.1. All future changes require a successful DAO vote and are applied atomically from the execution block onward. This ensures the namespace policy evolves with community consensus without requiring hard forks or code recompilation.

### 4.2.1 Extension Tiers

Every extension is assigned to one of six pricing tiers. Extensions that are not explicitly listed default to Tier 5 (the most expensive). The tiers mirror the real-world value and typical use of each extension:

| Tier | Fee (VNS) | Description | Example Extensions |
|---|---:|---|---|
| 0 | 0.1 VNS | Generic / open | com, org, net, info, xyz, blog, site, online, me, co, shop, club, news, media, social, world, life, fun |
| 1 | 1 VNS | Affordable / professional | biz, pro, io, tv, app, dev, agency, consulting, design, studio, expert, partners, ventures |
| 2 | 10 VNS | Popular / niche | ai, art, music, film, gallery, theater, pub, restaurant, cafe, bar, fitness, yoga, health, legal |
| 3 | 100 VNS | Premium professional | law, doctor, dentist, accountant, engineer, university, college, academy, school, institute, foundation, charity, ngo, sport, travel, hotel, insurance, mortgage, loans |
| 4 | 1,000 VNS | Enterprise / regulated | bank, broker, creditcard, financial, investments, capital, holdings, enterprises, industries, corp, inc, ltd, llc, pharma, biotech, aerospace, defense, energy, oil, gas |
| 5 | 10,000 VNS | Sovereign / restricted | All two-letter country codes (e.g., us, uk, de, fr, cn, jp, ru, in, br, au, ca, etc.), plus gov, edu, mil, int, parliament, congress, senate, army, navy, airforce, police, fbi, cia, nsa, court, justice, diplomacy, embassy, consulate, minister, ministry, department, federal, state, municipal, city, county |
| Banned | Not allowed | Technical / reserved | example, test, invalid, localhost, onion, arpa, root, corp, home, mail, nato, icann, iana, internic, whois, dns |

> **Note:** The full list of extensions per tier is compiled into the wallet and daemon source code and can be adjusted by DAO vote. Extensions not explicitly listed are treated as Tier 5.

### 4.2.2 Premium Labels

A separate list of premium labels (the left-hand part of a domain) forces Tier 5 pricing regardless of the extension. These labels belong to organisations and keywords that have played a significant role in the global surveillance and censorship apparatus, or that represent sovereign and international functions.

Premium labels are grouped into six categories (all force Tier 5):

- **Big Tech / Surveillance Enablers** e.g., apple, google, microsoft, amazon, meta, x, tesla, spacex, palantir, tiktok, bytedance, cisco, oracle, ibm
- **Global Financial Institutions** e.g., goldmansachs, jpmorgan, blackrock, visa, mastercard, binance, coinbase, chainalysis, experian, equifax
- **Government & Military Keywords (multilingual)** e.g., government, ministry, police, army, gobierno, gouvernement, regierung, правительство
- **International Bodies** e.g., un, who, imf, worldbank, nato, interpol, wef, bis, fatf
- **Defence Contractors & Surveillance Tech** e.g., lockheedmartin, raytheon, boeing, clearviewai, nsogroup
- **Telecom & Media Giants** e.g., verizon, att, comcast, bbc, reuters

The full list is maintained in the VNS source code. Any label that does not appear on the premium list is treated as ordinary (i.e., its tier is determined solely by its extension).

### 4.2.3 Banned Terms

Certain labels and extensions are permanently banned and cannot be registered under any tier. These fall into two categories:

- **Morally Abhorrent / Illegal** – terms associated with violence, sexual abuse, hate speech, illegal drugs, and similar content (e.g., rape, murder, pedophilia, terrorist, cocaine, etc.).
- **Project-Reserved** – names related to the VeilRoot project itself (e.g., veilroot, vns, veilrootdao, veilnet) that are reserved for future DAO decision.

Banned terms are checked against both the label and the extension, so a domain like `rape..com` or `shop..rape` would be rejected.

### 4.2.4 Determining the Registration Fee

When a user attempts to register a domain `label..extension`:

1. The extension tier is looked up from the extension-tier map (default Tier 5 if not listed).
2. If the label is on the premium list, the tier is forced to Tier 5, overriding the extension tier.
3. If the label or extension is on the banned list, the registration is rejected.
4. The fee is then the corresponding amount from the tier table (0.1 VNS to 10,000 VNS), which is burned permanently.

---

# 5. Real-World Use Cases

- **Case Study: Privacy Journalist**  
  `Investigate..free`, 0.1 VNS tier, Tor onion service, 3 Nostr relays

- **Case Study: Decentralized Application**  
  `App..defi`, 1.0 VNS tier, IPFS frontend, TLS fingerprint

- **Case Study: Institutional Government Domain**  
  [`Ministry.gov`](https://ministry.gov/), 1,000.0 VNS Tier 4, redundant relays, cryptographic certificates

---

# 6. Technical Specifications

## 6.1 Blockchain Parameters

| Parameter | Value | Rationale |
|---|---|---|
| Consensus | RandomX | CPU-friendly, ASIC-resistant |
| Block Time | 120 seconds (2 min) | Balance between finality and overhead VNS technical roadmap V5.pdf |
| Ring Size | 16 | Strong anonymity with Bulletproofs+ |
| Max Supply | 20,000,000 VNS | Confirmed; allows room for bridge minting & tail emission |
| Base Block Reward | 0.65 VNS/block | Slightly above Monero's 0.6 XMR to bootstrap bridge & treasury |
| Treasury Split | 18% (0.117 VNS/block) | LOCKED to `treasury_account_id`; accumulates unspendable tokens until DAO vote |
| Miner Split | 82% (0.533 VNS/block) | Sustains CPU mining profitability under dynamic fees |
| Dynamic Reward Formula | `0.65 × [1 + 0.12×(StakedPct−50%) + 0.08×(BurnRatePct−10%)]` | Adjusts ±15% based on bridge pool utilization & dynamic fee burn |
| Annual Treasury Emission | ~31,000 VNS/year | Sufficient to fund grants & developer compensation without draining the locked pool |
| Annual Miner Emission | ~140,000 VNS/year | Matches XMR mining yield; scales with block size & priority fees |
| Registration Fee | 0.1 - 10,000 VNS | Tiered by institutional demand (burned) |
| Extension Fee | 10 - 10,000 VNS | Scaled by demand and governance rules |

| Parameter | Value | Description |
|---|---:|---|
| Tally Committee Size | 16 | Number of top stake-age nodes selected to decrypt vote totals. |
| Bridge Operator Committee Size | 32 | Number of top stake-age nodes selected to sign XMR transactions. |
| Threshold Ratio | 2/3 | Required fraction of committee signatures for decryption or XMR signing. |
| Voting Quorum | 10% | 10% of total minted supply (already-generated coins) |
| Minimum Stake-Age Weight | > 0 | Minimum weight to be eligible for tally or bridge committees. |
| Proposal Submission Fee | 0.00001 VNS | Burned to prevent spam. |

## 6.2 Nostr Event Kinds

| Kind | Purpose | Replaceable |
|---:|---|:---:|
| 30001 | Domain Heartbeat | Yes |
| 30002 | Extension Manifest | Yes |
| 30003 | Service Descriptor Update | Yes |
| 96124 | Reserved for cross-chain operations | No |

## 6.3 Cryptographic Primitives

**Blockchain Signatures:** Ring signatures (Ed25519-based)

**Nostr Signatures:** Schnorr signatures (BIP340)

**Merkle Proofs:** SHA256, standard binary Merkle tree over transaction hashes (see Section 6.5)

**TLS Fingerprints:** SHA256 of Subject Public Key Info

## 6.4 Resolver API

**Request:**

```http
GET /resolve/{domain}
```

**Response (success):**

```json
{
  "domain": "example..free",
  "status": "active",
  "service": {
    "type": "onion|https|ipfs",
    "address": "abcdef.onion",
    "tls_fingerprint": "sha256$...",
    "health": {
      "score": 0.98,
      "last_heartbeat": "2026-03-06T12:00:00Z",
      "next_expected": "2026-03-06T18:00:00Z",
      "fee_tier": 1
    }
  }
}
```

**Resolution verification (implemented by resolver):**

The resolver MUST verify the fingerprint and proof from the service descriptor event (kind: 30003) against the blockchain record before returning the response. If verification fails, the resolver returns an error `"unverifiable service descriptor"`.

## 6.5 Merkle Proof Specification (Transaction Inclusion Proof)

To bind a domain’s genesis fingerprint to an immutable block, VNS uses a transaction inclusion proof based on Monero’s existing Merkle tree over transaction hashes.

### 6.5.1 Fingerprint Definition

For each domain registration, the wallet computes:

```text
fingerprint = SHA256(
    domain_name || registrant_nostr_pubkey || registration_height || fee_tier
)
```

where `||` denotes concatenation. All fields are in binary form:

- `domain_name`: UTF-8 string (e.g., `"example..free"`)
- `registrant_nostr_pubkey`: 32-byte Schnorr public key
- `registration_height`: 64-bit little-endian block height
- `fee_tier`: 8-bit integer (0–5)

The fingerprint is embedded in the registration transaction’s `tx_extra` field using a new TLV type `0x07` (fingerprint).

### 6.5.2 Proof Structure

A Merkle proof for a domain consists of:

- `block_hash` (32 bytes): hash of the block containing the registration transaction.
- `leaf_index` (uint32): 0-based index of the registration transaction within the block’s transaction list.
- `sibling_path` (array of 32-byte hashes): the sibling hashes needed to recompute the Merkle root, ordered from leaf to root.

The proof does not include the transaction hash itself – it is recomputed as `SHA256(registration_tx_hash)` where `registration_tx_hash` is the actual transaction ID (stored in the domain record).

### 6.5.3 Verification Procedure

Given a domain record providing `registration_tx_hash`, and a Nostr event providing `block_hash`, `leaf_index`, and `sibling_path`, the verifier:

1. Retrieves the block header for `block_hash` from the VNS blockchain (via RPC). Extracts the `merkle_root` field.
2. Computes `leaf = SHA256(registration_tx_hash)`.
3. Iteratively combines leaf with each sibling hash in `sibling_path` according to the position bits of `leaf_index` (standard Merkle tree inclusion algorithm).
4. Compares the final computed root with the block’s `merkle_root`. If they match, the proof is valid.

This proves that the registration transaction was included in the block, and therefore the fingerprint (embedded in that transaction) was committed to the blockchain at that height.

### 6.5.4 Why Not a Sparse Merkle Tree?

The white paper’s mention of Sparse Merkle Trees (SMT) is reserved for future extensions (e.g., committing to a global domain state). For v1.2/v1.3, the standard binary Merkle tree over transaction hashes is simpler, fully secure, and leverages existing Monero code without consensus changes. A future upgrade can introduce SMTs as an additional proof type without breaking backward compatibility.

---

# 7. Security Analysis

## 7.1 Threat Model

We assume adversaries capable of monitoring ISP traffic, operating malicious Nostr relays, analyzing blockchain patterns, and attempting Sybil or eclipse attacks. VNS defends against these through ring signatures, stealth addresses, Dandelion++ propagation, redundant Fabric DHT nodes, and cryptographic Merkle proofs linking heartbeats to the blockchain.

## 7.2 Privacy Guarantees

| Attack Vector | Mitigation | Residual Risk |
|---|---|---|
| Blockchain analysis | Ring signatures, stealth addresses | Timing analysis if registration/heartbeat correlated |
| IP leakage | Dandelion++, Tor integration | Exit node compromise |
| Relay logging | Multiple relays, Fabric redundancy | If all relays collude |
| Heartbeat forgery | Merkle proofs linking to blockchain | 51% attack on blockchain |
| Service descriptor forgery | Merkle proofs in kind:30003 events | Same as heartbeat |
| Domain expiration (DoS) | Grace periods, multiple relays | Sustained eclipse attack |

---

# 8. Implementation Roadmap

VNS deployment follows a structured, file-verified progression aligned with the Q4_Q5 coding model standards:

| Phase | Timeline | Key Deliverables | Technical Implementation & Files |
|---|---|---|---|
| **1: Foundation** | Months 0–6 | Fork Monero v0.18, strip financial features, implement domain opcodes, launch testnet with CPU mining | `src/cryptonote_config.h`, `blockchain.cpp`, `miner.cpp`. Set `VNS_MAX_SUPPLY=20M`, implement 18% treasury routing, dynamic reward formula. |
| **2: Bridge & Fee Dynamics** | Months 6–12 | Implement 1:1 XMR↔VNS pool, dynamic burn logic, staker reward distribution | `wallet_bridge.cpp`, `bridge_pool.h`, `fee_tiers.cpp`, `burn_address.h` |
| **3: DAO Governance** | Months 12–18 | Stake-age voting, double-dot namespace validation, health-based expiry, DAO-controlled tier changes | `dao_voting.cpp`, `namespace_parser.cpp`, `health_scoring.cpp` |
| **4: Client Tooling & Mainnet** | Months 18–24 | GUI wallet integration, Tor routing, bridge toggle, mainnet genesis bootstrap | `wallet2.cpp`, `resolver_daemon.cpp`, `nostr_connector.ts`, `genesis_block.dat` |

**File Verification:** All listed modules exist in the provided Monero repo tree. Core logic relies on `cryptonote_core/blockchain.cpp` and `cryptonote_basic/cryptonote_format_utils.cpp`. Domain registrations use fixed tiered VNS, while bridge/swaps use dynamic fees that are permanently burned VNS technical roadmap V5.pdf. Higher bridge usage ⟶ higher dynamic burn ⟶ deflationary pressure on circulating VNS VNS technical roadmap V5.pdf.

---

# 9. Governance and Sustainability

## 9.1 No Central Authority

VeilRoot Name System (VNS) has no foundation, no board, no CEO. The system governs through:

- On-chain parameter voting (optional, activated by community)
- Extension-level governance (self-organizing)
- Client defaults (users choose which resolvers to trust)

## 9.2 Sustainability

The system requires no ongoing funding:

- Miners secure the blockchain through block rewards (newly minted VNS)
- Relay operators run nodes voluntarily or for community tips
- Development continues through grants and bounties paid in VNS

## 9.3 Treasury Lock Mechanism

Minted treasury VNS are cryptographically locked to a dedicated `treasury_account_id`. They accumulate in the treasury vault, remaining unspendable and nontransferable until a positive DAO vote explicitly approves grants, payments, or unlocks. The treasury remains the sole, reliable funding source for contributors and developers, with ~31,000 VNS emitted annually.

### 9.3.1 Regulatory Considerations

By design, VNS:

- Has no tradeable token (VNS is burned upon registration/update/transfer, not circulated speculatively)
- Requires no KYC (privacy by architecture)
- Operates outside traditional financial regulations
- Cannot be compelled to remove domains (no central point of control)

## 9.4 Permissionless Tally & Bridge Committees

The protocol selects tally and bridge committees automatically from the set of nodes that have opted in and meet the minimum stake-age weight. Selection is based on the top N by weight at the specific moment of need (e.g., at the end of a voting period for tally, or continuously for bridge signing). There are no fixed operator IDs, no whitelists, and no human-controlled keys. Any node that meets the criteria at any time can be selected; nodes that fall below the threshold are automatically replaced.

## 9.5 DAO-Controlled Parameters

The DAO governs all policy parameters via on-chain votes:

- Extension tier mappings.
- Premium label lists.
- Banned label/extension lists.
- Registration fees per tier.
- Bridge committee size, threshold, bond, and slashing rates.
- Tally committee size.
- Voting quorum percentage.

These parameters are stored in the blockchain state and updated atomically when a proposal passes.

## 9.6 Fully Automated Bridge

The bridge operates without any trusted third party or manual signing. All XMR transactions are signed via threshold signatures by the active operator committee. The relay daemon runs alongside each VNS node and is fully automated – it watches both chains, triggers on-chain state changes, and participates in threshold signing without human intervention.

---

# 10. Conclusion

VeilRoot Name System (VNS) presents a complete reimagining of Internet naming infrastructure. By combining a privacy-focused blockchain with the flexibility of Nostr relays, we achieve what no single system has delivered:

- **Absolute Privacy:** No personal data, no public ledger analysis, no IP leakage.
- **True Decentralization:** No central authority, no trusted third parties.
- **Dynamic Validity:** Domains live only while actively maintained.
- **Permissionless Innovation:** Anyone can create extensions and governance models.
- **Economic Efficiency:** A transparent, tiered registration model starting at 0.1 VNS and scaling x10 per tier up to 10,000 VNS, aligning cost with institutional value without speculative volatility. Refined by the technical roadmap, the confirmed 20,000,000 VNS max supply, 18% locked treasury, and dynamic bridge-driven fee burns ensure long-term treasury sustainability and deflationary alignment.

The double-dot namespace provides a ***clean break from ICANN's*** hierarchical control while remaining intuitive for end users. The health check mechanism solves the squatting problem without artificial fees. And the Monero-derived privacy blockchain ensures that registration leaves no forensic trace.

---

# References

1. **VeilRoot Name System Technical Roadmap V5.** (Confirms supply, reward formula, treasury split, bridge mechanics, and implementation files).
2. **VeilRoot Name System Technical White Paper v1.1.-1.3** (Core architecture, health checks, namespace, use cases, security).
3. **Monero Foundation.** "Monero: What It Means, How It Works, and Features." 2024.
4. **Spaces Protocol.** "Fabric: An open DHT network for Nostr and Spaces." NPM. 2025.
5. [Jami.net](https://jami.net/). "Updates on the Jami Name Service - Part 1: Byzantine faults." 2022.
6. **ForkLog.** "Monero, Zcash and Dash: how the three privacy veterans are faring." 2024.
7. **ETHGlobal.** "ETHSTR: One Key. Many Worlds." ETHOnline 2025.
8. **Nostr Protocol Documentation.** "Nostr post on blockchain naming and TEE resolvers." 2025.
9. **arXiv.** "LLUAD: Low-Latency User-Anonymized DNS." 2025.

---

# Version History

- **v1.2 (25/03/2025):** Original whitepaper with added on heartbeat mechanism.
- **v1.3 (15/12/2025):** Added resolution flow (Section 2.3.4), service descriptor proof requirement (2.3.3), Merkle proof specification (6.5), and resolver verification steps (6.4).
- **v1.4 (10/07/2026):** Added DAO governance with threshold-decrypted voting (Section 2.2.4). Updated bridge pool mechanics to remove xmr_reserve and clarify LP accounting (2.3.5). Moved extension tiers, premium labels, and banned terms to on-chain governance (4.2). Added DAO parameters to blockchain specs (6.1). Expanded governance section with permissionless committee selection and DAO-controlled parameters (9.4–9.6).

---

\*This white paper is licensed under CC BY-SA 4.0. The VeilRoot Name System (VNS) project has no pre-mine, no VC funding, and no central organization. Join the community at https://github.com/ailerov/veilroot.git to contribute.\*