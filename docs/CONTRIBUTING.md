# Contributing to VeilRoot

A good way to help is to test VeilRoot and report bugs. Testing is invaluable in making VeilRoot secure, stable, usable, and compatible across supported platforms.

See [How to Report Bugs Effectively (by Simon Tatham)](https://www.chiark.greenend.org.uk/~sgtatham/bugs.html) if you want guidance on writing effective bug reports.

## General guidelines

* Comments are encouraged, particularly where they explain non-obvious behavior, consensus rules, security assumptions, privacy properties, or VeilRoot-specific architecture.
* If modifying code for which Doxygen or equivalent documentation exists, that documentation MUST be updated to remain accurate.
* Tests SHOULD be added when adding functionality or changing existing behavior.
* Consensus-sensitive, cryptographic, wallet, transaction, blockchain, database, and networking changes SHOULD include reproducible tests whenever practical.
* Security-sensitive changes SHOULD include tests covering both valid and invalid behavior.
* Patches MUST be focused. Unrelated whitespace changes, reindentation, spelling fixes, or formatting changes SHOULD NOT be included unless required by the change or user-visible.
* The existing code style of the surrounding code SHOULD be followed.
* Do not make speculative changes merely because a failure appears possible. Changes to consensus- or security-sensitive code MUST be based on a demonstrated problem, documented requirement, or reasonably verifiable behavior.

Patches SHOULD be self-contained. A good rule of thumb is one patch per separate issue, feature, protocol change, or logical change.

Temporary debugging code, diagnostic logging, assertions, experimental instrumentation, or one-off repair code MUST be removed before the associated change is considered production-ready unless it is intentionally part of the permanent implementation.

Proper squashing SHOULD be performed before a final patch is published. Intermediate broken commits SHOULD NOT remain in the public project history unless they have a specific documented purpose.

If unrelated changes exist in the working tree, use:

```bash
git add -p
git diff
git diff --cached
```

to ensure that only the intended changes are committed.

## Development and repository model

VeilRoot uses Git for distributed revision control.

VeilRoot development infrastructure MAY be maintained privately on project-controlled infrastructure. The public repository is a source distribution, collaboration, and release surface.

Private development infrastructure and public source distribution MUST be kept separate.

The public repository MUST contain only material intended for public distribution.

The public repository MUST NOT contain:

* private keys or credentials;
* Tor hidden-service private keys;
* VPN credentials;
* SSH private keys;
* API tokens;
* private authentication information;
* confidential infrastructure details;
* unnecessary personally identifying information;
* private hostnames or addresses;
* private filesystem paths that identify project operators;
* generated build artifacts that are not deliberately part of source distribution.

Before publishing source from private development infrastructure, the intended public tree MUST be audited for confidential and identifying information.

The controlled publication process SHOULD be used for publishing changes from private development infrastructure to the public repository.

## Privacy and anonymity

VeilRoot is a privacy-focused project.

Contributors MUST consider the privacy implications of changes affecting:

* transaction construction;
* transaction propagation;
* Dandelion++ behavior;
* Tor and I2P routing;
* peer discovery;
* inbound and outbound connections;
* peer-list advertisement;
* node address advertisement;
* wallet behavior;
* release infrastructure;
* diagnostics and logging.

Changes SHOULD preserve the privacy properties inherited from Monero wherever practical.

VeilRoot MAY intentionally differ from upstream Monero where required by VeilRoot's own architecture, but such differences SHOULD be narrow, explicit, documented, and reviewed.

During the founder-bootstrap phase, additional protections are used to reduce the possibility of exposing the founder's real network identity or private infrastructure. Contributors MUST NOT remove or weaken these protections without an explicit architectural decision.

In particular, contributors MUST NOT introduce accidental clearnet connections, peer advertisements, release metadata, diagnostics, or other mechanisms that could expose private infrastructure or identifying information.

## Consensus and protocol changes

VeilRoot contains consensus-critical code.

Changes affecting any of the following MUST be treated as consensus-sensitive:

* transaction formats or transaction versions;
* RingCT;
* CLSAG;
* Bulletproof or Bulletproof+ verification;
* ring sizes or mixin rules;
* key-image handling;
* output indexing;
* block validation;
* hard-fork rules;
* treasury accounting;
* governance state;
* proposal execution;
* domain-registration rules;
* persistent blockchain or governance state;
* block rollback or reorganization;
* P2P behavior that affects blockchain synchronization or transaction propagation.

Consensus-sensitive changes MUST:

1. clearly identify the existing consensus rule;
2. explain the intended new rule;
3. define an explicit activation condition or hard-fork height where applicable;
4. preserve deterministic behavior across all nodes;
5. include tests covering valid and invalid cases;
6. test activation boundaries where applicable;
7. consider synchronization, rollback, reorganization, and wallet compatibility.

New consensus rules MUST NOT be introduced retroactively merely to make a fresh node accept an existing chain.

Historical blocks MUST be validated according to the consensus rules that applied at their respective heights.

New consensus rules SHOULD be activated through fixed, deterministic protocol boundaries rather than mutable runtime state or operator-specific configuration.

Consensus changes MUST NOT depend on whether a particular developer, miner, seed node, or wallet happens to be online.

## Cryptography and privacy-preserving protocols

Changes to cryptographic functionality MUST be reviewed particularly carefully.

Cryptographic implementation changes SHOULD:

* use the established cryptographic libraries already adopted by VeilRoot where appropriate;
* preserve the expected serialization formats;
* provide deterministic and independent verification tests;
* avoid replacing modern primitives with older alternatives merely to work around unrelated implementation problems;
* document any deliberate deviation from upstream Monero behavior.

Where VeilRoot uses RingCT, CLSAG, Bulletproof+, BIP340, or related primitives, contributors MUST distinguish between:

* cryptographic validity;
* transaction format;
* consensus acceptance;
* wallet construction;
* network propagation.

A valid cryptographic object MUST NOT be rejected merely because unrelated relay or wallet logic is incorrect, and a workaround MUST NOT weaken cryptographic or privacy guarantees merely to conceal an implementation problem.

## Build requirements

A correct patch MUST compile cleanly on the principal supported platform relevant to the change.

Build-system changes SHOULD allow VeilRoot to be built from a clean checkout without relying on generated files left behind by a developer's machine.

Generated build artifacts MUST NOT be required to exist in a clean source checkout unless they are deliberately distributed as source artifacts.

Vendored dependencies MUST remain reproducible.

If a dependency is bundled as source, the build system SHOULD build it automatically where practical rather than requiring undocumented pre-built libraries.

The Linux build MUST NOT depend on private developer paths, private repositories, cached artifacts, or untracked generated files.

Windows cross-compilation MUST be reproducible from the documented build environment.

Shell scripts, Makefiles, CMake files, and other build-critical text files MUST use LF line endings where required by the project.

Repository attributes SHOULD enforce the expected line-ending policy.

## Testing

Tests are strongly encouraged for new functionality.

Consensus-sensitive changes SHOULD test:

* valid transactions or blocks;
* invalid transactions or blocks;
* historical behavior;
* hard-fork boundaries;
* block rollback;
* reorganization;
* clean-node synchronization;
* wallet construction and restoration where relevant.

P2P changes SHOULD test both inbound and outbound connection behavior where relevant.

Wallet changes SHOULD be tested with clean wallets where practical.

Cryptographic changes SHOULD have independent or cross-checked verification tests where possible.

A test that merely confirms that the current implementation does not crash is not sufficient to establish consensus correctness.

## Issue reporting

When reporting a bug, include as much of the following as practical:

* VeilRoot version;
* exact Git commit;
* operating system and architecture;
* exact command or operation;
* relevant configuration;
* exact error message;
* relevant logs;
* blockchain height;
* whether the database is fresh or previously synchronized;
* whether the issue reproduces after a clean rebuild;
* exact reproduction steps;
* expected result;
* actual result.

For consensus failures, also include where possible:

* block height;
* block hash;
* transaction hash;
* transaction version;
* hard-fork version;
* proof type;
* input/output type;
* whether other nodes accept the same transaction or block.

For database failures, include whether the failure occurs inside an active LMDB transaction and whether the relevant getter opens its own read transaction.

## Commits

Commit messages SHOULD be concise and meaningful.

A commit subject SHOULD clearly describe the change.

Good examples:

```text
Fix RingCT activation at HF6
```

```text
Restore treasury balance on rollback
```

```text
Allow Tor fluff relay to inbound peers
```

Avoid vague messages such as:

```text
fix
changes
debug
update
stuff
```

A commit SHOULD contain one logical change.

A consensus change SHOULD explain the reason for the change and its activation behavior in the commit body.

Temporary debugging commits SHOULD be squashed into the final logical change before public publication.

Commit messages MUST NOT contain private infrastructure information, private addresses, private credentials, internal paths, or other confidential information.

PGP/GPG signing of commits is encouraged, particularly for maintainers and release-related work.

## Pull requests and review

Public contributions SHOULD use pull requests or an equivalent reviewed-change process.

A contributor SHOULD provide:

1. a description of the problem;
2. reproduction steps;
3. the proposed solution;
4. relevant tests;
5. identification of whether the change affects consensus, privacy, networking, wallet behavior, cryptography, or database state.

The smallest correct patch is preferred.

A pull request SHOULD NOT combine unrelated refactoring with a bug fix or protocol change.

Consensus-sensitive changes SHOULD NOT be merged merely because they make one local node work.

Such changes MUST be considered against:

* existing nodes;
* fresh-node synchronization;
* alternate platforms;
* rollback and reorganization;
* transaction construction;
* transaction validation;
* wallet restoration;
* database state;
* network propagation;
* privacy properties.

Reviewers SHOULD request further testing when a proposed change alters a public protocol contract or consensus rule.

## Private development and public mirroring

Where private development infrastructure is used, public source publication MUST be performed through the designated controlled publication process.

The public Git repository MUST NOT be treated as an unrestricted mirror of private development history.

Private development history containing founder-identifying information, private infrastructure information, credentials, or other confidential material MUST NOT be published merely for the sake of preserving historical commits.

The public repository SHOULD contain a clean, complete source history suitable for public collaboration and release.

The controlled publication process SHOULD:

* synchronize the intended reviewed source;
* verify the exact commit being published;
* run security and content checks;
* verify that private credentials are absent;
* verify that confidential infrastructure information is absent;
* perform public Git operations only through the project's designated protected publication path;
* publish only intended branches and tags.

Public GitHub operations SHOULD NOT be performed directly from protected private infrastructure when the project's gatekeeper architecture provides a protected publication path.

## Networking and anonymity

VeilRoot's bootstrap network MAY use Tor and I2P as privacy-preserving transport zones.

Changes to Tor/I2P behavior MUST distinguish between:

* peer discovery;
* established connection handling;
* blockchain synchronization;
* transaction propagation;
* Dandelion++ stem propagation;
* transaction fluff propagation;
* noise/covert channels.

A change that allows data over an established inbound anonymous connection SHOULD NOT automatically make that connection eligible for unrelated privacy-sensitive stem or noise functions.

The existing privacy properties of anonymous transaction propagation SHOULD be preserved unless a deliberate VeilRoot protocol decision explicitly changes them.

Public-zone behavior MUST NOT be changed incidentally by a Tor/I2P-specific modification.

Founder-bootstrap privacy requirements MAY be stricter than mature-network requirements. Such differences MUST be explicitly documented.

## Database and rollback safety

VeilRoot uses persistent blockchain and governance state.

Any change that writes persistent state MUST define how that state is:

* created;
* read;
* validated;
* rolled back;
* reorganized;
* reconstructed on a fresh node;
* migrated from earlier database versions where necessary.

Persistent state SHOULD have a clearly identifiable connection owner and rollback owner.

A rollback MUST NOT leave derived database state inconsistent with the canonical blockchain.

LMDB access must respect transaction ownership.

A DB getter called while a write transaction is active MUST NOT open an independent read transaction if doing so violates LMDB's transaction model. Where necessary, an `_in_txn` accessor SHOULD use the active transaction.

Governance rollback operations MUST remain within the appropriate enclosing database transaction.

Database repair tools MUST be narrowly scoped, explicitly named, and documented.

Repair tools MUST NOT silently modify consensus rules or alter unrelated chain state.

## Public contracts and protocol evolution

All public APIs, RPC interfaces, transaction formats, network protocols, and consensus rules SHOULD be documented.

Public protocol changes MUST be intentional and versioned where necessary.

A stable public contract SHOULD NOT be broken without a clear compatibility or migration plan.

New protocol features SHOULD use new identifiers or explicit versions rather than silently changing the meaning of existing identifiers.

Old behavior SHOULD be deprecated systematically where compatibility requires it.

Old identifiers SHOULD NOT be reused for unrelated new features.

When a consensus change requires a hard fork, the activation height or activation rule MUST be explicit and deterministic.

Future protocol changes SHOULD be planned with migration, rollback, and fresh-node synchronization in mind.

## Development process

Changes to VeilRoot SHOULD follow this process:

1. Accurately identify the problem.
2. Reproduce it where possible.
3. Determine whether it is a software bug, protocol issue, operational issue, or expected behavior.
4. Identify the smallest correct solution.
5. Evaluate security, privacy, compatibility, consensus, and rollback implications.
6. Implement the change.
7. Test it from a clean environment where practical.
8. Review the complete diff for unrelated changes.
9. Commit the logical change.
10. Validate it on the relevant supported platforms.
11. Publish through the appropriate repository process.

Contributors SHOULD NOT repeatedly patch symptoms without first determining the underlying validation rule, state transition, or ownership problem.

## Creating stable releases

The primary development branch SHOULD contain the latest intended development state and SHOULD build successfully.

Stable releases MUST be created from an explicitly selected commit.

Release tags MUST identify the exact source used to build the published release.

Release tags SHOULD NOT be moved after publication except under a documented emergency procedure.

Before publishing a stable release, the project SHOULD verify:

* clean native builds;
* supported cross-platform builds;
* test results;
* daemon and wallet version output;
* release artifacts;
* SHA-256 checksums;
* release signatures where provided;
* repository privacy and security;
* absence of confidential development information;
* absence of unintended generated artifacts.

A release SHOULD initially be prepared as a draft release or equivalent reviewable state before publication.

A platform MAY be omitted from a release when its release build has not passed the project's validation requirements.

Release notes MUST accurately describe supported platforms and known limitations.

## Project administration and maintainership

VeilRoot maintainers are responsible for protecting the integrity of:

* source code;
* consensus rules;
* cryptographic implementation;
* privacy properties;
* public infrastructure;
* release processes.

The project SHOULD gradually distribute development, review, infrastructure, and release responsibilities as reliable independent contributors become available.

Maintainers SHOULD avoid unnecessary dependence on a single individual.

Project administrators MAY grant or revoke maintainer privileges based on contribution, reliability, security, inactivity, or repeated failure to follow project processes.

Contributors who repeatedly compromise project security, privacy, infrastructure, or collaboration rules MAY be removed from project-controlled systems.

Long-term succession, contributor diversity, and progressive decentralization SHOULD be treated as project goals.

## Code of Conduct

All contributors are expected to behave professionally and constructively.

Technical disagreement is expected and encouraged when it improves the quality, security, or privacy of the project.

Personal attacks, harassment, deliberate disruption, hostile behavior, or repeated disregard for project security and collaboration rules are not acceptable.

## License

VeilRoot is distributed under the license specified in the project's `LICENSE` file.

All contributions MUST comply with that license and with the licensing requirements of any third-party code incorporated into VeilRoot.

Contributors are responsible for ensuring that code they submit may legally be distributed under the project's license.

## Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.