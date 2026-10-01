# Roadmap

Agent Action Surety is usable from source today, while its npm and PyPI packages remain unpublished. The roadmap focuses on turning the current dual-language safety engine into an independently verifiable open-source control boundary for autonomous agents.

This is a technical plan, not a promise of dates. A milestone is complete only when its acceptance evidence is reproducible from the referenced commit.

## Milestone 1 — Public project foundation

- Maintain clear governance, contribution, conduct, support, and security policies.
- Keep TypeScript and Python runtime support aligned with maintained versions.
- Keep runtime dependency count at zero in both packages.
- Keep source-install, build, test, audit, and packaging commands reproducible.
- Publish machine-readable project and citation metadata.

**Acceptance:** a new contributor can identify the trust model, contribution path, supported runtimes, release gates, and private security-reporting channel from the repository root.

## Milestone 2 — Portable policy and receipt conformance

- Publish stable cross-language test vectors for policy decisions and receipt verification.
- Add explicit schema/version identifiers for portable policy and receipt formats where needed.
- Exercise Python-produced receipts in TypeScript verification and TypeScript-produced receipts in Python verification.
- Document backward-compatibility rules before stabilizing the receipt format.
- Provide a small conformance command that can be run without cloud credentials.

**Acceptance:** the same published vectors produce the same allow/deny result and receipt-verification outcome across both maintained implementations.

## Milestone 3 — Agent identity and admission interoperability

- Define a narrow adapter contract for authenticated actor/runtime context supplied by a host.
- Demonstrate interoperability with Agent ProofChain without making either project a mandatory runtime dependency.
- Separate caller claims from host-authenticated identity fields in examples and documentation.
- Preserve explicit host responsibility for credentials, process isolation, and final execution.
- Add negative tests for identity mismatch, missing attribution, and capability escalation.

**Acceptance:** an example host can evaluate identity/admission context, run a Surety policy decision, and verify both projects' evidence without sharing secrets or weakening either trust boundary.

## Milestone 4 — Independent security evidence

- Expand malicious and benign command/path fixtures with externally contributed cases.
- Add mutation/tamper tests for ledger verification and receipt-chain edge cases.
- Publish false-positive and false-negative expectations for interceptor fixtures.
- Keep workflow security checks, dependency audits, and release verification pinned and reproducible.
- Seek independent review of the threat model and at least one release candidate.

**Acceptance:** externally reviewable fixtures and audit artifacts demonstrate what is blocked, what is allowed, and what remains outside the project's guarantees.

## Milestone 5 — Trusted public distribution

- Complete exact-head hosted CI and security gates for a release candidate.
- Verify registry Trusted Publisher bindings and artifact attestations before publication.
- Clean-install packed npm, wheel, and sdist artifacts in isolated consumer environments.
- Publish only from reviewed release workflows; never treat a local build as registry evidence.
- Document rollback, yanking, and vulnerability-response procedures before the first trusted release.

**Acceptance:** independently verifiable build and install evidence exists for the exact commit that is released, and registry-side identity/provenance controls are confirmed.

## How to help

The highest-value contributions are independent security fixtures, cross-platform failures, conformance vectors, interoperability examples, documentation corrections, and reviews that tighten a stated trust boundary. See [CONTRIBUTING.md](CONTRIBUTING.md).
