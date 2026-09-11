# Governance

Agent Action Surety is an MIT-licensed open-source project stewarded by Nymrel. Governance is intentionally lightweight while the project is early, but security and release decisions remain evidence-driven and reviewable.

## Decision model

- Routine fixes and documentation changes are proposed through pull requests.
- Behavior changes should include tests in both TypeScript and Python when they affect shared guarantees.
- Security-boundary changes must state the threat addressed, the new trust assumption if any, and the verification evidence.
- Maintainers may reject changes that weaken default-deny behavior, cross-language parity, reproducibility, or the zero-runtime-dependency contract without a documented project-level decision.
- Public API or receipt-format changes should include migration notes before a stable release adopts them.

## Maintainer responsibilities

Maintainers are responsible for reviewing contributions, keeping supported runtimes current, coordinating vulnerability disclosure, maintaining release gates, and preventing the project documentation from making guarantees stronger than the implementation supports.

Repository access does not by itself authorize a release. Package publication, release signing, and other provider-side actions follow the repository's explicit release workflow and independent verification gates.

## Contribution path

Anyone may open an issue or pull request. Repeated high-quality contributions can lead to broader review responsibility. Maintainer or release authority is granted explicitly; it is never inferred from contribution volume or automation access.

## Security decisions

Potential vulnerabilities must be reported through the private path in [SECURITY.md](SECURITY.md). Public discussion can resume after a fix or disclosure decision makes that safe.

For disputed security behavior, maintainers should prefer a minimal reproducible test, a documented trust boundary, and a fail-closed outcome over intuition or popularity.

## Roadmap and prioritization

The public [ROADMAP.md](ROADMAP.md) records near-term technical priorities and acceptance evidence. Community demand, exploitability, interoperability, maintenance burden, and independent verification all influence priority.

Funding does not purchase control of the project or undisclosed exceptions to its security guarantees. Material sponsored work should remain reviewable under the same contribution and release rules as other changes.

## Changes to governance

Governance changes are made through a public pull request so contributors can inspect the rationale and history. If stewardship changes, this file should be updated before the new steward exercises release authority.
