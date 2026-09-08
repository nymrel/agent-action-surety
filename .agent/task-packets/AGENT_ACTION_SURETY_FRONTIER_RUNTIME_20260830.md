# Agent Action Surety frontier runtime and integration pass

Date: 2026-08-30
Owner: Codex
Claim: `codex-surety-frontier-runtime-integration-20260830`
Goal: `01a04d87-73f3-73e0-bd2f-8c89ee2b1023`
Pull request: `nymrel/agent-action-surety#2`
Canonical base: `92626655d03f1357d152027b9966fec53d2c7342`
Accepted PR head: `4e7eb525c1d865206c4a1e6ec4ed1d8ff25fdead`
Integration base: `62fe45046b891e4a76086bb25df6b205d91ce227`

## Why now

Surety is the reusable execution firewall for other agents, so its own delivery
contract must model the standard it enforces. The accepted release PR still
claims end-of-life Node 18/20 and Python 3.9/3.10, permits npm cache probing
before the reviewed package manager is active, duplicates stale Python metadata
in `setup.py`, and publishes without a GitHub artifact attestation. Two later
committed repairs tighten executable capability inference and deterministic
Windows output decoding, but have no durable independent integration receipt.

## Bounded scope

- Preserve and independently re-review the two committed security repairs.
- Require maintained Node 22–26 and Python 3.11–3.14 runtime families.
- Make npm, TypeScript, and the Python build backend exact, fail-closed inputs.
- Replace duplicate `setup.py` metadata with the declarative compatibility shim.
- Add executable release/workflow contracts and pinned workflow self-audit.
- Build and clean-install one npm/wheel/sdist bundle, then attest it before
  either trusted-publishing job.
- Preserve public runtime APIs, zero runtime dependencies, package identities,
  and provider/registry gates.

## Acceptance

- Exact npm install, TypeScript build, all Node tests, audits, release verifier,
  and clean packed-consumer smoke pass.
- Python source tests on available supported interpreters plus wheel/sdist,
  Twine, clean install, installed-package tests, import, and CLI smoke.
- Bandit, pip-audit, actionlint, and Zizmor pass at the declared thresholds.
- An independent reviewer accepts the full exact chain from PR head to final
  candidate before push.
- The existing PR remains draft until exact-head hosted CI/CodeQL and registry
  Trusted Publisher bindings are independently proven.
- No merge, tag, publication, provider/account mutation, deployment, customer,
  or revenue outcome is claimed.
