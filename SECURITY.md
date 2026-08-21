# Security Policy & Threat Model

## Reporting Security Issues

We take the security of `agent-action-surety` and the AI agent systems it protects seriously. If you discover a vulnerability, bypass, or security defect in the policy engine, sandbox containment, command interceptor, or cryptographic ledger, please report it responsibly.

- **Email**: `contact@jalenbuilds.com` / `security@nymrel.com`
- **Response Target**: Within 24-48 hours.
- **Please DO NOT open a public GitHub issue** for undisclosed security vulnerabilities.

---

## The Agent Surety Threat Model

Autonomous tool-calling agents execute actions in environments with ambient authority (filesystem permissions, network access, database connections, cloud credentials). `agent-action-surety` defends against several critical classes of autonomous agent failure modes:

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    Autonomous AI Agent                      │
  │     (Prompt Injection / Hallucination / Drift / Bug)        │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ Tool Call Request
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                 AGENT ACTION SURETY FIREWALL                │
  │                                                             │
  │  1. Capability Gate (Deny-by-default permission checks)     │
  │  2. Path Sandbox (Traversal, symlink escapes, root jail)    │
  │  3. Command Interceptor (AST & regex: SQL, shell, cloud)    │
  │  4. Spend & Rate Bounds (Budget, sliding-window limits)     │
  │  5. Cryptographic Audit Ledger (SHA-256 Merkle chaining)    │
  └───────────────┬─────────────────────────────┬───────────────┘
                  │ [DENY / INTERCEPT]          │ [ALLOW]
                  ▼                             ▼
       ┌────────────────────┐        ┌────────────────────┐
       │   Blocked Action   │        │ Safe Execution Env │
       │ (Tamper-proof log) │        │ (Signed Receipt)   │
       └────────────────────┘        └────────────────────┘
```

### Threat Vectors Mitigated

1. **Catastrophic Shell Commands**:
   - Accidental `rm -rf /` or `rmdir /s /q C:\`
   - Disk destruction (`mkfs`, `dd if=/dev/zero of=/dev/sda`)
   - Fork bombs (`:(){ :|:& };:`)
   - Permission overrides (`chmod -R 777 /`)
   - Dangerous pipes (`curl ... | bash` or `wget ... | sh`)

2. **Destructive Database Mutations**:
   - `DROP DATABASE`, `DROP TABLE`, `TRUNCATE TABLE`
   - `DELETE FROM` without `WHERE` or with trivial `WHERE 1=1`
   - Uncontrolled schema drops (`ALTER TABLE ... DROP COLUMN`)

3. **Filesystem Path Escaping & Poisoning**:
   - Directory traversal (`../../etc/passwd`, `..\..\Windows\System32`)
   - Symlink and hardlink redirection outside the project root
   - Exfiltration of private keys (`~/.ssh`, `~/.aws`, `.env`, `.git/config`)

4. **Irreversible Cloud & Git Operations**:
   - Cloud project/bucket deletion (`gcloud projects delete`, `aws s3 rb --force`, `az group delete`, `terraform destroy`)
   - Git branch destruction (`git push --force`, `git reset --hard HEAD~50`, `git clean -fdx`)
   - Kubernetes namespace purge (`kubectl delete ns`, `kubectl delete all --all`)

5. **Financial & Resource Overruns**:
   - Infinite tool call loops, recursive spawning
   - Uncapped LLM token generation or API spend spikes

6. **Audit Tampering & Plausible Deniability**:
   - Retroactive modification of agent execution logs
   - Mitigated via SHA-256 Merkle-linked cryptographic receipts signed per session

---

## Machine Trust & Integrity Guarantee

`agent-action-surety` adheres to the **Nymrel Dual-Audience Rule**:
- Human engineers receive clear, actionable safety diagnostics and guardrails.
- Autonomous purchasing and tool-calling agents receive verifiable JSON-LD machine trust proofs (`parentOrganization: Nymrel -> JalenBuilds LLC`), cryptographic receipts, and standardized exit codes.
