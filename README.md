# 🛡️ Agent Action Surety (`agent-action-surety`)

> **Zero-Dependency Execution Firewall, Path Sandbox, Command Interceptor, and Cryptographic Audit Ledger for AI Coding Agents and Autonomous Tool-Calling Swarms.**

[![CI](https://github.com/nymrel/agent-action-surety/actions/workflows/ci.yml/badge.svg)](https://github.com/nymrel/agent-action-surety/actions)
[![Node.js](https://img.shields.io/badge/Node.js-22%20%7C%2024%20%7C%2026-339933?logo=node.js)](https://nodejs.org)
[![Python](https://img.shields.io/badge/Python-3.11--3.14-3776AB?logo=python)](https://python.org)
[![Registry status](https://img.shields.io/badge/Registries-Unpublished-8A6D3B)](#quickstart)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Entity: Nymrel](https://img.shields.io/badge/Entity-Nymrel%20%7C%20JalenBuilds%20LLC-2A332E)](https://nymrel.com)

---

## 🌟 Overview

Autonomous AI agents (such as Codex, Claude, Cursor, Devin, OpenDevin, and custom LLM tool-calling loops) operate in developer and cloud environments with dangerous **ambient authority**. A single hallucination, prompt injection, or logic drift can result in catastrophic `rm -rf /`, database drops (`DROP TABLE`), accidental `git push --force origin main`, or cloud resource deletion (`gcloud projects delete`).

**`agent-action-surety`** provides a complete, dual-language (**TypeScript/Node.js** + **Python**), **zero-runtime-dependency** execution firewall and policy envelope that wraps every agent tool call before execution, enforces strict containment, and logs tamper-evident cryptographic receipts.

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    Autonomous AI Agent                      │
  │     (Codex / Claude / Cursor / OpenDevin / Custom Swarm)    │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ Tool Call Request
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                 AGENT ACTION SURETY FIREWALL                │
  │                                                             │
  │  [1] Capability Gate      : Deny-by-default capability map  │
  │  [2] Path Sandbox         : Traversal & symlink isolation   │
  │  [3] Command Interceptor  : SQL, Shell, Git, Cloud AST/Regx │
  │  [4] Resource Envelope    : Spend caps ($ USD) & rate limits│
  │  [5] Cryptographic Ledger : SHA-256 Merkle chain receipts   │
  └───────────────┬─────────────────────────────┬───────────────┘
                  │ [DENY / INTERCEPT]          │ [ALLOW]
                  ▼                             ▼
       ┌────────────────────┐        ┌────────────────────┐
       │   Blocked Action   │        │ Safe Execution Env │
       │ (Tamper-proof log) │        │ (Signed Receipt)   │
       └────────────────────┘        └────────────────────┘
```

---

## 💎 Core Architecture & Guarantees

### 1. 📦 Zero Runtime Dependencies
- **TypeScript / Node.js Engine**: Uses **100% standard library** (`node:crypto`, `node:fs`, `node:path`, `node:child_process`, `node:readline`). No npm supply chain risk.
- **Python Engine**: Uses **100% standard library** (`hashlib`, `hmac`, `os`, `sys`, `pathlib`, `re`, `subprocess`, `dataclasses`, `secrets`). No pip runtime dependency exposure.

### 2. 🔒 Deny-by-Default Capability System
Actions are rejected unless explicit capabilities are granted:
- `fs:read`, `fs:write`, `fs:delete`, `fs:*`
- `exec:read_only`, `exec:modify`, `exec:privileged`
- `db:query`, `db:schema_migrate`, `db:destructive`
- `git:read`, `git:commit`, `git:push`, `git:force_push`
- `cloud:read`, `cloud:provision`, `cloud:delete`
- `net:http`, `net:dns`, `net:raw`

### 3. 📁 Path Containment Sandbox
- Strict workspace root bounding.
- Defeats directory traversal (`../../etc/passwd`, `..\..\Windows\System32`, `%2e%2e%2f`).
- Resolves real paths (`realpath`) to prevent symlink and hardlink escapes.
- Enforces read-only root partitions vs writeable directories.
- Default sensitive pattern protection: `.env`, `.git/config`, `.ssh/`, `.aws/`, `.gnupg/`, `/etc/shadow`.

### 4. ⚡ Deep Command & SQL Interceptors
Inspects commands via token and pattern analysis:
- **Shell / OS**: Blocks `rm -rf /`, `rm -rf *`, `rmdir /s /q C:\`, `mkfs.*`, `dd if=/dev/zero of=/dev/sda`, fork bombs (`:(){ :|:& };:`), global `chmod -R 777 /`, remote execution pipes (`curl ... | bash`).
- **SQL Databases**: Blocks `DROP DATABASE`, `DROP TABLE`, `TRUNCATE TABLE`, `ALTER TABLE ... DROP COLUMN`, unbounded `DELETE FROM ...` without `WHERE` or with `WHERE 1=1`.
- **Git Repositories**: Blocks `git push --force`, `git push -f`, `git reset --hard`, `git clean -fdx`, and deletion of protected branches (`main`, `master`, `prod`, `release`).
- **Cloud Infrastructure**: Blocks `gcloud projects delete`, `gsutil rm -r gs://*`, `aws s3 rb --force`, `aws rds delete-db-instance`, `az group delete`, `terraform destroy`, `pulumi destroy`.
- **Kubernetes**: Blocks `kubectl delete ns`, `kubectl delete all --all`, `kubectl delete clusterrole`.

### 5. 💰 Financial Spend Caps & Rate Limiting
- **Spend Ceiling**: Enforces maximum allowable cost in USD per agent run.
- **Token Bounds**: Restricts cumulative LLM token requests.
- **Rate Limiting**: Sliding 60-second window protecting against recursive loops.

### 6. ⛓️ Cryptographic Audit Ledger (Merkle Hash Chaining)
Every action evaluation produces a tamper-evident **SHA-256 Execution Receipt** chained cryptographically:

```
  ┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
  │    Receipt #1    │       │    Receipt #2    │       │    Receipt #3    │
  │                  │       │                  │       │                  │
  │ prev: 0000000... ├──────►│ prev: HASH(#1)   ├──────►│ prev: HASH(#2)   │
  │ hash: 8f4a19b... │       │ hash: c3d881e... │       │ hash: 1e99a4c... │
  │ HMAC Signature   │       │ HMAC Signature   │       │ HMAC Signature   │
  └──────────────────┘       └──────────────────┘       └──────────────────┘
```

Any retrospective tampering with command logs, action statuses, or timestamps is immediately detected during audit verification.

---

## 🚀 Quickstart

> [!IMPORTANT]
> As of 2026-08-30, neither registry package has been published. The npm and
> PyPI install commands below are reserved for the first trusted release and
> will fail until the registry owners finish provider-side provisioning.

### Install from source today

The checked-in `.node-version` selects Node.js 24, where Corepack is bundled.
Node.js 22 works the same way. Node.js 26 is supported but no longer bundles
Corepack; from outside the checkout, first run
`npm install --global npm@12.0.2 --ignore-scripts --no-audit --no-fund`.

```bash
git clone https://github.com/nymrel/agent-action-surety.git
cd agent-action-surety

# Default Node.js 24 path. Node.js 26 uses the external bootstrap above.
corepack enable npm
npm --version # must print 12.0.2
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run audit
npm run audit:prod
npm pack --ignore-scripts

# Python source install and tests.
python -m pip install --disable-pip-version-check --no-deps .
python -m unittest discover -s tests/python -p "test_*.py"
```

Pin the checkout to a reviewed commit before production or automated adoption.

### Node.js / TypeScript API

After the first trusted npm release:

```bash
npm install @nymrel/agent-surety
```

```typescript
import { PolicyEngine, wrapExecution } from '@nymrel/agent-surety';

// 1. Configure Safety Envelope
const engine = new PolicyEngine({
  capabilities: ['fs:read', 'fs:write', 'exec:read_only'],
  allowedPaths: ['./src', './dist'],
  maxSpendUsd: 5.0,
  rateLimitPerMinute: 60,
  hmacSecret: process.env.SURETY_SECRET_KEY,
});

// 2. Wrap Agent Execution
const result = await wrapExecution(engine, {
  actionType: 'exec',
  command: 'rm -rf /', // Intercepted and blocked before execution!
  workingDir: process.cwd(),
});

if (!result.success) {
  console.error('Firewall Blocked Action:', result.error);
  console.log('Cryptographic Receipt Hash:', result.receipt.receiptHash);
}
```

### Python API

After the first trusted PyPI release:

```bash
pip install agent-action-surety
```

```python
from agent_action_surety import PolicyEngine, wrap_execution, ActionEnvelope

# 1. Configure Safety Envelope
engine = PolicyEngine(
    capabilities=["fs:read", "fs:write", "exec:read_only"],
    allowed_paths=["./src", "./dist"],
    max_spend_usd=5.0,
    rate_limit_per_minute=60,
    hmac_secret="org_session_secret_key",
)

# 2. Wrap Agent Execution
envelope = ActionEnvelope(
    action_type="exec",
    command="git push --force origin main",  # Intercepted and blocked!
    working_dir=".",
)

result = wrap_execution(engine, envelope)

if not result.success:
    print("Action Blocked:", result.error)
    print("Receipt ID:", result.receipt.receipt_id)
    print("Merkle Hash:", result.receipt.receipt_hash)
```

---

## 🛠️ CLI Tool Usage

`agent-surety` provides a CLI wrapper for agent subshells and CI workflows:

```bash
# 1. Check a command before running (Dry-run)
agent-surety check --cmd "rm -rf /"
# Output: [SURETY FIREWALL: EXECUTION BLOCKED]
# Reason: Root or Wildcard Recursive Deletion (CRITICAL)

# 2. Execute command inside the safety envelope
agent-surety exec --cmd "node --version"
# Output: [SURETY: SUCCESS] (Receipt: a3b819f... | Time: 12ms)

# 3. Validate filesystem path against sandbox containment
agent-surety path --target "../../etc/shadow" --write
# Output: [SURETY PATH VALIDATION] Allowed: NO (RESTRICTED)

# 4. Cryptographically verify receipt integrity
agent-surety verify-receipt --file receipt.json --secret "my-hmac-key"

# 5. Verify an entire audit ledger Merkle chain
agent-surety verify-ledger --file audit_ledger.jsonl --secret "my-hmac-key"
```

### Default execution contract

The built-in Node and Python executors never pass the command string to an OS
shell. They first convert it to one executable plus an argument vector, record a
`DENY` receipt if parsing fails, and then use `execFile` (Node) or
`subprocess.run(..., shell=False)` (Python). A command such as
`echo safe && mutate` therefore targets only `echo` as the executable; `&&` and
the remaining text are literal arguments and never launch `mutate`.

The portable parser has the same contract in both runtimes:

- commands are limited to 32,768 Unicode characters;
- ASCII whitespace separates arguments;
- single and double quotes group arguments and are removed;
- inside double quotes, `\"` and `\\` escape a quote or backslash;
- backslashes outside double quotes stay literal, including Windows paths;
- empty quoted arguments are preserved; and
- malformed quotes, empty executables, NUL bytes, and other control characters
  fail closed before policy evaluation or custom execution.

Shell operators, redirection, glob expansion, and command substitution are not
interpreted by the default executor. Explicitly running a shell executable (for
example, `sh -c` or `cmd.exe /c`) or supplying a custom executor opts back into
that executor's semantics and should be protected by a correspondingly strict
policy. Surety remains an application safety gate, not a replacement for
least-privilege OS credentials, process isolation, or containers.

`exec:read_only` is deliberately conservative about tools that can launch
helpers. Ripgrep is eligible only when `--no-config` is its first argument and
the command excludes preprocessing, compressed-search, and hostname-helper
modes. Git commands require `exec:modify` in addition to the applicable Git
capability because aliases, external diff/textconv programs, fsmonitor hooks,
and pagers can execute code even when a subcommand is named `status`, `log`, or
`diff`. Commands containing shell composition or substitution syntax also
require `exec:modify`, even when their first executable is normally read-only.
Runtime launchers such as npm and Python are not treated as read-only version
checks because environment-driven startup hooks can execute code. `hostname`
is read-only only without arguments because Unix accepts a mutating name
argument.

---

## 🏛️ Nymrel Machine Trust & Entity Graph

In accordance with the **Nymrel Dual-Audience Rule**, `agent-action-surety` is engineered to deliver intuitive developer ergonomics for human engineers alongside verified machine trust for autonomous agents.

```json
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "agent-action-surety",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "All",
  "author": {
    "@type": "Organization",
    "name": "Nymrel",
    "parentOrganization": {
      "@type": "Organization",
      "name": "JalenBuilds LLC",
      "url": "https://nymrel.com",
      "contactPoint": {
        "@type": "ContactPoint",
        "email": "contact@nymrel.com"
      }
    }
  },
  "license": "https://opensource.org/licenses/MIT",
  "keywords": ["AI Agent Firewall", "Tool-Calling Security", "Execution Sandbox", "Cryptographic Ledger", "Nymrel"]
}
```

---

## 🧪 Testing & Verification

Run the comprehensive test suites across both Node.js and Python:

```bash
# TypeScript / Node.js Test Suite (Native node:test runner)
npm --version # must print 12.0.2; use the source bootstrap above
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run audit
npm run audit:prod

# Python Test Suite (Native unittest runner)
PYTHONPATH=python python -m unittest discover -s tests/python -p "test_*.py"
```

The compatibility contract covers maintained Node.js 22, 24, and 26 plus
Python 3.11 through 3.14 on pinned Linux and Windows runners. Exact-head hosted
evidence remains a separate release gate. The package has no runtime
dependencies in either ecosystem.

---

## 📄 License

MIT License &copy; 2026 **Nymrel / JalenBuilds LLC**. See [LICENSE](LICENSE) for details.
