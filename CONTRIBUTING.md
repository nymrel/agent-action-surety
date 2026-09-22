# Contributing to Agent Action Surety

Thank you for your interest in contributing to `agent-action-surety`!

`agent-action-surety` is the zero-dependency, dual-language execution firewall and policy envelope developed under Nymrel / JalenBuilds LLC.

---

## Core Guarantees

1. **Zero Runtime Dependencies**:
   - The TypeScript/Node package MUST NOT introduce runtime dependencies from npm (`dependencies` in `package.json` must remain empty). All logic must use the Node.js standard library (`node:crypto`, `node:fs`, `node:path`, `node:child_process`, etc.).
   - The Python package MUST NOT introduce runtime dependencies from PyPI (`install_requires` must remain empty). All logic must use the Python standard library (`hashlib`, `hmac`, `os`, `sys`, `pathlib`, `re`, `shlex`, `subprocess`, etc.).
2. **Dual-Language Parity**:
   - Every feature added to the TypeScript engine must have an exact behavioral and cryptographic equivalent in the Python engine, and vice-versa.
   - Hash receipts and tamper-evident signatures produced by Python must be verifiable by TypeScript, and vice-versa.
3. **Cross-Platform Robustness**:
   - Must execute cleanly on Windows (PowerShell/CMD path delimiters, case-insensitivity) and POSIX (Linux, macOS).

---

## Development Workflow

### TypeScript / Node.js

The repository defaults to Node.js 24. Node.js 22 and 24 use the bundled
Corepack activation below. Node.js 26 is supported but does not bundle
Corepack; before entering the checkout, install the reviewed CLI with
`npm install --global npm@12.0.2 --ignore-scripts --no-audit --no-fund`.

```bash
corepack enable npm
npm --version # must print 12.0.2
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run audit
npm run audit:prod
```

### Python
```bash
# Use a maintained Python 3.11 through 3.14 interpreter.
python -m unittest discover -s tests/python -p "test_*.py"
```

---

## Submitting Pull Requests

1. Fork the repository and create a feature branch (`git checkout -b feature/awesome-interceptor`).
2. Write unit tests covering both safe and malicious input variations.
3. Run the complete Node and Python gates above with green exit codes.
4. Submit a PR describing the security threat vector addressed and the verification proof.
