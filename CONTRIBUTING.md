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

### TypeScript
```bash
# Typecheck
npm run lint

# Run Node.js unit tests
npm test
```

### Python
```bash
# Run Python unit tests
python -m unittest discover -s tests/python -p "test_*.py"
```

---

## Submitting Pull Requests

1. Fork the repository and create a feature branch (`git checkout -b feature/awesome-interceptor`).
2. Write unit tests covering both safe and malicious input variations.
3. Ensure all tests in both TypeScript and Python pass with 100% green exit codes.
4. Submit a PR describing the security threat vector addressed and the verification proof.
