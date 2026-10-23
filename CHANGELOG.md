# Changelog

## 2.6.0 candidate, 2026-10-22

- **Draft -03 Alignment**: Enforce strict IEEE 754 safe integer value normalization on claims JSON (`draft-ottley-agentic-epistemic-provenance-03` §3.3). Preserve exact raw byte fidelity for known binary formats including `.onnx`.
- **L3 DTA Byzantine Consensus Hardening**: Upgraded Degrading Timestamp Architecture (DTA) L3 network probing with simultaneous multi-tier fanout, mandatory quorum threshold ($\ge 3$ probes), and 3,000 ms max-drift window with median time selection. Added fair queue rotation and exponential backoff circuit breaking.
- **Zero-Dependency Native Test Harness**: Replaced Jest with Node.js 22/24 native `node:test` and `node:assert/strict` test harness (`test-harness.cjs`).
- **Dev-Dependency Reduction**: Purged 314 Jest, Babel, Istanbul, and transitive CLI packages from the public repository lockfile, leaving an audited 13-package footprint with zero vulnerabilities.
- **Test Matrix Parity**: 375/375 unit tests and 6/6 condition self-test suites passing under the native Node runner.

## 2.5.0 candidate, 2026-10-18

- Reject malformed UTF-8 and unsupported JSON values during canonicalization.
- Require exact bundle versions, complete v3 claims and actual Ed25519 keys. Verify the original bundle before countersigning, and enforce caller-supplied scope and signer policies.
- Separate timestamp integrity from certificate-chain trust. Check ESS binding, EKU, KeyUsage and token time. Bound file, sidecar, timestamp, HTTP and MCP inputs.
- Label keyless checks as hash-only. Add a verify command with failure exit codes. Refuse destructive moves and attested moves that require explicit resealing.
- Validate Merkle proof identity and tree geometry, and reject vault symlink traversal.
- Exclude public MCP signing tools, hooks, stale document seals and private integration packages. Add CI, release declarations and audit documentation. Remove unsupported public claims.

Version 2.0 introduced structured signatures that bind scope, signer and artifact hash. Earlier versions are not claimed to satisfy the current verification profile.
