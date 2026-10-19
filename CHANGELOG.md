# Changelog

## 2.5.0 candidate, 2026-10-18

- Reject malformed UTF-8 and unsupported JSON values during canonicalization.
- Require exact bundle versions, complete v3 claims and actual Ed25519 keys. Verify the original bundle before countersigning, and enforce caller-supplied scope and signer policies.
- Separate timestamp integrity from certificate-chain trust. Check ESS binding, EKU, KeyUsage and token time. Bound file, sidecar, timestamp, HTTP and MCP inputs.
- Label keyless checks as hash-only. Add a verify command with failure exit codes. Refuse destructive moves and attested moves that require explicit resealing.
- Validate Merkle proof identity and tree geometry, and reject vault symlink traversal.
- Exclude public MCP signing tools, hooks, stale document seals and private integration packages. Add CI, release declarations and audit documentation. Remove unsupported public claims.

Version 2.0 introduced structured signatures that bind scope, signer and artifact hash. Earlier versions are not claimed to satisfy the current verification profile.
