# Testing the 2.5.0 candidate

## Run the suite

Use Node 22 or 24 on Windows or Linux. From the repository root:

```sh
npm ci
npm test
npm run self-test
```

The test command removes `dist`, rebuilds the package and runs Jest against that output. Finding zero tests is a failure. The manifests and lockfile pin Jest 30.5.2, TypeScript 5.9.3, @types/jest 30.0.0 and @types/node 22.20.4.

The main-branch snapshot contains **230 tests in 11 suites**. The final documentation pass reran all 230 on Windows with Node 24.16.0, with no failures, skips or pending tests. Earlier candidate audits also exercised Node 22 and 24 on Windows and Linux. Their results apply to the audited snapshots; this document does not substitute them for a fresh CI run on a later commit.

The separate recovery snapshot has four additional shared-vector cases. Its 234-test count does not describe this main-branch snapshot.

## Suites

All suites are under `packages/provenance-ts/src`.

| Suite | Coverage |
|---|---|
| `index.test.js` | Canonical bytes, signing, mutation, bundle versions, claims, scope and countersigning |
| `binding.test.js` | Signed payload fields, replay, incomplete bundles and unverifiable attestations |
| `merkle.test.js` | Golden roots, odd-node promotion, inclusion proofs and vault scans |
| `timestamp.test.js` | DER helpers, response structure, acquisition failures, endpoint scheduling and synthetic tokens |
| `mcp.test.js` | The three read-only tools, keyless output, blocked gates and scope policy |
| `artifactHook.test.js` | Observation, provisional sealing, exclusions and refusal of attested moves |
| `artifactEnvelope.test.js` | Envelope schema and artifact identity helpers |
| `badge.test.js` | Badge formatting and filesystem status |
| `self-test.test.js` | The six built-in self-test conditions |
| `release-security.test.js` | Malformed UTF-8/JSON, claims stripping, versions, signer policies, scope replay, key algorithms, countersigning refusal, forged badges, CLI exits, move collisions/rollback, proof substitution, junction escape and stdio MCP |
| `timestamp-security.test.js` | CA trust, self-signed integrity-only tokens, ESS/EKU/KeyUsage, expiration, wrong anchors/imprints, time binding, response limits and deadlines |

## Fixtures and prerequisites

Tests use ephemeral synthetic Ed25519/RSA keys, local HTTP servers, temporary files and filesystem links. They need no production key, keyring or private corpus. The default suite does not call live timestamp services.

Some Windows application sandboxes block loopback connections, junctions or hard links. Use a local account allowed to create those fixtures. Do not suppress a blocked test and report the suite as passing.

The built-in self-test checks any package-root sidecar hashes and states that it has not verified package signatures. This candidate intentionally ships no document sidecars.

## Limits

The default tests do not establish live public TSA availability, certificate revocation status, macOS behavior or safety against a concurrent hostile filesystem writer. OpenPGP/SSHSIG verification is unsupported. The legacy library OpenPGP signing helper and real GPG/SSH signing are not covered by this suite. Default hooks, platform keystores and sibling packages are excluded from this release.

Production audit checks also covered clean installation, a runtime-only package consumer, CLI binaries, repeatable clean builds, package contents, local documentation links, disclosure and secret scans, runtime licenses and dependency vulnerabilities. These results describe the tested artifact; any later package change needs its own verification.
