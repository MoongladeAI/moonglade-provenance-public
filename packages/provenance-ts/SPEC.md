# Implemented profile: 2.5.0

This is a personal implementation specification, not an IETF standard or submitted Internet-Draft. Historical drafts are non-normative and excluded from this release.

## Bundle formats

Supported bundle identifiers are exactly Moonglade Provenance Attestation Bundle v2 and Moonglade Provenance Attestation Bundle v3. V2 attestation method is moonglade-ed25519-v2; v3 uses moonglade-ed25519-v3. Format and method must agree. Every supported signature must verify. Unknown methods return INDETERMINATE with verified:false. Missing signatures, malformed schemas, unsupported formats, invalid keys, revoked local sidecars and policy failures fail closed.

Artifact basename, recorded digest and bounded attestation array are required. V3 additionally requires a plain claims object and its SHA-256 over strict canonical JSON. Keys sort by UTF-16 code units. Non-finite numbers, lone surrogates, unsupported values, accessors, cycles and sparse arrays are rejected. All v3 signatures bind the recomputed claims digest. Ed25519 key type is checked independently of labels.

V2 signing payload is UTF-8 lines: moonglade-provenance/v2, scope:<scope>, sha256:<digest>, signer:<identity>, followed by a final LF. V3 replaces the version with moonglade-provenance/v3 and uses scope, target-sha256, signer and claims-sha256 lines. Payload fields are nonempty and contain no control characters. SHA-256 digests are lowercase hex. Sidecar metadata outside these fields is not authenticated by the document signature.

## Canonicalization

Text follows strict UTF-8, one leading BOM removal, CRLF-to-LF and NFC, preserving bare CR. Known binary extensions preserve bytes. Unknown extensions sample the first 1024 bytes for NUL: NUL means binary; otherwise strict text. Cross-language golden vectors ship in src/canonical.golden.json. File reads are bounded and reject symlinks. Do not use these APIs against a concurrently hostile filesystem writer.

## Verification policy

`VerificationPolicy.expectedScope` must match every signature. `requiredSigners` must each be present and verified. The library default scope root is the containing directory unless a root is supplied; CLI uses the current directory or MOONGLADE_ROOT. Explicit roots reject outside-root paths. Countersigning requires verificationKeys and validates the original bundle, claims, signatures and supplied policy before writing. It keeps the original signed scope. Verification failures leave the bundle unchanged.

## Result fields

Results report aggregate `verified`, `documentSignatureVerified`, `timestampStatus` and `timestampVerified` separately. `timestampVerified` means an anchored timestamp was verified; a host-clock observation cannot satisfy it. Invalid timestamp evidence keeps aggregate verified:false while retaining successful document signature verification. See TIMESTAMP.md for timestamp trust constraints.

## Merkle proofs

Merkle trees use SHA-256 domain prefixes 0x00 for leaves and 0x01 for internal nodes, sorted paths, leaf bytes '<artifact SHA256>  <path>', and promotion of odd nodes. The algorithm identifier remains merkle-sha256-rfc6962 for compatibility with existing root vectors. RFC 9162 supersedes RFC 6962. Proofs now include artifact_sha256; verification recomputes the named leaf and checks algorithm, indexes, tree size, path orientation and step count. Callers should supply both a trusted expected root and expected artifact path/digest. Without an external root the result establishes internal consistency only. Scans exclude hidden directories and node_modules, reject symlinks and hash raw file bytes. No consistency proof or append-only log guarantee is provided.

## Envelopes and self-test

Envelope validation checks data shape; envelope evidence/status strings are not cryptographic authorization. Self-test compares any shipped package-root sidecar hashes and reports that no signatures were checked. This candidate intentionally ships no document sidecars.

References: [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161), [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).
