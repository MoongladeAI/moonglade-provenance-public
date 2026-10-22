# Attestation Bundle v3 (Extended): Generic Claims, Dual-Hash Binding & Multi-Party Countersigning

**Status:** Implemented in `@moonglade/provenance` v2.5.0+ / v3-Extended Engine  
**Author:** Marc Ottley (Moonglade AI)  
**Supersedes:** Bundle v2 Specification (`SPEC.md`)  

---

## 1. Motivation & Design Intent

Attestation Bundle v2 solved field binding and domain separation for local-first document attestation:
```text
moonglade-provenance/v2\n
scope:<scope>\n
sha256:<sha256 of canonical bytes>\n
signer:<identity>\n
```

While v2 securely bound the document's content hash to its repository scope and signer, real-world systems require attaching **rich, structured domain metadata** that must also be tamper-evident:
- **Photography & Generative Media:** EXIF camera telemetry, focal length, color space, creator royalty splits, and Creative Commons / commercial licensing terms.
- **Enterprise PDF & Legal Documents:** Contract identifiers, governing jurisdictions, classification levels, and counterparty entities.
- **Forensic Science & Chain of Custody:** Evidence acquisition timestamps, laboratory operator IDs, case numbers, and forensic instrument serial numbers.
- **Agentic AI Governance:** Model version, generation prompt hash, hallucination audit logs, and parent artifact DAG pointers.

Attestation Bundle v3 introduces **Generic Signed Claims** with **Dual-Hash Cryptographic Preimage Binding** and **Multi-Party Countersigning**, preserving 100% backward compatibility with v2 bundles.

---

## 2. Generic Claims Architecture

### 2.1 Arbitrary Datatype Support
Claims are not restricted to predefined strings. Any valid JSON data structure can be used as a claim key or value:
- **Primitive types:** Strings, numbers (safe integers only; carry a decimal as a string or a scaled integer), booleans, null.
- **Structured types:** Arrays, nested objects, associative lookup tables.

### 2.2 Deterministic Canonicalization (RFC 8785 JCS)
To ensure that claims serialize identically across different programming languages and runtimes (Node.js, Python, Rust, Go, browser extensions):
1. **Object Key Sorting:** All object keys are sorted lexicographically by UTF-16 code units.
2. **Whitespace Stripping:** No whitespace is permitted between keys, colons, commas, or values.
3. **Number Formatting:** Numbers MUST be IEEE 754 integers within -(2^53-1) to 2^53-1, judged by value (draft -03 section 3.3): `1.0` and `1e2` are accepted and written `1` and `100`, `-0` is written `0`. Non-integral numbers (such as `1.5`), values beyond the safe range, `NaN` and `Infinity` are rejected by the TypeScript, Python and Rust engines alike.
4. **String Escaping:** Characters below `0x20` are escaped using standard escape sequences (`\\n`, `\\r`, `\\t`) or `\\u00xx`.
5. **Undefined Exclusion:** Undefined object properties are omitted from serialization.

Formally:
$$\\text{ClaimsHash} = \\text{SHA-256}(\\text{JCS}(\\text{claims}))$$

---

## 3. The 5-Line Signing Preimage Framing

### 3.1 Framing Specification
The digital signature covers an unambiguous, newline-delimited framing payload that binds both the artifact bytes and the claims:

```text
moonglade-provenance/v3\n
scope:<scope-uri>\n
target-sha256:<64-hex of canonical artifact bytes>\n
signer:<signer-identity>\n
claims-sha256:<64-hex of JCS canonical claims map>\n
```

### 3.2 ABNF Definition

```abnf
V3-Payload      = "moonglade-provenance/v3" LF
                  "scope:" Scope-URI LF
                  "target-sha256:" 64HEXDIG LF
                  "signer:" Identity-String LF
                  "claims-sha256:" 64HEXDIG LF

Scope-URI       = 1*(ALPHA / DIGIT / "-" / "_" / "." / "/" / ":")
Identity-String = 1*(VCHAR)
64HEXDIG        = 64HEXDIG
LF              = %x0A
```

### 3.3 Security Invariants
1. **Domain Separation:** The header `"moonglade-provenance/v3\n"` guarantees that v3 signatures cannot be replayed or downgraded to v2 or v1 formats.
2. **Dual-Hash Binding:** The signature cryptographically binds the canonical artifact bytes (`target-sha256`) and the claims payload (`claims-sha256`) into a single atomic assertion. Tampering with either the artifact OR the claims invalidates the signature.
3. **Control Character Rejection:** Control characters (`0x00` through `0x1F` and `0x7F`) in any field abort signing immediately, preventing delimiter injection attacks.

---

## 4. Sidecar Schema (v3)

```json
{
  "standard": "Moonglade Provenance Attestation Bundle v3",
  "artifact": "bathsheba_twilight_raw.jpg",
  "claims": {
    "photographer": "Marc Ottley",
    "focal_length_mm": 85,
    "camera_make": "Sony",
    "camera_model": "ILCE-7RM5",
    "iso": 100,
    "aperture": "1.8",
    "shutter_speed": "1/250",
    "license": "CC-BY-NC-ND-4.0",
    "royalty_split": {
      "photographer_pct": 70,
      "gallery_fund_pct": 30
    },
    "tags": ["bathsheba", "east-coast", "golden-hour", "raw"]
  },
  "claims_sha256": "3c89b27e8d1a49f5...",
  "attestations": [
    {
      "method": "moonglade-ed25519-v3",
      "signer": "marc.ottley@moongladeai.net",
      "scope": "moonglade:vault:gallery/bathsheba_twilight_raw.jpg",
      "target_sha256": "9f83a2...",
      "claims_sha256": "3c89b27e8d1a49f5...",
      "created": "2026-09-14T14:35:00Z",
      "git_commit": "c4d2e1f",
      "signature": "base64-ed25519-sig..."
    },
    {
      "method": "moonglade-ed25519-v3",
      "signer": "gallery.curator@moongladeai.net",
      "scope": "moonglade:vault:gallery/bathsheba_twilight_raw.jpg",
      "target_sha256": "9f83a2...",
      "claims_sha256": "3c89b27e8d1a49f5...",
      "created": "2026-09-14T14:40:00Z",
      "git_commit": "c4d2e1f",
      "signature": "base64-ed25519-countersig..."
    },
    {
      "method": "rfc3161",
      "tier": "L1_CRYPTO_PRIMARY",
      "tsa": "https://freetsa.org/tsr",
      "tsa_time": "2026-09-14T14:35:03Z",
      "token_b64": "MIIB..."
    }
  ],
  "sha256_at_last_write": "9f83a2...",
  "updated": "2026-09-14T14:40:00Z",
  "status": "canonical"
}
```

---

## 5. Multi-Party Countersigning Protocol

In distributed workflows (e.g. Creator to Publisher, Laboratory Analyst to Quality Inspector):
1. **Primary Seal:** The creator seals the artifact with their private key, attaching the canonical claims.
2. **Review & Countersign:**
   - The countersigner reads `<artifact>.provenance.json`.
   - The engine validates that `target_sha256` matches the artifact bytes and `claims_sha256` matches the JCS-canonicalized claims.
   - The countersigner executes `countersignDocument()`:
     $$\\text{Sig}_{\\text{counter}} = \\text{Sign}_{K_{\\text{counter}}}(\\text{V3-Payload})$$
   - Appends the countersignature to `attestations`.
3. **Independent Keyring Verification:**
   - Recipients pass a keyring mapping signer identities to public keys:
     ```typescript
     const keyring = {
       "marc.ottley@moongladeai.net": marcPublicKeyPem,
       "gallery.curator@moongladeai.net": galleryPublicKeyPem
     };
     const result = await ProvenanceEngine.verifyDocument(path, keyring);
     ```
   - Every signature in the bundle must verify against its corresponding key. If any key is missing or forged, the verification fails closed.

---

## 6. Threat Model & Verification Guarantees

| Attack Vector | Detection Mechanism | Result |
| :--- | :--- | :--- |
| **Artifact Byte Mutation** | Target hash mismatch | `Hash mismatch: Document has been mutated` |
| **Claims Value Tampering** | Recomputed JCS hash mismatch | `Claims hash mismatch: claims payload has been mutated` |
| **Claims Substitution** | Preimage `claims-sha256` mismatch | `Signature validation failed` |
| **Scope Smuggling** | Strict POSIX relative URI binding | `Attestation records a different hash / scope mismatch` |
| **Signature Downgrade** | Version header framing (`moonglade-provenance/v3`) | Legacy v1/v2 parsers fail closed on version string |
| **Forged Countersignature** | Keyring verification fails on invalid signature | `Signature validation failed for signer` |
| **Timestamp Forgery** | RFC 3161 X.509 cert chain and ASN.1 message imprint | `Timestamp token verification failed` |\n