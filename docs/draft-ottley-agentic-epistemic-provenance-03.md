---
title: "Sovereign Cryptographic Attestation and Epistemic Provenance for Autonomous Agent Memory (SCA-EPM)"
docname: draft-ottley-agentic-epistemic-provenance-03
category: exp
consensus: false
ipr: trust200902
area: Security
date: 2026-10-22
author:
  - name: Marc Ottley
    org: Moonglade AI
    city: Boscobelle
    region: St. Andrew
    country: Barbados
    email: moongladeai@gmail.com
---

# Sovereign Cryptographic Attestation and Epistemic Provenance for Autonomous Agent Memory

```text
Internet-Draft                                                 M. Ottley
Intended status: Experimental                               Moonglade AI
Expires: April 25, 2027                                 October 22, 2026


   Sovereign Cryptographic Attestation and Epistemic Provenance for
                       Autonomous Agent Memory
                draft-ottley-agentic-epistemic-provenance-03
```

## Abstract

This document specifies the format, canonicalization algorithms, degrading timestamp procedures, and distributed ledger epoch anchoring for binding digital artifacts (source code, Markdown documents, neural weights, and multi-modal assets) to a verifiable cryptographic key possession, an atomic time attestation, and a public immutability commitment.

Revision -03 updates canonicalization to mandate fatal rejection of non-conforming UTF-8 byte sequences in text-classified artifacts, defines the Byzantine median quorum algorithm for Tier 3 network time synchronization, and specifies the public anchoring profile for committing RFC 9162 Merkle epoch roots to the XRP Ledger (XRPL).

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task Force (IETF). Note that other groups may also distribute working documents as Internet-Drafts. The list of current Internet-Drafts is at https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as "work in progress."

This document is an individual submission. It has no working group and no consensus. It is published for review and to gather implementation experience, and its intended status is Experimental.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights reserved.

---

## 1. Introduction & Terminology

Autonomous artificial intelligence agents generate code, policy documents, analytical syntheses, and operational actions without continuous synchronous human supervision. Third parties receiving these artifacts require deterministic proof that:
1. The artifact has not been modified since creation or ratification (Integrity);
2. The entity asserting authorship possesses the corresponding signing key (Authenticity);
3. The artifact existed no later than an asserted chronological epoch (Temporal Upper Bound);
4. The attestation root is publicly anchored to a neutral, tamper-evident ledger (Public Auditability).

### 1.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

### 1.2. Vocabulary

* **Artifact**: A sequence of octets representing a file or stream.
* **Canonical Bytes**: The deterministic byte sequence obtained after applying Section 2 normalization.
* **Sidecar Bundle**: A companion document (`<artifact>.provenance.json`) conveying attestations, timestamp evidence, and inclusion coordinates.
* **Directory Registry**: An aggregated manifest (`.provenance-registry.json`) indexing sidecar payloads across an asset collection.
* **Epoch Tree**: An RFC 9162 Merkle tree committing an ordered set of artifact digests.
* **Anchor Receipt**: A verifiable cryptographic attestation confirming the publication of an epoch root to an immutable public substrate.

---

## 2. Canonicalization

Prior to computing cryptographic digests, implementations MUST normalize artifacts into deterministic canonical bytes.

```text
                     +----------------------+
                     | Raw Input File Bytes |
                     +----------------------+
                                |
                   [Is Binary or Text by Ext?]
                     /                      \
            [Binary Ext / NUL]          [Text Ext]
                    |                        |
             Raw Octets (Pass)      Strict UTF-8 Decode (Fatal)
                                             |
                                    Strip Leading U+FEFF
                                             |
                                    Normalize CRLF -> LF
                                    (Bare CR PRESERVED)
                                             |
                                    Unicode NFC Normalization
                                             |
                                     UTF-8 Encode Octets
```

### 2.1. Artifact Classification

Implementations MUST classify input artifacts as either `text` or `raw_binary`:
1. **Known Binary Extensions**: Files matching known binary suffixes (e.g., `png`, `jpg`, `pdf`, `wasm`, `onnx`, `bin`, `zip`) MUST be treated as binary.
2. **Known Text Extensions**: Files matching known text suffixes (e.g., `md`, `txt`, `json`, `yaml`, `ts`, `rs`, `py`, `sql`) MUST be treated as text.
3. **Unknown Extensions**: If the extension is unrecognized, the implementation MUST inspect the first 1024 octets. If a NUL byte (`0x00`) is observed, the file MUST be treated as binary; otherwise, it MUST be treated as text.

### 2.2. Text Canonicalization Profile (canonical/v3)

For artifacts classified as text:
1. **Strict UTF-8 Decoding**: The octets MUST be decoded as UTF-8 in strict mode. If invalid or truncated byte sequences are encountered, the implementation MUST terminate processing with a fatal error. Lossy substitution (such as replacement with U+FFFD) is STRICTLY PROHIBITED.
2. **BOM Stripping**: If the decoded text commences with a single Byte Order Mark (`U+FEFF`), it MUST be removed. Secondary or embedded BOMs MUST NOT be removed.
3. **Line Ending Normalization**: Every CRLF (`0x0D 0x0A`) sequence MUST be replaced with LF (`0x0A`). A bare CR (`0x0D`) without an immediately succeeding LF MUST NOT be modified.
4. **Unicode Normalization**: Unicode Normalization Form C (`NFC`) [UAX15] MUST be applied.
5. **Encoding**: The normalized text MUST be encoded as canonical UTF-8 bytes.

### 2.3. Binary Canonicalization Profile (raw_binary)

For artifacts classified as binary, the canonical bytes MUST be the exact, unaltered raw octet stream.

---

## 3. Signing Payloads & Claims

### 3.1. Version 2 Signing Payload

The version 2 signing payload is composed of newline-delimited UTF-8 lines:

```text
moonglade-provenance/v2
scope:<scope>
sha256:<digest>
signer:<identity>
```

Each field MUST be non-empty and MUST NOT contain control characters or newlines. The `<digest>` MUST be formatted as a 64-character lowercase hexadecimal string. The payload MUST terminate with a single LF (`0x0A`).

### 3.2. Version 3 Signing Payload

The version 3 signing payload binds structured claims alongside the target artifact:

```text
moonglade-provenance/v3
scope:<scope>
target-sha256:<digest>
signer:<identity>
claims-sha256:<claims-digest>
```

Where `<claims-digest>` is the SHA-256 digest of the UTF-8 encoded canonical JSON representation of the claims object. If no claims object is specified, an empty JSON object (`{}`) MUST be canonicalized.

### 3.3. Canonical JSON for Claims

Claims objects MUST be canonicalized via a deterministic subset of RFC 8785 [RFC8785]:
1. Object member keys MUST be sorted lexicographically by UTF-16 code units.
2. Insignificant whitespace MUST NOT be emitted.
3. Numbers MUST be restricted to IEEE 754 integers within the safe range ($-2^{53}+1$ to $2^{53}-1$). The test is on the numeric value, not its spelling, because a JSON number parsed into an IEEE 754 binary64 carries no lexical form: `1.0`, `1e2` and `-0` denote the integers 1, 100 and 0, MUST be accepted, and are emitted as `1`, `100` and `0`. Any other floating-point value (such as `1.5`), `2^53` and beyond, `NaN`, and `Infinity` MUST be rejected, as MUST a number that overflows binary64 (such as `1e400`). Producers that need a decimal fraction MUST carry it as a string or as a scaled integer.
4. Lone Unicode surrogates (`U+D800` through `U+DFFF`) MUST be rejected.

---

## 4. Concurrent Degrading Timestamp Architecture (DTA)

To secure historical validity without hard dependencies on single points of failure, DTA queries concurrent temporal sources across four degrading tiers.

### 4.1. Tier Hierarchy

* **Tier 1 (Crypto Primary)**: Pinned RFC 3161 Time-Stamp Authorities (TSAs) verifying via critical-EKU and ESSCertIDv2 certificates.
* **Tier 2 (Crypto Fallback)**: Secondary or unanchored RFC 3161 TSAs providing unauthenticated timestamp tokens.
* **Tier 3 (Network Consensus)**: Byzantine-tolerant median quorum across distributed public network servers.
* **Tier 4 (Host UTC)**: Local kernel system clock (`KERNEL_UTC`), providing unauthenticated self-observation.

### 4.2. Tier 3 Byzantine Median Quorum Algorithm

When cryptographic TSAs are unavailable, Tier 3 queries a diverse pool of independent network time servers (e.g., `cloudflare.com`, `google.com`, `apple.com`, `amazon.com`) via HTTPS HEAD requests:

1. **Probe Collection**: Each server is queried for its HTTP `Date` header. The header MUST be an HTTP-date as defined by RFC 7231 section 7.1.1.1 (IMF-fixdate, or the obsolete RFC 850 and asctime forms), with a day name that agrees with the date and a date that exists. A response whose `Date` header is anything else (for example `2026-10-22`) is a failed probe.
2. **Quorum Threshold**: A minimum quorum of successful responses ($M \ge 2$, default $M = 2$, recommended $M \ge 3$) MUST be obtained. Responses are counted per distinct server: the same host listed or answering more than once is a single participant, so repeating a server cannot create a quorum. Consequently a single server can never produce Tier 3, and a result from one server is reported as Tier 4 unless the implementation is explicitly configured with $M = 1$. A Tier 3 attempt MUST therefore query at least $\min(3, \text{distinct servers available})$ servers.
3. **Drift Boundary Enforcement**: The implementation computes the absolute drift:
   $$\Delta t = |t_{\max} - t_{\min}|$$
   If $\Delta t > 3000\text{ ms}$, quorum fails, and the system MUST fall back to Tier 4.
4. **Median Selection**: The successful timestamps are sorted chronologically. The true median timestamp is selected:
   $$t_{\text{consensus}} = t_{\lfloor K / 2 \rfloor}$$
5. **Server Attestation Binding**: The participating servers are bound into a composite identifier (`consensus(server1+server2+...)`).

---

## 5. RFC 9162 Merkle Epoch Trees

To commit multiple artifacts within a discrete temporal batch, artifacts are aggregated into an RFC 9162-compliant Merkle tree using SHA-256 [RFC9162].

### 5.1. Leaf Preimage Encoding

Each leaf hash is computed over a domain-separated preimage:
$$\text{LeafHash} = \text{SHA-256}(0x00 \mathbin{\Vert} \text{LeafData})$$

Where `LeafData` is the UTF-8 encoding of:
```text
<sha256-hex>  <relative-path>
```
Note: Exactly two ASCII spaces (`0x20 0x20`) separate the hex digest and the normalized relative POSIX path.

### 5.2. Node Hashing & Promotion

Internal nodes use prefix `0x01`:
$$\text{NodeHash} = \text{SHA-256}(0x01 \mathbin{\Vert} \text{LeftChild} \mathbin{\Vert} \text{RightChild})$$

Odd leaves or nodes in an unbalanced tree are **promoted** to the next level without duplication. Duplicating odd leaves is strictly prohibited to prevent second-preimage vulnerabilities.

---

## 6. Distributed Ledger Epoch Anchoring (XRPL Profile)

To provide tamper-evident, third-party verifiable public finality, Merkle epoch roots MAY be anchored to the XRP Ledger (XRPL).

### 6.1. Transaction Profile

Anchoring transactions MUST use the standard `AccountSet` transaction type on XRPL. Redundant payment transactions (`Payment` to self) MUST NOT be used due to engine-level `temREDUNDANT` rejection rules.

### 6.2. Memo Format Specification

The transaction MUST include exactly one `Memos` entry with the following canonical fields:

* **MemoType**: `hex("moonglade/anchor/v1")` (`6D6F6F6E676C6164652F616E63686F722F7631`)
* **MemoFormat**: `hex("application/octet-stream")` (`6170706C69636174696F6E2F6F637465742D73747265616D`)
* **MemoData**: A 45-octet packed binary structure:
  ```text
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Version (1)  |          Epoch Root Digest (32 octets)        |
  +-+-+-+-+-+-+-+-+                                               +
  |                                                               |
  |                                                               |
  |               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               |          Epoch Sequence (8 octets, BE)        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               |            Leaf Count (4 octets, BE)          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ```

### 6.3. Ledger Finality & Verification

A verifier confirms ledger anchoring by inspecting the validated transaction on-ledger:
1. The transaction MUST have achieved finality (`validated: true` within a closed ledger).
2. The transaction metadata MUST report `TransactionResult: tesSUCCESS`.
3. The `MemoData` root digest MUST match the calculated Merkle root of the asserted epoch.

---

## 7. Verification Outcome Vocabulary

Verifiers MUST evaluate attestations into a four-valued outcome vocabulary:

1. **`VALID` (or `VERIFIED`)**: The canonical digest matches the artifact, the signature validates under a trusted public key, and all anchored constraints hold.
2. **`TAMPERED`**: The artifact canonical bytes do not match the signed digest recorded in the attestation.
3. **`INVALID`**: The signature is cryptographically invalid, corrupted, or explicitly revoked.
4. **`INDETERMINATE`**: The signature algorithm is unrecognized, the public key is not registered in the trusted keystore, or required online anchoring receipts cannot be verified.

---

## 8. Security Considerations

1. **Preimage Collision Defenses**: Domain separation prefixes (`0x00` for leaves, `0x01` for nodes) and odd-node promotion prevent internal nodes from being presented as leaves.
2. **Fatal UTF-8 Boundary**: Fatal decoding on invalid UTF-8 closes the collision vulnerability where distinct malformed byte sequences could produce identical replacement strings (`U+FFFD`).
3. **Quorum Drift Defenses**: The 3000 ms threshold on Tier 3 network consensus prevents a compromised DNS resolver or local HTTP cache from manipulating perceived artifact creation dates.
4. **Key Separation**: Attestation keys used by autonomous agents MUST be cryptographically distinct from ledger transaction signing keys.

---

## 9. References

### 9.1. Normative References

* [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
* [RFC3161] Adams, C., Cain, P., Pinkas, D., and R. Zuccherato, "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)", RFC 3161, August 2001.
* [RFC8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
* [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
* [RFC8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
* [RFC9162] Laurie, B., Messeri, E., and R. Stradling, "Certificate Transparency Version 2.0", RFC 9162, December 2021.
* [UAX15] The Unicode Consortium, "Unicode Standard Annex #15: Unicode Normalization Forms".

### 9.2. Informative References

* [RFC6962] Laurie, B., Langley, A., and E. Kasper, "Certificate Transparency", RFC 6962, June 2013.
* [XRPL-TX] Ripple Labs, "XRPL AccountSet Specification", 2026.

---

## Appendix A. Changes Since -02

* **Fatal Canonicalization**: Mandated strict fatal error handling on invalid UTF-8 byte sequences in text artifacts, removing lossy substitution.
* **Tier 3 Median Quorum**: Specified the Byzantine median quorum algorithm with maximum allowable drift thresholds ($\Delta t \le 3000\text{ ms}$).
* **Distributed Ledger Epoch Anchoring**: Specified the standard XRPL `AccountSet` memo profile with 45-octet packed binary payload format (`0x01 || root || epochSeq || size`).
* **Canonical JSON Formalization**: Formally codified the RFC 8785 subset restrictions (UTF-16 code unit ordering, safe integer bounds, surrogate rejection).
* **Clarifications (alignment of the TypeScript, Python and Rust engines)**: Claims numbers are judged by value (section 3.3); `onnx` is a known binary extension (section 2.1) in all three engines; Tier 3 counts distinct servers, requires an RFC 7231 HTTP-date, and is never produced by a single server (section 4.2). All three engines read one generated conformance file, `packages/provnat-core/tests/canonical_v3.golden.json`.

---

## Author's Address

```text
Marc Ottley
Moonglade AI
Boscobelle, St. Andrew
Barbados
Email: moongladeai@gmail.com
```
