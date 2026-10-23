# Timestamp verification in 2.6.0

## Token verification

`verifyTimeStampToken` checks the CMS signature over signed attributes, signed content type, TSTInfo digest, SHA-256 document imprint, one TSA signer, ESS certificate binding, certificate validity at token generation time and critical timestamp-only EKU. If KeyUsage is present it must permit signatures. SHA-256/384/512 CMS digests and RSA PKCS#1 v1.5 or ECDSA signatures are supported. Other algorithms fail closed. Legacy ESSCertID is supported for integrity-only checks; anchored policy requires ESSCertIDv2.

## Trust anchors

Without caller-supplied `trustAnchors`, a token can earn INTEGRITY_ONLY, including self-signed tokens. Supplying CA trustAnchors requires successful PKI.js certificate path validation at the token generation time and yields ANCHORED. An empty anchor list is an error. Sidecar-supplied anchors are ignored. No OCSP/CRL revocation lookup is performed and no revocation assurance is claimed. No public TSA anchor is installed implicitly.

## Acquisition and response checks

`validateTimeStampResp` checks response structure; it does not verify signatures. It parses the actual TSTInfo imprint/nonce rather than searching bytes. verifyTimeStampToken establishes cryptographic integrity and optional trust. probeTsa performs both response/nonce checking and token signature/imprint validation. queryTsa limits responses to 512 KiB and imposes an absolute deadline. Acquisition routing labels L1/L2 on probes describe selected endpoint pools only; returned token results are INTEGRITY_ONLY, never trusted by routing. Network HTTP Date and host-clock fallbacks are unauthenticated observations, not timestamp attestations. No host-time substitute is inserted into a token result.

## Public functions

Public functions: encodeDerLength, encodeDerSequence, decodeDerLength, parsePkiStatus, validateTimeStampResp, verifyTimeStampToken, buildTimeStampReq, extractGenTime, queryTsa, probeTsa, probeNetworkTime and concurrentDegradingTimestamp. EndpointCircuitBreaker and exported endpoint/policy constants provide acquisition scheduling. extractGenTime is a legacy unauthenticated diagnostic parser, never used for a verified timestamp verdict.

## Test coverage

Tests generate ephemeral synthetic CA/TSA keys in memory. No private fixture key or third-party TSA token ships. Live TSA behavior and revocation are outside the hermetic tests. Services are used under their own terms and are not endorsed by this package. Sources: [PKI.js certificate validation](https://pkijs.org/docs/api/classes/CertificateChainValidationEngine/), [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816).
