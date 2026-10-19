# Dependency and fixture notices

This package uses the MIT license. Its direct runtime dependencies are PKI.js 3.4.1 and ASN1.js 3.0.10, both BSD-3-Clause. The locked runtime dependency tree also includes @noble/hashes (MIT), bytestreamjs (BSD-3-Clause), pvtsutils (MIT), pvutils (MIT) and tslib (0BSD).

Each dependency retains its own copyright and license files when installed. No dependency code is vendored in this package.

Timestamp tests generate synthetic certificates and ephemeral keys with PKI.js and Node WebCrypto. Merkle and canonicalization vectors are project test data. The historical FreeTSA fixture and unreviewed TSA anchors are excluded.

The Moonglade name identifies the project. The MIT license does not grant additional trademark permission. The exported root certificate deliberately contains the release maintainer's public signer identity. It is not an artifact verification key and does not grant agents architect authority.
