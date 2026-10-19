# Moonglade provenance 2.5.0 release candidate

Moonglade provenance signs files and checks their integrity. It combines Ed25519 signatures, RFC 3161 timestamp verification and Merkle inclusion proofs in a local Node.js library, CLI and read-only MCP server.

This repository contains [@moonglade/provenance](packages/provenance-ts/README.md). It is the staging repository for the 2.5.0 candidate. Production publication still requires the release audit and human signing gates to close.

## Build and test

Use Node 22 or 24 on Windows or Linux. From the repository root:

```sh
npm ci
npm test
npm run self-test
```

[TESTING.md](TESTING.md) describes the suites, recorded results and coverage limits. The [package README](packages/provenance-ts/README.md) has the API and CLI quickstart, including an example that uses caller-supplied keys.

## What a seal establishes

A valid signature binds the signed payload to a supplied key. It establishes integrity under that key; it cannot establish whether the content is true, who actually wrote it, or whether an AI performs better because it uses provenance.

Text checks normalize the encodings listed in the [specification](packages/provenance-ts/SPEC.md). Binary files retain their exact bytes. Timestamp trust requires caller-supplied certificate anchors. Certificate revocation is not checked.

No controlled evaluation in this release demonstrates improved agent behavior or performance. Standing instructions and operator choices would need to be controlled in such a study.

## Release information

See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md) and [AI-DISCLOSURE.md](AI-DISCLOSURE.md).

The staging repository is [MoongladeAI/moonglade-provenance-public](https://github.com/MoongladeAI/moonglade-provenance-public). Private security reporting must be checked before publication. The candidate documentation has no provenance sidecars, and the root release signature remains a separate human act. The private development monorepo remains the development home; its earlier history and integration code are excluded here.

## Dedication

> *Dedicated to my Godchildren. The promise of a better future for you begins with Provenance.*

The dedication, thanks and intellectual influences are in [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).
