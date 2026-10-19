# Contributing

Use Node 22 or 24. From the repository root, run:

```sh
npm ci
npm test
npm run self-test
```

The test command starts with an empty `dist` directory. Tests use local HTTP fixtures, CLI subprocesses and filesystem links, so your account must be allowed to create them. They need no production key, live timestamp service or external corpus. See [TESTING.md](TESTING.md) for details.

Contributions use the repository's MIT license. Document architecture changes before implementing them. Changes to signing or verification need attack regression tests, the complete automated suites and an independent audit.

Every MUST requirement needs evidence. Unresolved failures block release. Agents can prepare code and reviews; the maintainer supplies human root approval. The tree approved and signed through the human gate must be the tree that passed the final checks. Contribution workflows must not use the release root automatically or publish a release.
