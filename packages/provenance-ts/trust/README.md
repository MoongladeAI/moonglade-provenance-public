# Release root trust

The OpenPGP release root fingerprint is:

```text
5E7FA9F6C5B0A65BC23A75704FF2C2DE69C0C4A3
```

Inspect the public certificate independently:

```sh
gpg --show-keys --with-fingerprint root-public.asc
```

Verify the human release manifest or commit with GPG. Before trusting it, compare the full fingerprint with the MoongladeAI organization profile and the identified publication on moongladeai.net. Those external publications must be checked at release time. A key shipped inside the same untrusted download cannot establish its own identity.

The registry contains the root role only. Agent reviews have no architect authority. The registry remains an unsigned candidate until the human gate signs it.

The artifact API accepts raw Ed25519 SPKI PEM keys, not OpenPGP certificates. Do not pass this certificate to that API or use the release root from an unattended agent. The certificate's user IDs are deliberate public signer identifiers.
