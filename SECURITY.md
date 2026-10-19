# Security policy

Version 2.5.0 is a release candidate. No production version is declared supported until its release audit passes. After release, the latest 2.5 patch is intended to receive security fixes. Older major and minor versions have no support commitment here.

## Reporting a vulnerability

Use GitHub private vulnerability reporting through the repository's Security tab. Keep exploit details out of public issues. Private reporting must be enabled and checked before publication. If that route is unavailable, hold sensitive details until a private channel has been established. This repository does not publish a personal reporting email address.

Maintainers aim to acknowledge reports within seven days. That is a target, not a guarantee. Agree on a disclosure date after a fix is available or as part of a coordinated response.

## Trust boundary

The CLI and MCP server run with the operator's filesystem permissions. A supplied MCP path authorizes a local read. The server is not an operating-system sandbox and does not infer human approval or signer authority. Its public tools do not sign.

Protect private keys and workspace write permissions. The implementation does not cover concurrent hostile filesystem writers or certificate revocation checks. Report integrity failures, scope or signer policy bypasses, malformed-input acceptance, symlink escapes and misleading assurance labels privately.
