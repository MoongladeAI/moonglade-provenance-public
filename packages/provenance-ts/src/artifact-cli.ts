#!/usr/bin/env node
import { ProvenanceEngine } from './index';
import { processArtifact, sealWithOpenPgp, moveArtifactWithAttestation } from './artifactHook';
import { runSelfTests, printSelfTestReport } from './self-test';
import { getArtifactBadge } from './badge';

async function main() {
  const [, , action, file, dest] = process.argv;
  if (action === '--help' || action === '-h') { console.log('provenance <verify|badge|observe|seal-provisional|move|test> <file> [dest]. Keys: MOONGLADE_PUBLIC_KEY_PEM / MOONGLADE_PRIVATE_KEY_PEM. Verification root: MOONGLADE_ROOT or current directory.'); return; }
  if (action === '--version') { console.log(require('../package.json').version); return; }
  if (action === 'verify') {
    if (!file || !process.env.MOONGLADE_PUBLIC_KEY_PEM) throw new Error('verify requires a file and MOONGLADE_PUBLIC_KEY_PEM');
    const expectedScope = ProvenanceEngine.scopeFor(file, process.env.MOONGLADE_ROOT || process.cwd());
    const requiredSigners = process.env.MOONGLADE_REQUIRED_SIGNERS?.split(',');
    const result = await ProvenanceEngine.verifyDocument(file, process.env.MOONGLADE_PUBLIC_KEY_PEM, { expectedScope, requiredSigners });
    console.log(JSON.stringify(result, null, 2));
    if (!result.verified) process.exitCode = 1;
    return;
  }
  if (action === 'test' || action === 'self-test') {
    const isJson = process.argv.includes('--json');
    const report = await runSelfTests();
    if (isJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printSelfTestReport(report);
    }
    if (!report.passed) process.exitCode = 1;
    return;
  }

  if (action === 'badge') {
    if (!file) {
      console.error('usage: provenance badge <file> [--format=text|markdown|json|shields] [--short]');
      process.exitCode = 2;
      return;
    }
    const isJson = process.argv.includes('--json') || process.argv.includes('--format=json');
    const isText = process.argv.includes('--format=text');
    const isShields = process.argv.includes('--format=shields') || process.argv.includes('--format=shields-url');
    const isHtml = process.argv.includes('--format=html') || process.argv.includes('--html');
    const isColor = process.argv.includes('--color') || process.argv.includes('-c');
    const isShort = process.argv.includes('--short');

    const badgeInfo = await getArtifactBadge(file, {
      style: isShort ? 'short' : 'detailed',
      color: isColor ? 'ansi' : false,
      publicKeyPem: process.env.MOONGLADE_PUBLIC_KEY_PEM,
      requiredScope: process.env.MOONGLADE_PUBLIC_KEY_PEM ? ProvenanceEngine.scopeFor(file, process.env.MOONGLADE_ROOT || process.cwd()) : undefined
    });

    if (isJson) {
      console.log(JSON.stringify(badgeInfo, null, 2));
    } else if (isHtml) {
      console.log(badgeInfo.html ?? badgeInfo.badgeText);
    } else if (isShields) {
      console.log(badgeInfo.shieldsUrl);
    } else if (isText) {
      console.log(isColor ? (badgeInfo.ansiText ?? badgeInfo.badgeText) : badgeInfo.badgeText);
    } else {
      console.log(isColor ? `${badgeInfo.markdown.replace(badgeInfo.badgeText, badgeInfo.ansiText ?? badgeInfo.badgeText)}` : badgeInfo.markdown);
    }
    if (badgeInfo.status === 'MUTATED' || badgeInfo.status === 'INVALID_SIGNATURE' || badgeInfo.status === 'NOT_FOUND') {
      process.exitCode = 1;
    }
    return;
  }

  if (!action || !file || !['observe', 'seal-provisional', 'move'].includes(action)) {
    console.error('usage: provenance <observe|seal-provisional|move|test|badge> <file> [dest]');
    process.exitCode = 2;
    return;
  }
  if (action === 'move') {
    if (!dest) {
      console.error('usage: provenance-artifact move <source> <dest>');
      process.exitCode = 2;
      return;
    }
    const result = await moveArtifactWithAttestation(file, dest);
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  const common = {
    vaultRoot: process.cwd(),
    signerIdentity: process.env.MOONGLADE_SIGNER,
    generator: {
      agent: process.env.MOONGLADE_AGENT ?? 'unknown',
      model: process.env.MOONGLADE_MODEL
    }
  };
  const result = await processArtifact(file, { ...common, action: action as any, privateKeyPem: process.env.MOONGLADE_PRIVATE_KEY_PEM });
  if (result.skipped) process.exitCode = 1;
  console.log(JSON.stringify(result, null, 2));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
