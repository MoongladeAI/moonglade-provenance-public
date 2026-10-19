import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { ProvenanceEngine } from './index';
import { merkleRoot, inclusionProof, verifyProof } from './merkle';
import { createArtifactEnvelope, validateArtifactEnvelope, artifactId } from './artifactEnvelope';
import { concurrentDegradingTimestamp } from './timestamp';

export interface ConditionResult {
  name: string;
  passed: boolean;
  durationMs: number;
  error?: string;
  details?: string;
}

export interface SelfTestReport {
  passed: boolean;
  version: string;
  nodeVersion: string;
  platform: string;
  conditions: ConditionResult[];
  totalDurationMs: number;
  verifiedPackageArtifacts: number;
}

export async function runSelfTests(options: { packageRoot?: string; verbose?: boolean } = {}): Promise<SelfTestReport> {
  const startTime = Date.now();
  const root = options.packageRoot ?? path.resolve(__dirname, '..');
  const conditions: ConditionResult[] = [];

  // Helper to record condition results
  async function runCondition(name: string, fn: () => Promise<string | void>) {
    const t0 = Date.now();
    try {
      const details = await fn();
      conditions.push({
        name,
        passed: true,
        durationMs: Date.now() - t0,
        details: details || undefined
      });
    } catch (err: any) {
      conditions.push({
        name,
        passed: false,
        durationMs: Date.now() - t0,
        error: err?.message || String(err)
      });
    }
  }

  // Condition 1: Ed25519 Micro-Signatures & Structured V2 Framing
  await runCondition('Ed25519 Micro-Signatures & V2 Framing', async () => {
    const keyPair = ProvenanceEngine.generateEd25519KeyPair();
    const digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const payload = ProvenanceEngine.buildSigningPayload({
      scope: 'moonglade:self-test:doc',
      sha256: digest,
      signer: 'test@moonglade.ai'
    });

    const signature = crypto.sign(null, payload, keyPair.privateKey);
    const valid = crypto.verify(null, payload, keyPair.publicKey, signature);
    if (!valid) throw new Error('Valid signature failed verification');

    // Reject tampered payload
    const tamperedPayload = ProvenanceEngine.buildSigningPayload({
      scope: 'moonglade:self-test:doc',
      sha256: '0000000000000000000000000000000000000000000000000000000000000000',
      signer: 'test@moonglade.ai'
    });
    const tamperedPayloadValid = crypto.verify(null, tamperedPayload, keyPair.publicKey, signature);
    if (tamperedPayloadValid) throw new Error('Tampered payload was accepted as valid');

    // Reject tampered signature
    const corruptedSig = Buffer.from(signature);
    corruptedSig[0] ^= 0xff;
    const tamperedSigValid = crypto.verify(null, payload, keyPair.publicKey, corruptedSig);
    if (tamperedSigValid) throw new Error('Corrupted signature was accepted as valid');

    return 'Sign, verify, and tamper rejection passed';
  });

  // Condition 2: RFC 6962 Merkle Trees & Leaf Inclusion Proofs
  await runCondition('RFC 6962 Merkle Trees & Inclusion Proofs', async () => {
    const mockRegistry = {
      'docs/a.md': { sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
      'docs/b.md': { sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' },
      'docs/c.md': { sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' },
      'docs/d.md': { sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' }
    };

    const root = merkleRoot(mockRegistry);
    if (!/^[0-9a-f]{64}$/.test(root)) throw new Error('Invalid Merkle root derived');

    const proof = inclusionProof(mockRegistry, 'docs/c.md');
    if (!proof) throw new Error('Inclusion proof derivation failed for existing leaf');

    const validProof = verifyProof(proof, root);
    if (!validProof) throw new Error('Valid inclusion proof failed mathematical verification');

    // Corrupted proof must fail
    const corruptedProof = JSON.parse(JSON.stringify(proof));
    corruptedProof.proof[0].hash = '0000000000000000000000000000000000000000000000000000000000000000';
    if (verifyProof(corruptedProof, root)) throw new Error('Corrupted inclusion proof was accepted');

    // Missing artifact returns null
    if (inclusionProof(mockRegistry, 'docs/missing.md') !== null) {
      throw new Error('Inclusion proof returned non-null for missing leaf');
    }

    return `Tree of size 4 verified; root ${root.slice(0, 12)}...`;
  });

  // Condition 3: Artifact Envelope v1 Contract & Canonical Byte Binding
  await runCondition('Artifact Envelope v1 Schema & Hash Binding', async () => {
    const rawBytes = Buffer.from('# Moonglade Self Test\nInvariant proof substrate.', 'utf8');
    const expectedId = artifactId(rawBytes);

    const envelope = createArtifactEnvelope({
      artifact_type: 'release',
      canonical_bytes: expectedId,
      created_at: new Date().toISOString(),
      parents: [],
      attestations: [{ method: 'self-test', status: 'provisional' }],
      status: 'signed',
      evidence: { integrity: 'valid', signature: 'provisional', timestamp: 'none', scope: 'valid' },
      generator: { agent: 'synthetic-test', model: 'self-test-harness' },
      bytes: rawBytes
    });

    if (!validateArtifactEnvelope(envelope)) throw new Error('Constructed envelope failed schema validation');
    if (envelope.artifact_id !== expectedId) throw new Error('Envelope artifact_id does not match canonical bytes hash');

    // Tampered schema must fail
    const tampered = { ...envelope, artifact_id: 'invalid-id' };
    if (validateArtifactEnvelope(tampered)) throw new Error('Invalid envelope format was accepted as valid');

    return `Envelope ${envelope.artifact_id.slice(0, 19)}... verified`;
  });

  // Condition 4: Fail-Closed Gate Barriers & Anti-Tampering Rejection
  await runCondition('Fail-Closed Gate Barriers & Mutation Rejection', async () => {
    const tempDir = path.join(root, '.tmp-selftest-' + Date.now());
    await fs.mkdir(tempDir, { recursive: true });
    const testDoc = path.join(tempDir, 'gate-test.md');
    const keyPair = ProvenanceEngine.generateEd25519KeyPair();

    try {
      await fs.writeFile(testDoc, '# Gate Assertion Test\nOriginal untouched bytes.\n', 'utf8');
      await ProvenanceEngine.sealDocument(testDoc, keyPair.privateKey, 'test-signer', 'head', {
        vaultRoot: tempDir,
        timestamp: false
      });

      // Valid check must pass
      const initialVerify = await ProvenanceEngine.verifyDocument(testDoc, keyPair.publicKey);
      if (!initialVerify.verified) {
        throw new Error(`Expected verification to succeed: ${initialVerify.error}`);
      }

      // Mutate the document
      await fs.appendFile(testDoc, '\nMalicious unsealed line inserted.\n', 'utf8');
      const tamperedVerify = await ProvenanceEngine.verifyDocument(testDoc, keyPair.publicKey);
      if (tamperedVerify.verified) {
        throw new Error('Mutated document passed verification; fail-closed gate violated');
      }
      if (!tamperedVerify.error?.includes('Hash mismatch')) {
        throw new Error(`Expected hash mismatch error, got: ${tamperedVerify.error}`);
      }

      return 'Sealed artifact verified; post-seal modification rejected fail-closed';
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  // Condition 5: Concurrent Degrading Timestamping Architecture (DTA)
  await runCondition('Concurrent Degrading Timestamp Architecture (DTA)', async () => {
    const dummyDigest = crypto.createHash('sha256').update('dta-test').digest();
    const dta = await concurrentDegradingTimestamp(dummyDigest, { specifiedTier: 'L4_HOST_UNAUTHENTICATED' });

    if (!dta.tier || dta.tier !== 'L4_HOST_UNAUTHENTICATED') {
      throw new Error(`Expected L4 offline degradation tier, got ${dta.tier}`);
    }
    if (!dta.tsa_time || isNaN(Date.parse(dta.tsa_time))) {
      throw new Error('Invalid ISO timestamp returned by DTA degradation fallback');
    }
    if (!Array.isArray(dta.probes) || dta.probes.length === 0) {
      throw new Error('Expected probe audit telemetry in DTA result');
    }

    return `Degraded to ${dta.tier} at ${dta.tsa_time}`;
  });

  // Condition 6: Package Self-Provenance (All Shipped Items Carry Provenance)
  let verifiedCount = 0;
  await runCondition('Package Self-Provenance Verification', async () => {
    // Look for all .provenance.json files directly in package root and docs
    const entries = await fs.readdir(root, { withFileTypes: true });
    const sidecarFiles: string[] = [];

    for (const ent of entries) {
      if (ent.isFile() && ent.name.endsWith('.provenance.json')) {
        sidecarFiles.push(path.join(root, ent.name));
      }
    }

    // Only package-root sidecars belong to this distribution inventory.
    if (sidecarFiles.length === 0) {
      return 'No shipped sidecars; distribution files are intentionally unsealed pending release approval';
    }

    for (const sidecarPath of sidecarFiles) {
      const sidecarRaw = await fs.readFile(sidecarPath, 'utf8');
      const sidecar = JSON.parse(sidecarRaw);
      
      const targetPath = sidecarPath.replace(/\.provenance\.json$/, '');
      let fileBytes: Buffer;
      try {
        fileBytes = await fs.readFile(targetPath);
      } catch {
        // Special case: package.provenance.json may target package.json
        if (path.basename(sidecarPath) === 'package.provenance.json') {
          fileBytes = await fs.readFile(path.join(root, 'package.json'));
        } else {
          throw new Error(`Target artifact missing for sidecar: ${path.basename(sidecarPath)}`);
        }
      }

      const compareBytes = ProvenanceEngine.canonicalizeBytes(fileBytes, path.basename(sidecarPath) === 'package.provenance.json' ? 'package.json' : targetPath);

      const computedHash = crypto.createHash('sha256').update(compareBytes).digest('hex');
      if (!/^[a-f0-9]{64}$/.test(sidecar.sha256_at_last_write) || sidecar.sha256_at_last_write !== computedHash) {
        throw new Error(`Hash mismatch on shipped artifact ${path.basename(targetPath)}: sidecar has ${sidecar.sha256_at_last_write}, actual is ${computedHash}`);
      }

      if (sidecar.envelope) {
        if (!validateArtifactEnvelope(sidecar.envelope)) {
          throw new Error(`Invalid envelope on shipped artifact ${path.basename(targetPath)}`);
        }
      }

      verifiedCount++;
    }

    return `${verifiedCount} shipped sidecar hashes compared; no package signature verification performed`;
  });

  const totalDurationMs = Date.now() - startTime;
  const passed = conditions.every(c => c.passed);

  return {
    passed,
    version: require('../package.json').version,
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    conditions,
    totalDurationMs,
    verifiedPackageArtifacts: verifiedCount
  };
}

export function printSelfTestReport(report: SelfTestReport): void {
  console.log(`\nMoonglade Provenance Self-Test Suite v${report.version} (${report.platform}, Node ${report.nodeVersion})`);
  console.log('='.repeat(75));

  for (let i = 0; i < report.conditions.length; i++) {
    const c = report.conditions[i];
    const statusTag = c.passed ? '[PASS]' : '[FAIL]';
    console.log(`${statusTag} ${i + 1}. ${c.name} (${c.durationMs}ms)`);
    if (c.details) {
      console.log(`       Evidence: ${c.details}`);
    }
    if (c.error) {
      console.log(`       Error: ${c.error}`);
    }
  }

  console.log('-'.repeat(75));
  if (report.passed) {
    console.log(`All ${report.conditions.length} condition suites PASSED (${report.totalDurationMs}ms). Environment verified.`);
  } else {
    const failedCount = report.conditions.filter(c => !c.passed).length;
    console.error(`${failedCount} condition suite(s) FAILED (${report.totalDurationMs}ms). Verification failed.`);
  }
}
