/**
 * Unit tests for native stdio MCP server tools.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { handleMcpToolCall, MCP_TOOLS } = require('../dist/mcp.js');
const { ProvenanceEngine } = require('../dist/index.js');

let tmp;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-test-'));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

const write = (name, content) => {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, content);
  return p;
};

describe('MCP Tools Schema Definition', () => {
  test('exports exactly 3 read-only MCP tools', () => {
    expect(MCP_TOOLS.length).toBe(3);
    const names = MCP_TOOLS.map(t => t.name);
    expect(names).toContain('verify_artifact_provenance');
    expect(names).toContain('audit_vault_merkle_root');
    expect(names).not.toContain('seal_canonical_epoch');
    expect(names).toContain('assert_gate_status');
  });
});

describe('handleMcpToolCall Execution', () => {
  test('verify_artifact_provenance detects unsealed artifacts', async () => {
    const file = write('unsealed.md', '# Unsealed');
    const out = await handleMcpToolCall('verify_artifact_provenance', { file_path: file });
    expect(out).toContain('[UNATTESTED]');
  });

  test('assert_gate_status blocks on missing prerequisite', async () => {
    const out = await handleMcpToolCall('assert_gate_status', {
      gate_type: 'GATE_A_ARCHITECTURE',
      prerequisite_token_path: path.join(tmp, 'nonexistent.md')
    });
    expect(out).toContain('[BLOCKED 🛑]');
  });

  test('assert_gate_status clears on a sealed artifact when given the key', async () => {
    const file = write('canonical.md', '# Architecture SAD\nCanonical ground truth.\n');
    const { privateKey, publicKey } = ProvenanceEngine.generateEd25519KeyPair();
    await ProvenanceEngine.sealDocument(file, privateKey, 'architect@moongladeai', 'abc1234', {
      vaultRoot: tmp,
      timestamp: false
    });

    const out = await handleMcpToolCall('assert_gate_status', {
      gate_type: 'GATE_A_ARCHITECTURE',
      prerequisite_token_path: file,
      public_key_pem: publicKey
    });
    expect(out).toContain('[PASSED 🟢]');
  });

  // --- regression tests for the 2026-09-06 independent evaluation (F1, F2, F5, F6) ---

  test('F1: assert_gate_status fails closed without a public key', async () => {
    const file = write('canonical.md', '# SAD\n');
    const { privateKey } = ProvenanceEngine.generateEd25519KeyPair();
    await ProvenanceEngine.sealDocument(file, privateKey, 'architect@moongladeai', 'abc1234', {
      vaultRoot: tmp, timestamp: false
    });
    const out = await handleMcpToolCall('assert_gate_status', {
      gate_type: 'GATE_A_ARCHITECTURE',
      prerequisite_token_path: file
    });
    expect(out).toContain('[BLOCKED 🛑]');
    expect(out).toContain('Missing required argument: public_key_pem');
  });

  test('F1: a hash-only sidecar with no signature cannot clear the gate', async () => {
    const file = write('memory.md', 'attacker controlled memory\n');
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update('attacker controlled memory\n').digest('hex');
    fs.writeFileSync(file + '.provenance.json', JSON.stringify({ standard: 'Moonglade Provenance Attestation Bundle v2', artifact: path.basename(file), sha256_at_last_write: hash, attestations: [{ method: 'openpgp', signer: 'synthetic' }] }));
    const out = await handleMcpToolCall('assert_gate_status', {
      gate_type: 'GATE_A_ARCHITECTURE',
      prerequisite_token_path: file
    });
    expect(out).toContain('[BLOCKED 🛑]');
    expect(out).not.toContain('[PASSED');
  });

  test('F2: an unsigned signer string never produces a human-verified verdict', async () => {
    const file = write('forged.md', 'forged\n');
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update('forged\n').digest('hex');
    fs.writeFileSync(file + '.provenance.json', JSON.stringify({
      standard: 'Moonglade Provenance Attestation Bundle v2', artifact: path.basename(file), sha256_at_last_write: hash,
      attestations: [{ method: 'openpgp', signer: 'signer@example.invalid' }]
    }));
    const out = await handleMcpToolCall('verify_artifact_provenance', { file_path: file });
    expect(out).toContain('[UNVERIFIED - HASH ONLY]');
    expect(out).not.toContain('HUMAN_VERIFIED');
    expect(out).toContain('attacker-controllable');
  });

  test('F2: an absent timestamp is never rendered as a default assurance tier', async () => {
    const file = write('notier.md', 'x\n');
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update('x\n').digest('hex');
    fs.writeFileSync(file + '.provenance.json', JSON.stringify({ standard: 'Moonglade Provenance Attestation Bundle v2', artifact: path.basename(file), sha256_at_last_write: hash, attestations: [{ method: 'openpgp', signer: 'synthetic' }] }));
    const out = await handleMcpToolCall('verify_artifact_provenance', { file_path: file });
    expect(out).not.toContain('L1_CRYPTO_PRIMARY');
    expect(out).not.toContain('DigiCert');
    expect(out).toContain('none recorded');
  });

  test('F5: required_scope is enforced, not ignored', async () => {
    const file = write('scoped.md', '# scoped\n');
    const { privateKey, publicKey } = ProvenanceEngine.generateEd25519KeyPair();
    await ProvenanceEngine.sealDocument(file, privateKey, 'architect@moongladeai', 'abc1234', {
      vaultRoot: tmp, timestamp: false
    });
    const bad = await handleMcpToolCall('verify_artifact_provenance', {
      file_path: file, public_key_pem: publicKey, required_scope: 'some/other/scope'
    });
    expect(bad).toContain('Scope mismatch');
    const good = await handleMcpToolCall('verify_artifact_provenance', {
      file_path: file, public_key_pem: publicKey
    });
    expect(good).toContain('[VERIFIED ✅]');
  });

  test('F6: an audit with no expected_root reports that it compared nothing', async () => {
    write('a.md', 'alpha');
    const out = await handleMcpToolCall('audit_vault_merkle_root', { vault_root: tmp });
    expect(out).not.toContain('PRISTINE');
    expect(out).toContain('NOT COMPARED');
  });

  test('F6: a deleted file makes the root differ from the expected root', async () => {
    write('a.md', 'alpha');
    const b = write('b.md', 'beta');
    const before = await handleMcpToolCall('audit_vault_merkle_root', { vault_root: tmp });
    const root = before.match(/Root:\s+([a-f0-9]{64})/)[1];
    fs.rmSync(b);
    const after = await handleMcpToolCall('audit_vault_merkle_root', {
      vault_root: tmp, expected_root: root
    });
    expect(after).toContain('DIFFERS');
    expect(after).toContain('DELETED');
  });

  test('audit_vault_merkle_root computes root over workspace', async () => {
    write('a.md', 'alpha');
    write('b.md', 'beta');
    const out = await handleMcpToolCall('audit_vault_merkle_root', { vault_root: tmp });
    expect(out).toContain('[MERKLE SNAPSHOT]');
    expect(out).toContain('Root:');
  });
});
