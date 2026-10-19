const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const { ProvenanceEngine: E, canonicalizeJson, getArtifactBadge, moveArtifactWithAttestation,
  inclusionProof, verifyProof, merkleRoot, ProvenanceVault, MAX_SIDECAR_BYTES } = require('../dist');
let dir, file, keys;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-security-'));
  file = path.join(dir, 'artifact.md'); fs.writeFileSync(file, 'original\n'); keys = E.generateEd25519KeyPair();
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
async function seal(claims) { return E.sealDocument(file, keys.privateKey, 'synthetic', 'test', { vaultRoot: dir, ...(claims === undefined ? {} : { claims }) }); }
function edit(fn) { const s = JSON.parse(fs.readFileSync(file + '.provenance.json', 'utf8')); fn(s); fs.writeFileSync(file + '.provenance.json', JSON.stringify(s)); }
function cli(args, env = {}) { return cp.spawnSync(process.execPath, [path.resolve(__dirname, '../dist/artifact-cli.js'), ...args], { cwd: dir, encoding: 'utf8', env: { ...process.env, MOONGLADE_PRIVATE_KEY_PEM: '', MOONGLADE_PUBLIC_KEY_PEM: '', MOONGLADE_ROOT: dir, ...env } }); }

describe('canonical bytes and strict JSON', () => {
  test.each(['file.md', 'file.unknown', 'file.onnx'])('invalid UTF8 is rejected for %s', name => {
    for (const byte of [0xff, 0xfe]) expect(() => E.canonicalizeBytes(Buffer.from([97, byte, 98]), name)).toThrow();
  });
  test('known binary is byte exact', () => { const raw = Buffer.from([0xff, 13, 10, 0]); expect(E.canonicalizeBytes(raw, 'file.png')).toEqual(raw); });
  test.each([NaN, Infinity, -Infinity, undefined, 1n, Symbol('x'), () => 1, '\ud800', '\udfff', { x: undefined }, [undefined], new Date()])('unsupported JSON %# fails', value => { expect(() => canonicalizeJson(value)).toThrow(); });
  test('cycles, sparse arrays and accessors fail', () => {
    const a = {}; a.x = a; expect(() => canonicalizeJson(a)).toThrow();
    expect(() => canonicalizeJson(new Array(2))).toThrow();
    expect(() => canonicalizeJson({ get x() { throw Error('must not execute'); } })).toThrow(/accessors/);
  });
  test('valid supplementary unicode and sorted JSON remain deterministic', () => { expect(canonicalizeJson({ z: '😀', a: [null, true, 1] })).toBe('{"a":[null,true,1],"z":"😀"}'); });
});
describe('bundle attacks', () => {
  test.each(['claims', 'claims_sha256'])('stripping %s from v3 fails', async field => { await seal({ a: 1 }); edit(s => { delete s[field]; }); expect((await E.verifyDocument(file, keys.publicKey)).verified).toBe(false); });
  test('edited claims with hash deleted fails', async () => { await seal({ a: 1 }); edit(s => { s.claims.a = 2; delete s.claims_sha256; }); expect((await E.verifyDocument(file, keys.publicKey)).verified).toBe(false); });
  test.each(['forged v2', 'Moonglade Provenance Attestation Bundle v20', 'Moonglade Provenance Attestation Bundle v3 extra', '', null])('invented standard %# fails', async standard => { await seal(); edit(s => { s.standard = standard; }); expect((await E.verifyDocument(file, keys.publicKey)).verified).toBe(false); });
  test.each(['openpgp', 'ssh-ed25519', 'unknown'])('a valid signature cannot redeem %s sibling', async method => { await seal(); edit(s => { s.attestations.push({ method }); }); const result = await E.verifyDocument(file, keys.publicKey); expect(result.verified).toBe(false); expect(result.status).toBe('INDETERMINATE'); });
  test('expected scope is enforced for all signatures', async () => { await seal(); expect((await E.verifyDocument(file, keys.publicKey, { expectedScope: 'moonglade:vault:elsewhere.md' })).verified).toBe(false); });
  test('required signer omissions fail', async () => { await seal(); expect((await E.verifyDocument(file, keys.publicKey, { requiredSigners: ['missing'] })).verified).toBe(false); expect((await E.verifyDocument(file, keys.publicKey, { requiredSigners: ['synthetic'] })).verified).toBe(true); });
  test('renamed identical artifact fails', async () => { await seal(); const renamed = path.join(dir, 'renamed.md'); fs.copyFileSync(file, renamed); fs.copyFileSync(file + '.provenance.json', renamed + '.provenance.json'); expect((await E.verifyDocument(renamed, keys.publicKey)).verified).toBe(false); });
  test('same basename relocated requires scope policy', async () => { await seal(); fs.mkdirSync(path.join(dir, 'sub')); const sub = path.join(dir, 'sub/artifact.md'); fs.copyFileSync(file, sub); fs.copyFileSync(file + '.provenance.json', sub + '.provenance.json'); expect((await E.verifyDocument(sub, keys.publicKey, { expectedScope: E.scopeFor(sub, dir) })).verified).toBe(false); });
  test('countersigning missing keys and tampered claims leave original bytes unchanged', async () => { await seal({ a: 1 }); const second = E.generateEd25519KeyPair(); edit(s => { s.claims.a = 2; }); const before = fs.readFileSync(file + '.provenance.json'); await expect(E.countersignDocument(file, second.privateKey, 'second')).rejects.toThrow(/verificationKeys/); await expect(E.countersignDocument(file, second.privateKey, 'second', 'test', { verificationKeys: keys.publicKey })).rejects.toThrow(/Claims/); expect(fs.readFileSync(file + '.provenance.json')).toEqual(before); });
  test('countersigning forged original signature fails', async () => { await seal(); edit(s => { s.attestations[0].signature = Buffer.alloc(64).toString('base64'); }); await expect(E.countersignDocument(file, keys.privateKey, 'second', 'test', { verificationKeys: keys.publicKey })).rejects.toThrow(); });
  test.each(['rsa', 'ec'])('algorithm confusion %s fails at signing and verification', async algorithm => {
    const other = crypto.generateKeyPairSync(algorithm, algorithm === 'rsa' ? { modulusLength: 2048 } : { namedCurve: 'prime256v1' });
    const priv = other.privateKey.export({ type: 'pkcs8', format: 'pem' }), pub = other.publicKey.export({ type: 'spki', format: 'pem' });
    await expect(E.sealDocument(file, priv, 'synthetic')).rejects.toThrow(/Ed25519/);
    await seal(); edit(s => { s.attestations[0].signature = crypto.sign(null, E.buildSigningPayload({ scope: s.attestations[0].scope, sha256: s.sha256_at_last_write, signer: 'synthetic' }), priv).toString('base64'); });
    expect((await E.verifyDocument(file, pub)).verified).toBe(false);
  });
  test('tokenless forged time fails and unsigned created time is not returned', async () => { await seal(); expect((await E.verifyDocument(file, keys.publicKey)).timestamp).toBeUndefined(); edit(s => { s.attestations.push({ method: 'rfc3161', tier: 'L1_CRYPTO_PRIMARY', tsa_time: '2001-01-01T00:00:00Z' }); }); expect((await E.verifyDocument(file, keys.publicKey)).verified).toBe(false); });
  test('oversized sidecars fail', async () => { fs.writeFileSync(file + '.provenance.json', ' '.repeat(MAX_SIDECAR_BYTES + 1)); expect((await E.verifyDocument(file, keys.publicKey)).verified).toBe(false); });
});
describe('badges and real CLI', () => {
  test.each([{}, [], 'x', null, { sha256_at_last_write: '0'.repeat(64) }])('malformed sidecar %# never sealed', async sidecar => { fs.writeFileSync(file + '.provenance.json', JSON.stringify(sidecar)); expect((await getArtifactBadge(file)).status).not.toBe('SEALED'); });
  test('keyless matching hash is amber HASH-ONLY; valid key is SEALED', async () => { await seal(); const badge = await getArtifactBadge(file); expect(badge.status).toBe('HASH_ONLY'); expect(badge.colorHex).not.toBe('#2ea44f'); expect((await getArtifactBadge(file, { publicKeyPem: keys.publicKey })).status).toBe('SEALED'); });
  test('badge required scope fails', async () => { await seal(); expect((await getArtifactBadge(file, { publicKeyPem: keys.publicKey, requiredScope: 'wrong' })).status).toBe('INVALID_SIGNATURE'); });
  test('help and version succeed', () => { expect(cli(['--help']).status).toBe(0); expect(cli(['--version']).stdout.trim()).toBe('2.5.0'); });
  test('verify exits nonzero without key, succeeds with key, rejects mutation and required signer', async () => { await seal(); expect(cli(['verify', file]).status).toBe(1); expect(cli(['verify', file], { MOONGLADE_PUBLIC_KEY_PEM: keys.publicKey }).status).toBe(0); expect(cli(['verify', file], { MOONGLADE_PUBLIC_KEY_PEM: keys.publicKey, MOONGLADE_REQUIRED_SIGNERS: 'missing' }).status).toBe(1); fs.appendFileSync(file, 'mutated'); expect(cli(['verify', file], { MOONGLADE_PUBLIC_KEY_PEM: keys.publicKey }).status).toBe(1); });
  test('refused seal exits nonzero', () => { const secret = path.join(dir, 'secret.pem'); fs.writeFileSync(secret, 'synthetic'); expect(cli(['seal-provisional', secret], { MOONGLADE_PRIVATE_KEY_PEM: keys.privateKey, MOONGLADE_SIGNER: 'synthetic' }).status).toBe(1); });
  test('moves refuse destination files and orphan sidecars without data loss', async () => { const destination = path.join(dir, 'destination.md'); fs.writeFileSync(destination, 'existing'); await expect(moveArtifactWithAttestation(file, destination)).rejects.toThrow(/exists/); expect(fs.readFileSync(destination, 'utf8')).toBe('existing'); fs.unlinkSync(destination); fs.writeFileSync(destination + '.provenance.json', '{}'); await expect(moveArtifactWithAttestation(file, destination)).rejects.toThrow(/exists/); expect(fs.readFileSync(file, 'utf8')).toBe('original\n'); });
  test('unsigned move succeeds without carrying stale scope', async () => { const destination = path.join(dir, 'destination.md'); const result = await moveArtifactWithAttestation(file, destination); expect(result.attestationMoved).toBe(false); expect(fs.readFileSync(destination, 'utf8')).toBe('original\n'); expect(fs.existsSync(file)).toBe(false); });
  test('move rolls back exclusive destination link when source removal fails', async () => { const promises = require('fs/promises'); const unlink = jest.spyOn(promises, 'unlink').mockRejectedValueOnce(new Error('synthetic failure')); const destination = path.join(dir, 'destination.md'); try { await expect(moveArtifactWithAttestation(file, destination)).rejects.toThrow(/synthetic/); expect(fs.existsSync(file)).toBe(true); expect(fs.existsSync(destination)).toBe(false); } finally { unlink.mockRestore(); } });
});
describe('proof validation', () => {
  test.each(['artifact', 'algorithm', 'leaf_index', 'tree_size', 'artifact_sha256'])('modified proof %s fails', key => {
    const registry = { 'one.md': { sha256: 'a'.repeat(64) }, 'two.md': { sha256: 'b'.repeat(64) } };
    const proof = inclusionProof(registry, 'one.md'); proof[key] = key === 'leaf_index' ? 999 : key === 'tree_size' ? 0 : 'forged';
    expect(verifyProof(proof, merkleRoot(registry))).toBe(false);
  });
  test('caller expected artifact is bound and odd-size paths validate', () => {
    for (let n = 1; n <= 19; n++) {
      const registry = Object.fromEntries(Array.from({ length: n }, (_, i) => ['f' + i, { sha256: crypto.createHash('sha256').update('' + i).digest('hex') }]));
      for (const [name, entry] of Object.entries(registry)) { const proof = inclusionProof(registry, name); expect(verifyProof(proof, merkleRoot(registry), { path: name, sha256: entry.sha256 })).toBe(true); expect(verifyProof(proof, merkleRoot(registry), { path: 'wrong', sha256: entry.sha256 })).toBe(false); }
    }
  });
});
describe('filesystem boundary', () => {
  test('vault rejects directory junction escape on Windows and symlink on POSIX', async () => {
    const external = fs.mkdtempSync(path.join(os.tmpdir(), 'external-release-')); fs.writeFileSync(path.join(external, 'outside.md'), 'outside');
    const link = path.join(dir, 'escape');
    try { fs.symlinkSync(external, link, process.platform === 'win32' ? 'junction' : 'dir'); await expect(new ProvenanceVault(dir).scanAndAudit()).rejects.toThrow(/Symbolic links/); }
    finally { if (fs.existsSync(link)) fs.unlinkSync(link); fs.rmSync(external, { recursive: true, force: true }); }
  });
});

test('stdio MCP retains request IDs and advertises only the read-only surface', async () => {
  const child = cp.spawn(process.execPath, [path.resolve(__dirname, '../dist/mcp.js')], { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; const result = new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill(); reject(Error('stdio timeout')); }, 5000); child.stdout.on('data', c => { output += c; if (output.trim().split('\n').length >= 5) { clearTimeout(timer); child.kill(); resolve(output); } }); child.on('error', reject); });
  child.stdin.write([
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
    JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    JSON.stringify({ jsonrpc: '2.0', id: 'bad-args', method: 'tools/call', params: { name: 'verify_artifact_provenance', arguments: { file_path: 42 } } }),
    JSON.stringify({ jsonrpc: '2.0', id: 'removed', method: 'tools/call', params: { name: 'seal_canonical_epoch', arguments: {} } }),
    '{invalid json'
  ].join('\n') + '\n');
  const messages = (await result).trim().split('\n').map(JSON.parse);
  expect(messages.find(r => r.id === 1).result.serverInfo.version).toBe('2.5.0');
  expect(messages.find(r => r.id === 2).result.tools.map(t => t.name).sort()).toEqual(['assert_gate_status', 'audit_vault_merkle_root', 'verify_artifact_provenance']);
  expect(messages.find(r => r.id === 'bad-args').result.isError).toBe(true);
  expect(messages.find(r => r.id === 'removed').result.isError).toBe(true);
  expect(messages.find(r => r.id === null).error.code).toBe(-32700);
});
