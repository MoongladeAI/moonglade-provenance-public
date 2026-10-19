const fs = require('fs');
const os = require('os');
const path = require('path');
const { ProvenanceEngine, processArtifact, moveArtifactWithAttestation } = require('../dist/index.js');

let tmp;
beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-hook-')); });
afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

test('observes a safe artifact without writing a sidecar', async () => {
  const file = path.join(tmp, 'note.md'); fs.writeFileSync(file, 'hello\r\n');
  const result = await processArtifact(file);
  expect(result.skipped).toBe(false);
  expect(result.sidecar.sha256_at_last_write).toBeTruthy();
  expect(fs.existsSync(`${file}.provenance.json`)).toBe(false);
});

test('provisionally seals with generator metadata', async () => {
  const file = path.join(tmp, 'note.md'); fs.writeFileSync(file, 'hello\n');
  const keys = ProvenanceEngine.generateEd25519KeyPair();
  const result = await processArtifact(file, { action: 'seal-provisional', vaultRoot: tmp, privateKeyPem: keys.privateKey, signerIdentity: 'synthetic-signer', generator: { agent: 'Codex' } });
  expect(result.sidecar.status).toBe('provisional');
  expect(result.sidecar.generator.agent).toBe('Codex');
  expect((await ProvenanceEngine.verifyDocument(file, keys.publicKey)).verified).toBe(true);
});

test('skips private material and excluded directories', async () => {
  const key = path.join(tmp, 'secret.pem'); fs.writeFileSync(key, 'secret');
  const node = path.join(tmp, 'node_modules'); fs.mkdirSync(node); const dep = path.join(node, 'x.md'); fs.writeFileSync(dep, 'x');
  expect((await processArtifact(key)).skipped).toBe(true);
  expect((await processArtifact(dep)).skipped).toBe(true);
});

test('refuses attested moves until the caller explicitly reseals a destination', async () => {
  const source = path.join(tmp, 'old.md'); const destination = path.join(tmp, 'new.md');
  fs.writeFileSync(source, 'hello\n');
  const keys = ProvenanceEngine.generateEd25519KeyPair();
  await processArtifact(source, { action: 'seal-provisional', vaultRoot: tmp, privateKeyPem: keys.privateKey, signerIdentity: 'synthetic-signer' });
  await expect(moveArtifactWithAttestation(source, destination)).rejects.toThrow(/explicitly reseal/);
  expect(fs.existsSync(source)).toBe(true);
  expect(fs.existsSync(`${source}.provenance.json`)).toBe(true);
  expect(fs.existsSync(destination)).toBe(false);
});
