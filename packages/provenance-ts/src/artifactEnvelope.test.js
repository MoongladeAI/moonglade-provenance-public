const crypto = require('crypto');
const { artifactId, createArtifactEnvelope, validateArtifactEnvelope } = require('../dist/index.js');

test('artifact identity is raw-byte SHA-256', () => {
  const bytes = Buffer.from([0, 255, 10, 42]);
  expect(artifactId(bytes)).toBe(`sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`);
});

test('creates and validates an envelope with independent evidence dimensions', () => {
  const envelope = createArtifactEnvelope({
    bytes: Buffer.from([1, 2, 3]), artifact_type: 'image', canonical_bytes: 'sha256:abc', created_at: new Date().toISOString(),
    parents: [], attestations: [], status: 'signed',
    evidence: { integrity: 'valid', signature: 'provisional', timestamp: 'none', scope: 'valid' },
    generator: { agent: 'Codex' }
  });
  expect(validateArtifactEnvelope(envelope)).toBe(true);
  expect(envelope.artifact_id).toMatch(/^sha256:[0-9a-f]{64}$/);
});

test('rejects a malformed or overclaimed envelope', () => {
  expect(validateArtifactEnvelope({ format: 'moonglade-artifact-envelope-v1', artifact_id: 'sha256:00', status: 'published' })).toBe(false);
});
