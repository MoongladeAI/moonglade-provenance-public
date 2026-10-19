const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const { fixture } = require('./synthetic-timestamp.fixture.cjs');
const { verifyTimeStampToken, validateTimeStampResp, queryTsa, ProvenanceEngine: E } = require('../dist');
let good;
beforeAll(async () => { good = await fixture(); });
test('genuine signature and imprint without anchors are integrity-only', async () => { const r = await verifyTimeStampToken(good.token, good.doc); expect(r.verified).toBe(true); expect(r.trusted).toBe(false); expect(r.trust).toBe('INTEGRITY_ONLY'); });
test('explicit CA anchor establishes chain at token time', async () => { const r = await verifyTimeStampToken(good.token, good.doc, { trustAnchors: [good.pem] }); expect(r.verified).toBe(true); expect(r.trusted).toBe(true); expect(r.genTime).toBe('2026-10-18T12:00:00.000Z'); });
test('self-signed TSA is never implicitly trusted', async () => { const self = await fixture({ selfSigned: true }); const r = await verifyTimeStampToken(self.token, self.doc); expect(r.trust).toBe('INTEGRITY_ONLY'); expect(r.trusted).toBe(false); expect((await verifyTimeStampToken(self.token, self.doc, { trustAnchors: [good.pem] })).verified).toBe(false); });
test('missing or wrong caller anchors fail', async () => { const unrelated = await fixture(); for (const trustAnchors of [[], [unrelated.pem], ['malformed']]) expect((await verifyTimeStampToken(good.token, good.doc, { trustAnchors })).verified).toBe(false); });
test.each(['badEss', 'badEku', 'badKu', 'expired', 'noncriticalEku'])('rejects %s certificate/token', async name => { const f = await fixture({ [name]: true }); expect((await verifyTimeStampToken(f.token, f.doc)).verified).toBe(false); });
test('wrong imprint and malformed expected digest fail', async () => { expect((await verifyTimeStampToken(good.token, Buffer.from('wrong'))).verified).toBe(false); expect((await verifyTimeStampToken(good.token, good.doc, { expectedDigest: Buffer.alloc(2) })).verified).toBe(false); });
test('extra bytes and oversized token fail', async () => { for (const token of [Buffer.concat([good.token, Buffer.from([0])]), Buffer.alloc(512 * 1024 + 1)]) expect((await verifyTimeStampToken(token, good.doc)).verified).toBe(false); });
test('sidecar time edits do not override token time and anchors remain caller supplied', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'token-binding-')); const file = path.join(dir, 'doc.md'); fs.writeFileSync(file, good.doc); const keys = E.generateEd25519KeyPair();
  try {
    const sidecar = await E.sealDocument(file, keys.privateKey, 'synthetic');
    sidecar.attestations.push({ method: 'rfc3161', token_b64: good.token.toString('base64'), tsa_time: '1900-01-01T00:00:00Z', tier: 'L1_CRYPTO_PRIMARY', trustAnchors: [good.pem] });
    fs.writeFileSync(file + '.provenance.json', JSON.stringify(sidecar));
    const r = await E.verifyDocument(file, keys.publicKey); expect(r.verified).toBe(true); expect(r.timestamp).toBe('2026-10-18T12:00:00.000Z'); expect(r.timestampTier).toBe('INTEGRITY_ONLY'); expect(r.timestampVerified).toBe(false);
    const anchored = await E.verifyDocument(file, keys.publicKey, { timestampTrustAnchors: [good.pem] }); expect(anchored.timestampTier).toBe('ANCHORED'); expect(anchored.timestampVerified).toBe(true);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('structural validation compares actual TSTInfo imprint and nonce', () => {
  const p = require('pkijs'); const ci = p.ContentInfo.fromBER(good.token); const resp = new p.TimeStampResp({ status: new p.PKIStatusInfo({ status: 0 }), timeStampToken: ci }); const bytes = Buffer.from(resp.toSchema().toBER(false));
  expect(validateTimeStampResp(bytes, { expectedDigest: crypto.createHash('sha256').update(good.doc).digest() }).valid).toBe(true);
  expect(validateTimeStampResp(bytes, { expectedDigest: Buffer.alloc(32) }).valid).toBe(false);
  expect(validateTimeStampResp(bytes, { expectedNonce: 42n }).valid).toBe(false);
});
test('network response size and absolute deadline are bounded', async () => {
  const server = http.createServer((req, res) => { if (req.url === '/large') { res.end(Buffer.alloc(512 * 1024 + 1)); } else { const timer = setInterval(() => res.write('x'), 10); res.on('close', () => clearInterval(timer)); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + server.address().port;
  try { await expect(queryTsa(url + '/large', Buffer.from('request'), 1000)).rejects.toThrow(/size limit|aborted/); await expect(queryTsa(url + '/slow', Buffer.from('request'), 100)).rejects.toThrow(/deadline/); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
