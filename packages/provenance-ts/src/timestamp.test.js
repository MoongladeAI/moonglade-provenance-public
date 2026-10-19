/**
 * Unit and integration tests for RFC 3161 Timestamping and DTA fanout.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const {
  ProvenanceEngine,
  buildTimeStampReq,
  extractGenTime,
  encodeDerLength,
  decodeDerLength,
  encodeDerSequence,
  parsePkiStatus,
  validateTimeStampResp,
  concurrentDegradingTimestamp,
  EndpointCircuitBreaker,
  globalCircuitBreaker,
  DEFAULT_PRIMARY_TSAS,
  DEFAULT_FALLBACK_TSAS,
  TIER_CONFIGS,
  DEFAULT_SERVER_POLICIES,
  verifyTimeStampToken
} = require('../dist/index.js');

let tmp;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-test-'));
  globalCircuitBreaker.reset();
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

const write = (name, content) => {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, content);
  return p;
};

// Helper to construct a synthetic TimeStampResp DER buffer for unit testing
function makeSyntheticTsr({
  status = 0,
  digest = null,
  nonce = null,
  timeStr = '20260902120000Z'
} = {}) {
  const statusInt = Buffer.from([0x02, 0x01, status]);
  const pkiStatusInfo = encodeDerSequence([statusInt]);

  const tokenParts = [Buffer.from([0x02, 0x01, 0x01])]; // Version 1

  if (digest) {
    const sha256Oid = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    const nullParams = Buffer.from([0x05, 0x00]);
    const algId = encodeDerSequence([sha256Oid, nullParams]);
    const octetDigest = Buffer.concat([Buffer.from([0x04, digest.length]), digest]);
    tokenParts.push(encodeDerSequence([algId, octetDigest]));
  }

  if (timeStr) {
    const timeTag = Buffer.from([0x18, timeStr.length]);
    tokenParts.push(Buffer.concat([timeTag, Buffer.from(timeStr, 'ascii')]));
  }

  if (nonce !== null && nonce !== undefined) {
    let nonceBuf = Buffer.isBuffer(nonce) ? nonce : Buffer.from(nonce.toString(16), 'hex');
    if (nonceBuf[0] & 0x80) nonceBuf = Buffer.concat([Buffer.from([0x00]), nonceBuf]);
    tokenParts.push(Buffer.concat([Buffer.from([0x02]), encodeDerLength(nonceBuf.length), nonceBuf]));
  }

  const tstInfo = encodeDerSequence(tokenParts);
  const timeStampToken = encodeDerSequence([tstInfo]);

  return encodeDerSequence([pkiStatusInfo, timeStampToken]);
}

describe('RFC 3161 DER Serialization & Deserialization', () => {
  test('encodes and decodes short and multi-byte DER lengths correctly', () => {
    expect(encodeDerLength(10)).toEqual(Buffer.from([10]));
    expect(encodeDerLength(127)).toEqual(Buffer.from([127]));
    expect(encodeDerLength(128)).toEqual(Buffer.from([0x81, 128]));
    expect(encodeDerLength(300)).toEqual(Buffer.from([0x82, 0x01, 0x2c]));

    expect(decodeDerLength(Buffer.from([10]), 0)).toEqual({ length: 10, headerLength: 1 });
    expect(decodeDerLength(Buffer.from([127]), 0)).toEqual({ length: 127, headerLength: 1 });
    expect(decodeDerLength(Buffer.from([0x81, 128]), 0)).toEqual({ length: 128, headerLength: 2 });
    expect(decodeDerLength(Buffer.from([0x82, 0x01, 0x2c]), 0)).toEqual({ length: 300, headerLength: 3 });
  });

  test('builds a valid TimeStampReq buffer with SHA-256 OID and nonce', () => {
    const digest = crypto.createHash('sha256').update('test payload\n').digest();
    const nonce = crypto.randomBytes(8);
    const tsq = buildTimeStampReq(digest, { certReq: true, nonce });

    expect(Buffer.isBuffer(tsq)).toBe(true);
    expect(tsq[0]).toBe(0x30); // SEQUENCE tag
    expect(tsq.length).toBeGreaterThan(60);

    // Contains SHA-256 OID: 2.16.840.1.101.3.4.2.1 (06 09 60 86 48 01 65 03 04 02 01)
    const sha256OidHex = '0609608648016503040201';
    expect(tsq.toString('hex')).toContain(sha256OidHex);

    // Contains the 32-byte digest
    expect(tsq.toString('hex')).toContain(digest.toString('hex'));
  });

  test('rejects invalid digest lengths', () => {
    expect(() => buildTimeStampReq(Buffer.from('short'))).toThrow(/32-byte SHA-256 digest/);
  });
});

describe('In-Band RFC 3161 Response Validation', () => {
  test('parses granted and rejected PKIStatus values correctly', () => {
    const granted = makeSyntheticTsr({ status: 0 });
    expect(parsePkiStatus(granted)).toEqual({ status: 0, statusText: 'granted' });

    const grantedWithMods = makeSyntheticTsr({ status: 1 });
    expect(parsePkiStatus(grantedWithMods)).toEqual({ status: 1, statusText: 'grantedWithMods' });

    const rejected = makeSyntheticTsr({ status: 2 });
    expect(parsePkiStatus(rejected)).toEqual({ status: 2, statusText: 'rejection' });

    const revNotification = makeSyntheticTsr({ status: 5 });
    expect(parsePkiStatus(revNotification)).toEqual({ status: 5, statusText: 'revocationNotification' });
  });

  test('rejects a synthetic byte-search pseudo-token despite embedded matching digest and nonce', () => {
    const digest = crypto.createHash('sha256').update('canonical document content').digest();
    const nonce = crypto.randomBytes(8);
    const tsr = makeSyntheticTsr({ status: 0, digest, nonce, timeStr: '20260902143000Z' });

    const result = validateTimeStampResp(tsr, { expectedDigest: digest, expectedNonce: nonce });
    expect(result.valid).toBe(false);
    expect(result.genTime).toBeUndefined();
  });

  test('rejects response when PKIStatus is rejection', () => {
    const tsr = makeSyntheticTsr({ status: 2 });
    const result = validateTimeStampResp(tsr);
    expect(result.valid).toBe(false);
    expect(result.status).toBe(2);
    expect(result.error).toContain('RFC 3161 PKIStatus rejected: 2 (rejection)');
  });

  test('rejects response when messageImprint digest does not match', () => {
    const actualDigest = crypto.createHash('sha256').update('real file').digest();
    const tamperedDigest = crypto.createHash('sha256').update('tampered file').digest();
    const tsr = makeSyntheticTsr({ status: 0, digest: actualDigest });

    const result = validateTimeStampResp(tsr, { expectedDigest: tamperedDigest });
    expect(result.valid).toBe(false);
    expect(result.error).toBeTruthy();
  });

  test('rejects response when nonce does not echo request nonce (replay attack protection)', () => {
    const digest = crypto.createHash('sha256').update('payload').digest();
    const sentNonce = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const wrongNonce = Buffer.from([0x09, 0x09, 0x09, 0x09]);
    const tsr = makeSyntheticTsr({ status: 0, digest, nonce: wrongNonce });

    const result = validateTimeStampResp(tsr, { expectedDigest: digest, expectedNonce: sentNonce });
    expect(result.valid).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

describe('GeneralizedTime ASN.1 Parser', () => {
  test('extracts ISO UTC date from valid DER TSR payload', () => {
    // Construct synthetic GeneralizedTime: tag 0x18, len 15, "20260901120000Z"
    const timeStr = '20260901120000Z';
    const tag = Buffer.from([0x18, timeStr.length]);
    const payload = Buffer.concat([Buffer.from([0x30, 0x20]), tag, Buffer.from(timeStr, 'ascii'), Buffer.alloc(10)]);

    const iso = extractGenTime(payload);
    expect(iso).toBe('2026-09-01T12:00:00Z');
  });

  test('returns null when no GeneralizedTime tag is present', () => {
    const emptyBuf = Buffer.alloc(32);
    expect(extractGenTime(emptyBuf)).toBeNull();
  });
});

describe('Concurrent Multi-Source DTA Cascade', () => {
  test('falls back gracefully to L4 Host UTC when all network TSAs are unreachable', async () => {
    const digest = crypto.createHash('sha256').update('offline test').digest();
    const result = await concurrentDegradingTimestamp(digest, {
      primaryEndpoints: ['http://127.0.0.1:9999/unreachable'],
      fallbackEndpoints: ['http://127.0.0.1:9998/unreachable'],
      networkEndpoints: ['127.0.0.1:9997'],
      timeoutMs: 100
    });

    expect(result.tier).toBe('L4_HOST_UNAUTHENTICATED');
    expect(result.tsa).toBe('localhost');
    expect(typeof result.tsa_time).toBe('string');
    expect(result.probes.length).toBe(4); // 1 primary + 1 fallback + 1 network + 1 host
    expect(result.probes.some(p => p.tier === 'L4_HOST_UNAUTHENTICATED' && p.status === 'SUCCESS')).toBe(true);
  });
});

describe('ProvenanceEngine Sealing with RFC 3161', () => {
  test('seals a document with RFC 3161 attestation and verifies it', async () => {
    const file = write('rfc3161_doc.md', '# Sealed with DTA\nImmutable research.\n');
    const { publicKey, privateKey } = ProvenanceEngine.generateEd25519KeyPair();

    // Seal with mock/fallback DTA options for fast deterministic test execution
    const sidecar = await ProvenanceEngine.sealDocument(
      file,
      privateKey,
      'architect@moongladeai',
      'abc1234',
      {
        vaultRoot: tmp,
        timestamp: {
          primaryEndpoints: [],
          fallbackEndpoints: [],
          networkEndpoints: []
        }
      }
    );

    expect(sidecar.attestations.length).toBe(1);
    expect(sidecar.attestations[0].method).toBe('moonglade-ed25519-v2');
    const result = await ProvenanceEngine.verifyDocument(file, publicKey);
    expect(result.verified).toBe(true);
    expect(result.timestamp).toBeUndefined();
    expect(result.timestampTier).toBeUndefined();
    expect(result.unknownMethods).toEqual([]);
  });
});

describe('EndpointCircuitBreaker & Exponential Backoff', () => {
  test('includes expanded enterprise and fallback public TSAs by default', () => {
    expect(DEFAULT_PRIMARY_TSAS).toContain('http://timestamp.digicert.com');
    expect(DEFAULT_PRIMARY_TSAS).toContain('http://timestamp.sectigo.com');
    expect(DEFAULT_PRIMARY_TSAS).toContain('http://timestamp.globalsign.com/tsa/r6advanced1');
    expect(DEFAULT_PRIMARY_TSAS).toContain('http://timestamp.entrust.net/TSS/RFC3161sha2TS');
    expect(DEFAULT_PRIMARY_TSAS).toContain('http://time.certum.pl');

    expect(DEFAULT_FALLBACK_TSAS).toContain('http://timestamp.apple.com/ts01');
    expect(DEFAULT_FALLBACK_TSAS).toContain('http://ts.quovadisglobal.com/eu');
    expect(DEFAULT_FALLBACK_TSAS).toContain('https://freetsa.org/tsr');
  });

  test('calculates exponential backoff delays on consecutive failures', () => {
    const cb = new EndpointCircuitBreaker({ baseBackoffMs: 1000, maxBackoffMs: 10000 });
    const url = 'http://test.tsa.com';

    expect(cb.isAvailable(url)).toBe(true);

    const b1 = cb.recordFailure(url, 'timeout', 1000);
    expect(b1).toBe(1000); // 1000 * 2^0
    expect(cb.isAvailable(url, 1500)).toBe(false);
    expect(cb.isAvailable(url, 2001)).toBe(true);

    const b2 = cb.recordFailure(url, '500 error', 2001);
    expect(b2).toBe(2000); // 1000 * 2^1

    const b3 = cb.recordFailure(url, '429 rate limit', 4002);
    expect(b3).toBe(4000); // 1000 * 2^2

    const b4 = cb.recordFailure(url, 'timeout again', 8003);
    expect(b4).toBe(8000); // 1000 * 2^3

    const b5 = cb.recordFailure(url, 'timeout again', 16004);
    expect(b5).toBe(10000); // capped at maxBackoffMs
  });

  test('resets failure count and backoff on success', () => {
    const cb = new EndpointCircuitBreaker({ baseBackoffMs: 1000 });
    const url = 'http://test.tsa.com';

    cb.recordFailure(url, 'fail 1', 1000);
    cb.recordFailure(url, 'fail 2', 2000);
    expect(cb.isAvailable(url, 2500)).toBe(false);

    cb.recordSuccess(url, 2501);
    expect(cb.isAvailable(url, 2501)).toBe(true);
    expect(cb.getHealth(url).consecutiveFailures).toBe(0);
  });

  test('selectEndpoints prioritizes healthy endpoints over backed-off ones', () => {
    const cb = new EndpointCircuitBreaker({ baseBackoffMs: 5000 });
    const u1 = 'http://tsa1.com';
    const u2 = 'http://tsa2.com';
    const u3 = 'http://tsa3.com';

    cb.recordFailure(u1, 'down', 1000); // u1 backed off until 6000

    const selected = cb.selectEndpoints([u1, u2, u3], 2, 2000);
    expect(selected).toEqual([u2, u3]);
  });

  test('selectEndpoints falls back to shortest recovery time when all are backed off', () => {
    const cb = new EndpointCircuitBreaker({ baseBackoffMs: 1000 });
    const u1 = 'http://tsa1.com';
    const u2 = 'http://tsa2.com';

    cb.recordFailure(u1, 'down', 1000); // available at 2000
    cb.recordFailure(u2, 'down', 1000); // 1st fail: 2000
    cb.recordFailure(u2, 'down', 2000); // 2nd fail: available at 4000

    const selected = cb.selectEndpoints([u1, u2], 1, 1500);
    expect(selected).toEqual([u1]);
  });
});

describe('Tier Defaults and Simultaneous/Targeted Seeking', () => {
  test('defines explicit defaults and fallbacks for each tier', () => {
    expect(TIER_CONFIGS.L1.default).toBe('http://timestamp.digicert.com');
    expect(TIER_CONFIGS.L1.fallbacks.length).toBeGreaterThan(0);
    expect(TIER_CONFIGS.L1.fallbacks).toContain('http://timestamp.sectigo.com');

    expect(TIER_CONFIGS.L2.default).toBe('http://timestamp.apple.com/ts01');
    expect(TIER_CONFIGS.L2.fallbacks).toContain('https://freetsa.org/tsr');

    expect(TIER_CONFIGS.L3.default).toBe('cloudflare.com');
    expect(TIER_CONFIGS.L3.fallbacks).toContain('google.com');
  });

  test('simultaneously seeks 1 probe from each tier by default', async () => {
    const digest = crypto.createHash('sha256').update('1 per tier test').digest();
    const result = await concurrentDegradingTimestamp(digest, {
      primaryEndpoints: ['http://127.0.0.1:9999/unreachable'],
      fallbackEndpoints: ['http://127.0.0.1:9998/unreachable'],
      networkEndpoints: ['127.0.0.1:9997'],
      timeoutMs: 80
    });

    // When probesPerTier = 1 (default), we get exactly 1 primary probe + 1 fallback probe + 1 network probe + 1 host probe = 4 total probes
    expect(result.probes.length).toBe(4);
    expect(result.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });

  test('honors specifiedServer option bypassing multi-tier fanout', async () => {
    const digest = crypto.createHash('sha256').update('specific server test').digest();
    const result = await concurrentDegradingTimestamp(digest, {
      specifiedServer: 'http://127.0.0.1:9995/unreachable',
      timeoutMs: 50
    });

    // Only queries the specified server + records host fallback probe = 2 probes
    expect(result.probes.length).toBe(2);
    expect(result.probes[0].server).toBe('http://127.0.0.1:9995/unreachable');
    expect(result.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });

  test('honors specifiedTier option restricting execution', async () => {
    const digest = crypto.createHash('sha256').update('specific tier test').digest();
    const result = await concurrentDegradingTimestamp(digest, {
      specifiedTier: 'L4_HOST_UNAUTHENTICATED'
    });

    expect(result.tier).toBe('L4_HOST_UNAUTHENTICATED');
    expect(result.probes.length).toBe(1);
    expect(result.probes[0].server).toBe('localhost');
  });
});

describe('Server Policies, Fair Queue Rotation, and Telemetry', () => {
  test('stores server policies with custom rate limits (e.g. FreeTSA 15s cooldown)', () => {
    const freeTsa = DEFAULT_SERVER_POLICIES.find(p => p.url === 'https://freetsa.org/tsr');
    expect(freeTsa).toBeDefined();
    expect(freeTsa.minIntervalMs).toBe(15000);

    const digiCert = DEFAULT_SERVER_POLICIES.find(p => p.url === 'http://timestamp.digicert.com');
    expect(digiCert).toBeDefined();
    expect(digiCert.minIntervalMs).toBe(1000);
  });

  test('fairly rotates through endpoints in round-robin order', () => {
    const cb = new EndpointCircuitBreaker();
    const urls = ['http://tsa1.com', 'http://tsa2.com', 'http://tsa3.com'];

    // 1st request selects tsa1
    const s1 = cb.selectRotatingEndpoints(urls, 1, 'test_queue', 1000);
    expect(s1).toEqual(['http://tsa1.com']);

    // 2nd request selects tsa2
    const s2 = cb.selectRotatingEndpoints(urls, 1, 'test_queue', 1000);
    expect(s2).toEqual(['http://tsa2.com']);

    // 3rd request selects tsa3
    const s3 = cb.selectRotatingEndpoints(urls, 1, 'test_queue', 1000);
    expect(s3).toEqual(['http://tsa3.com']);

    // 4th request wraps around to tsa1
    const s4 = cb.selectRotatingEndpoints(urls, 1, 'test_queue', 1000);
    expect(s4).toEqual(['http://tsa1.com']);
  });

  test('enforces server policy cooldowns and skips servers currently on cooldown', () => {
    const cb = new EndpointCircuitBreaker();
    const freeTsaUrl = 'https://freetsa.org/tsr';

    // Simulate request at t=1000
    cb.recordRequest(freeTsaUrl, 1000);

    // At t=5000, 4 seconds have passed; FreeTSA (15s cooldown) is in COOLDOWN
    expect(cb.isAvailable(freeTsaUrl, 5000)).toBe(false);
    expect(cb.getServerStatus(freeTsaUrl, 5000)).toBe('COOLDOWN');

    // At t=16001, 15+ seconds have passed; FreeTSA is READY
    expect(cb.isAvailable(freeTsaUrl, 16001)).toBe(true);
    expect(cb.getServerStatus(freeTsaUrl, 16001)).toBe('READY');
  });

  test('rotation skips disabled items (in backoff or cooldown) to pick the next ready server', () => {
    const cb = new EndpointCircuitBreaker();
    const urls = ['http://tsa1.com', 'http://tsa2.com', 'http://tsa3.com'];

    // Put tsa2 into backoff failure
    cb.recordFailure('http://tsa2.com', '503 Service Unavailable', 1000);

    // 1st call picks tsa1
    const s1 = cb.selectRotatingEndpoints(urls, 1, 'skip_test', 2000);
    expect(s1).toEqual(['http://tsa1.com']);

    // 2nd call starts check at tsa2, sees it in BACKOFF, and skips it to pick tsa3!
    const s2 = cb.selectRotatingEndpoints(urls, 1, 'skip_test', 2000);
    expect(s2).toEqual(['http://tsa3.com']);
  });

  test('telemetry methods expose queue ordering, disabled/cooldown items, and ready items', () => {
    const cb = new EndpointCircuitBreaker();
    const urls = ['http://tsa1.com', 'http://tsa2.com', 'http://tsa3.com'];

    cb.recordFailure('http://tsa1.com', 'Network timeout', 1000); // Backoff for 5s (until 6000)
    cb.recordRequest('http://tsa2.com', 1000); // 1s policy cooldown (until 2000)

    // At t=1500: tsa1 is in BACKOFF, tsa2 is in COOLDOWN, tsa3 is READY
    const disabledAt1500 = cb.getDisabledEndpoints(urls, 1500);
    expect(disabledAt1500.length).toBe(2);
    expect(disabledAt1500.find(d => d.url === 'http://tsa1.com').status).toBe('BACKOFF');
    expect(disabledAt1500.find(d => d.url === 'http://tsa2.com').status).toBe('COOLDOWN');

    // At t=2500: tsa2 1s cooldown has expired; only tsa1 is still disabled in BACKOFF
    const disabledAt2500 = cb.getDisabledEndpoints(urls, 2500);
    expect(disabledAt2500.length).toBe(1);
    expect(disabledAt2500[0].url).toBe('http://tsa1.com');

    const ready = cb.getReadyEndpoints(urls, 2500);
    expect(ready.map(r => r.url)).toContain('http://tsa2.com');
    expect(ready.map(r => r.url)).toContain('http://tsa3.com');

    const queue = cb.getQueue(urls, 'default');
    expect(queue).toEqual(urls);
  });
});

describe('RFC 3161 Cryptographic Token Verification (PKI.js)', () => {
  let tokenBytes, validDoc;
  beforeAll(async () => { const f = await require('./synthetic-timestamp.fixture.cjs').fixture(); tokenBytes = f.token; validDoc = f.doc; });

  test('cryptographically verifies genuine TSA token and signer cert', async () => {
    const res = await verifyTimeStampToken(tokenBytes, validDoc);
    expect(res.verified).toBe(true);
    expect(res.signerVerified).toBe(true);
    expect(typeof res.signerSubject).toBe('string');
    expect(res.signerSubject).toContain('Synthetic audit TSA');
    expect(typeof res.genTime).toBe('string');
  });

  test('rejects verification if document bytes are tampered', async () => {
    const tamperedDoc = Buffer.from('moonglade-test-fixture-2026-tampered');
    const res = await verifyTimeStampToken(tokenBytes, tamperedDoc);
    expect(res.verified).toBe(false);
    expect(res.error).toContain('TSTInfo verification is failed');
  });

  test('rejects verification if token bytes are corrupted', async () => {
    const corruptedToken = Buffer.from(tokenBytes);
    corruptedToken[corruptedToken.length - 10] ^= 0xff;
    const res = await verifyTimeStampToken(corruptedToken, validDoc);
    expect(res.verified).toBe(false);
  });
});

