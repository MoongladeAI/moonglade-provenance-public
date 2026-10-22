/**
 * Bad quorum / drift configuration must fail closed (QA B1, B2).
 * A single host reaches L3 only when quorumThreshold is explicitly a positive integer 1; every
 * other odd value leaves the default of 2 (or, for impossible values, no consensus at all), and
 * a NaN drift limit must not switch the drift check off.
 */

const { EventEmitter } = require('events');
const https = require('https');
const crypto = require('crypto');
const { concurrentDegradingTimestamp, resolveNetworkConsensus, EndpointCircuitBreaker } = require('../dist/index.js');

const NOW = Date.UTC(2026, 9, 22, 12, 0, 0);
const probe = (server, ms) => ({
  tier: 'L3_NETWORK_CONSENSUS', method: 'HTTP_DATE', server, status: 'SUCCESS',
  timestamp_iso: new Date(ms).toISOString()
});
const one = [probe('a.test', NOW)];
const two = [probe('a.test', NOW), probe('b.test', NOW + 1000)];
const dayApart = [probe('a.test', NOW), probe('b.test', NOW + 24 * 3600 * 1000)];

describe('quorumThreshold: only an explicit integer 1 lets a single host through', () => {
  test.each([0, -1, -100, 0.5, 1e-9, NaN, '1', null, {}])('a single host with quorumThreshold %p is not consensus', (q) => {
    expect(resolveNetworkConsensus(one, q)).toBeNull();
  });

  test('explicit 1 still works, and so does the default', () => {
    expect(resolveNetworkConsensus(one, 1).server).toBe('consensus(a.test)');
    expect(resolveNetworkConsensus(one)).toBeNull();
    expect(resolveNetworkConsensus(two).server).toBe('consensus(a.test+b.test)');
  });

  test('a fractional threshold rounds UP, never down', () => {
    expect(resolveNetworkConsensus(two, 2.5)).toBeNull(); // needs 3
    expect(resolveNetworkConsensus([...two, probe('c.test', NOW)], 2.5)).not.toBeNull();
    expect(resolveNetworkConsensus(one, 1.5)).toBeNull(); // needs 2
  });

  test('an impossible threshold (Infinity) can never be met', () => {
    const many = ['a', 'b', 'c', 'd', 'e'].map(h => probe(`${h}.test`, NOW));
    expect(resolveNetworkConsensus(many, Infinity)).toBeNull();
  });
});

describe('maxDriftMs: a NaN or negative limit does not disable the check', () => {
  test.each([NaN, -1, -3000, Infinity, undefined, null, '3000'])('hosts a day apart are not consensus with maxDriftMs %p', (d) => {
    expect(resolveNetworkConsensus(dayApart, 2, d)).toBeNull();
  });

  test('a sane limit still decides', () => {
    expect(resolveNetworkConsensus(two, 2, 3000)).not.toBeNull();
    expect(resolveNetworkConsensus(two, 2, 999)).toBeNull();
    expect(resolveNetworkConsensus(two, 2, 1000)).not.toBeNull();
  });
});

describe('the same guards hold end to end', () => {
  const digest = crypto.createHash('sha256').update('guards').digest();
  let script;
  beforeEach(() => {
    script = {};
    jest.spyOn(https, 'request').mockImplementation((url, _o, cb) => {
      const host = String(url).replace(/^https:\/\//, '');
      const req = new EventEmitter();
      req.destroy = () => {};
      req.end = () => setImmediate(() => (script[host] ? cb({ headers: { date: script[host] } }) : req.emit('error', new Error('x'))));
      return req;
    });
  });
  afterEach(() => jest.restoreAllMocks());
  const opts = (extra) => ({ primaryEndpoints: [], fallbackEndpoints: [], timeoutMs: 200, circuitBreaker: new EndpointCircuitBreaker(), ...extra });

  test.each([0, -1, 0.5, NaN])('specifiedServer with quorumThreshold %p is L4', async (q) => {
    script = { 'a.test': new Date(NOW).toUTCString() };
    const r = await concurrentDegradingTimestamp(digest, opts({ networkEndpoints: ['a.test'], specifiedServer: 'a.test', quorumThreshold: q }));
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });

  test.each([NaN, -1])('two hosts a day apart are L4 with maxDriftMs %p', async (d) => {
    script = { 'a.test': new Date(NOW).toUTCString(), 'b.test': new Date(NOW + 24 * 3600 * 1000).toUTCString() };
    const r = await concurrentDegradingTimestamp(digest, opts({ networkEndpoints: ['a.test', 'b.test'], maxDriftMs: d }));
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });
});

describe('malformed probes do not throw (QA N7)', () => {
  test('a probe with no server is ignored', () => {
    const bad = { tier: 'L3_NETWORK_CONSENSUS', method: 'HTTP_DATE', status: 'SUCCESS', timestamp_iso: new Date(NOW).toISOString() };
    expect(() => resolveNetworkConsensus([bad, ...two])).not.toThrow();
    expect(resolveNetworkConsensus([bad, ...two]).server).toBe('consensus(a.test+b.test)');
  });
});
