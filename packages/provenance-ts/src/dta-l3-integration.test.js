/**
 * End-to-end DTA fanout for the L3 network tier, with https.request mocked (no network).
 *
 * Before 2.6.0 the default fanout sent ONE L3 probe (so quorum was unreachable), a single
 * specifiedServer was promoted straight to L3, duplicate hosts counted as separate
 * participants, and any string Date.parse accepted passed as an HTTP Date header.
 */

const { EventEmitter } = require('events');
const https = require('https');
const crypto = require('crypto');

const {
  concurrentDegradingTimestamp,
  resolveNetworkConsensus,
  probeNetworkTime,
  parseHttpDate,
  EndpointCircuitBreaker
} = require('../dist/index.js');

const digest = crypto.createHash('sha256').update('dta l3').digest();
const NOW = Date.UTC(2026, 9, 22, 12, 0, 0);
const http = (ms) => new Date(ms).toUTCString();

let requests;
let script; // host -> Date header string | 'ERROR' | 'NODATE'

function install() {
  requests = [];
  jest.spyOn(https, 'request').mockImplementation((url, _opts, cb) => {
    const host = String(url).replace(/^https:\/\//, '');
    requests.push(host);
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => setImmediate(() => {
      const v = script[host];
      if (v === 'ERROR' || v === undefined) {
        req.emit('error', new Error(`mock: ${host} unreachable`));
        return;
      }
      cb({ headers: v === 'NODATE' ? {} : { date: v } });
    });
    return req;
  });
}

const l3Only = (hosts, extra = {}) => ({
  primaryEndpoints: [],
  fallbackEndpoints: [],
  networkEndpoints: hosts,
  timeoutMs: 200,
  circuitBreaker: new EndpointCircuitBreaker(),
  ...extra
});

beforeEach(() => { script = {}; install(); });
afterEach(() => jest.restoreAllMocks());

describe('L3 fanout reaches consensus end to end', () => {
  test('three agreeing hosts -> three probes dispatched -> L3_NETWORK_CONSENSUS', async () => {
    script = { 'a.test': http(NOW), 'b.test': http(NOW + 1000), 'c.test': http(NOW + 2000) };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test', 'b.test', 'c.test']));
    expect(requests.sort()).toEqual(['a.test', 'b.test', 'c.test']);
    expect(r.tier).toBe('L3_NETWORK_CONSENSUS');
    expect(r.tsa).toBe('consensus(a.test+b.test+c.test)');
    expect(r.tsa_time).toBe(new Date(NOW + 1000).toISOString()); // median
  });

  test('default L3 probe count is min(3, hosts)', async () => {
    script = Object.fromEntries(['a', 'b', 'c', 'd', 'e'].map(h => [`${h}.test`, http(NOW)]));
    await concurrentDegradingTimestamp(digest, l3Only(['a.test', 'b.test', 'c.test', 'd.test', 'e.test']));
    expect(requests.length).toBe(3);

    requests.length = 0;
    script = { 'a.test': http(NOW), 'b.test': http(NOW) };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test', 'b.test']));
    expect(requests.length).toBe(2);
    expect(r.tier).toBe('L3_NETWORK_CONSENSUS');
  });

  test('two of three succeed within drift -> still L3 (quorum is 2)', async () => {
    script = { 'a.test': http(NOW), 'b.test': http(NOW + 1000), 'c.test': 'ERROR' };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test', 'b.test', 'c.test']));
    expect(r.tier).toBe('L3_NETWORK_CONSENSUS');
  });

  test('only one of three succeeds -> L4', async () => {
    script = { 'a.test': http(NOW), 'b.test': 'ERROR', 'c.test': 'NODATE' };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test', 'b.test', 'c.test']));
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
    expect(r.tsa).toBe('localhost');
  });

  test('drift above 3000 ms -> L4 (HTTP dates have 1 s resolution)', async () => {
    script = { 'a.test': http(NOW), 'b.test': http(NOW + 4000), 'c.test': http(NOW + 5000) };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test', 'b.test', 'c.test']));
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });

  test('drift of exactly 3000 ms is accepted', async () => {
    script = { 'a.test': http(NOW), 'b.test': http(NOW + 3000) };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test', 'b.test']));
    expect(r.tier).toBe('L3_NETWORK_CONSENSUS');
  });
});

describe('a single host can never be L3', () => {
  test('specifiedServer with one healthy host is not L3', async () => {
    script = { 'a.test': http(NOW) };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test'], { specifiedServer: 'a.test' }));
    expect(requests).toEqual(['a.test']);
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
    expect(r.tsa).toBe('localhost');
    // the probe stays visible as evidence, but it is not what the result is built from
    const probe = r.probes.find(p => p.server === 'a.test');
    expect(probe.status).toBe('SUCCESS');
  });

  test('only an explicit quorumThreshold of 1 allows a single-host L3', async () => {
    script = { 'a.test': http(NOW) };
    const r = await concurrentDegradingTimestamp(
      digest, l3Only(['a.test'], { specifiedServer: 'a.test', quorumThreshold: 1 }));
    expect(r.tier).toBe('L3_NETWORK_CONSENSUS');
  });

  test('a failed specifiedServer is L4', async () => {
    script = { 'a.test': 'ERROR' };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test'], { specifiedServer: 'a.test' }));
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });

  test('one reachable host in the pool is not L3 either', async () => {
    script = { 'a.test': http(NOW) };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['a.test']));
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });
});

describe('duplicate hosts are one participant', () => {
  test('the same host listed three times is probed once and cannot form quorum', async () => {
    script = { 'same.test': http(NOW) };
    const r = await concurrentDegradingTimestamp(digest, l3Only(['same.test', 'same.test', 'Same.Test.']));
    expect(requests).toEqual(['same.test']);
    expect(r.tier).toBe('L4_HOST_UNAUTHENTICATED');
  });

  test('resolveNetworkConsensus counts distinct hostnames', () => {
    const p = (server, iso) => ({ tier: 'L3_NETWORK_CONSENSUS', method: 'HTTP_DATE', server, status: 'SUCCESS', timestamp_iso: iso });
    const iso = new Date(NOW).toISOString();
    expect(resolveNetworkConsensus([p('same.example', iso), p('same.example', iso)])).toBeNull();
    expect(resolveNetworkConsensus([p('same.example', iso), p('SAME.example.', iso)])).toBeNull();
    const ok = resolveNetworkConsensus([p('same.example', iso), p('same.example', iso), p('other.example', iso)]);
    expect(ok.server).toBe('consensus(same.example+other.example)');
  });
});

describe('Date header must be an RFC 7231 HTTP-date', () => {
  test.each([
    ['IMF-fixdate', 'Thu, 22 Oct 2026 12:00:00 GMT', NOW],
    ['obsolete RFC 850', 'Thursday, 22-Oct-26 12:00:00 GMT', NOW],
    ['obsolete asctime', 'Thu Oct 22 12:00:00 2026', NOW],
  ])('accepts %s', (_n, s, ms) => {
    expect(parseHttpDate(s)).toBe(ms);
  });

  test.each([
    '2026-10-22',
    '2026-10-22T12:00:00Z',
    'Oct 22 2026',
    'Fri, 22 Oct 2026 12:00:00 GMT',      // 22 Oct 2026 is a Thursday
    'Thu, 31 Feb 2026 12:00:00 GMT',      // not a date
    'Thu, 22 Oct 2026 24:00:00 GMT',
    'Thu, 22 Oct 2026 12:00:60 GMT',
    'Thu, 22 Oct 2026 12:00:00 PST',
    'Thu, 22 Oct 2026 12:00:00',
    'thu, 22 oct 2026 12:00:00 gmt',      // case-sensitive grammar
    ' Thu, 22 Oct 2026 12:00:00 GMT',
    '',
    '1761134400',
  ])('rejects %j', (s) => {
    expect(parseHttpDate(s)).toBeNull();
  });

  test('probeNetworkTime reports ERROR for a non-HTTP-date Date header', async () => {
    script = { 'a.test': '2026-10-22' };
    const probe = await probeNetworkTime('a.test', 200);
    expect(probe.status).toBe('ERROR');
    expect(probe.timestamp_iso).toBeUndefined();
  });

  test('probeNetworkTime accepts a proper HTTP-date', async () => {
    script = { 'a.test': http(NOW) };
    const probe = await probeNetworkTime('a.test', 200);
    expect(probe.status).toBe('SUCCESS');
    expect(probe.timestamp_iso).toBe(new Date(NOW).toISOString());
  });
});
