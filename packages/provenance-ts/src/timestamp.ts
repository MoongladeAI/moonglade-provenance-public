import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';

/** RFC 3161 signature/imprint checks and optional caller-anchored chain validation.
 * Acquisition probe tiers describe routing; only verified tokens supply timestamp evidence.
 * Revocation checking is outside this implementation.
 */

export interface TSAProbeResult {
  tier: 'L1_CRYPTO_PRIMARY' | 'L2_CRYPTO_FALLBACK' | 'L3_NETWORK_CONSENSUS' | 'L4_HOST_UNAUTHENTICATED';
  method: 'RFC3161' | 'HTTP_DATE' | 'KERNEL_UTC';
  server: string;
  status: 'SUCCESS' | 'ERROR' | 'TIMEOUT';
  timestamp_iso?: string;
  token_b64?: string;
  token_bytes?: Buffer;
  error?: string;
}

export interface DTAResult {
  tier: 'INTEGRITY_ONLY' | 'L3_NETWORK_CONSENSUS' | 'L4_HOST_UNAUTHENTICATED';
  tsa?: string;
  tsa_time: string;
  token_b64?: string;
  token_bytes?: Buffer;
  probes: TSAProbeResult[];
}

export interface DTAOptions {
  /** If specified, bypasses multi-tier fanout and queries only this specific TSA server URL or network host */
  specifiedServer?: string;

  /** If specified, restricts queries to this tier only */
  specifiedTier?: 'L1_CRYPTO_PRIMARY' | 'L2_CRYPTO_FALLBACK' | 'L3_NETWORK_CONSENSUS' | 'L4_HOST_UNAUTHENTICATED';

  /**
   * Number of probes to simultaneously seek from each tier (default: 1 for the TSA tiers,
   * min(3, distinct hosts) for the L3 network tier, because one probe can never reach quorum)
   */
  probesPerTier?: number;

  /** Whether to rotate through available endpoints (default: true) */
  rotate?: boolean;

  primaryEndpoints?: string[];
  fallbackEndpoints?: string[];
  networkEndpoints?: string[];
  timeoutMs?: number;
  certReq?: boolean;
  nonce?: Buffer | bigint;
  circuitBreaker?: EndpointCircuitBreaker;
  maxParallelProbes?: number; // legacy alias for probesPerTier

  /**
   * Distinct agreeing network hosts needed for L3_NETWORK_CONSENSUS (default 2). A single host
   * is never L3 unless this is explicitly set to 1.
   */
  quorumThreshold?: number;

  /** Maximum spread between the earliest and latest L3 probe, in milliseconds (default 3000). */
  maxDriftMs?: number;
}

export interface TierEndpointConfig {
  default: string;
  fallbacks: string[];
}

export const TIER_CONFIGS: {
  L1: TierEndpointConfig;
  L2: TierEndpointConfig;
  L3: TierEndpointConfig;
} = {
  L1: {
    default: 'http://timestamp.digicert.com',
    fallbacks: [
      'http://timestamp.sectigo.com',
      'http://timestamp.globalsign.com/tsa/r6advanced1',
      'http://timestamp.entrust.net/TSS/RFC3161sha2TS',
      'http://time.certum.pl'
    ]
  },
  L2: {
    default: 'http://timestamp.apple.com/ts01',
    fallbacks: [
      'http://ts.quovadisglobal.com/eu',
      'https://freetsa.org/tsr'
    ]
  },
  L3: {
    default: 'cloudflare.com',
    fallbacks: [
      'google.com',
      'apple.com',
      'amazon.com'
    ]
  }
};

export const DEFAULT_PRIMARY_TSAS = [
  TIER_CONFIGS.L1.default,
  ...TIER_CONFIGS.L1.fallbacks
];

export const DEFAULT_FALLBACK_TSAS = [
  TIER_CONFIGS.L2.default,
  ...TIER_CONFIGS.L2.fallbacks
];

export const DEFAULT_NETWORK_HOSTS = [
  TIER_CONFIGS.L3.default,
  ...TIER_CONFIGS.L3.fallbacks
];

export interface ServerPolicy {
  url: string;
  name: string;
  tier: 'L1_CRYPTO_PRIMARY' | 'L2_CRYPTO_FALLBACK' | 'L3_NETWORK_CONSENSUS';
  /** Minimum interval in ms between consecutive requests to this endpoint (rate-limit compliance) */
  minIntervalMs: number;
}

export const DEFAULT_SERVER_POLICIES: ServerPolicy[] = [
  // Tier 1 Primary
  { url: 'http://timestamp.digicert.com', name: 'DigiCert', tier: 'L1_CRYPTO_PRIMARY', minIntervalMs: 1000 },
  { url: 'http://timestamp.sectigo.com', name: 'Sectigo', tier: 'L1_CRYPTO_PRIMARY', minIntervalMs: 1000 },
  { url: 'http://timestamp.globalsign.com/tsa/r6advanced1', name: 'GlobalSign', tier: 'L1_CRYPTO_PRIMARY', minIntervalMs: 1000 },
  { url: 'http://timestamp.entrust.net/TSS/RFC3161sha2TS', name: 'Entrust', tier: 'L1_CRYPTO_PRIMARY', minIntervalMs: 1000 },
  { url: 'http://time.certum.pl', name: 'Certum', tier: 'L1_CRYPTO_PRIMARY', minIntervalMs: 1000 },

  // Tier 2 Fallback
  { url: 'http://timestamp.apple.com/ts01', name: 'Apple', tier: 'L2_CRYPTO_FALLBACK', minIntervalMs: 1000 },
  { url: 'http://ts.quovadisglobal.com/eu', name: 'QuoVadis', tier: 'L2_CRYPTO_FALLBACK', minIntervalMs: 1000 },
  { url: 'https://freetsa.org/tsr', name: 'FreeTSA', tier: 'L2_CRYPTO_FALLBACK', minIntervalMs: 15000 }, // FreeTSA 15s policy

  // Tier 3 Network Consensus
  { url: 'cloudflare.com', name: 'Cloudflare', tier: 'L3_NETWORK_CONSENSUS', minIntervalMs: 500 },
  { url: 'google.com', name: 'Google', tier: 'L3_NETWORK_CONSENSUS', minIntervalMs: 500 }
];

export interface EndpointHealth {
  url?: string;
  name?: string;
  consecutiveFailures: number;
  nextAvailableTime: number;
  lastRequestTime?: number;
  lastSuccessTime?: number;
  lastError?: string;
}

export interface ServerStatusSnapshot {
  url: string;
  name?: string;
  status: 'READY' | 'COOLDOWN' | 'BACKOFF';
  consecutiveFailures: number;
  remainingCooldownMs: number;
  lastError?: string;
}

/**
 * Circuit breaker & Server Pool Manager.
 * Manages:
 * 1. Endpoint health and consecutive failure tracking
 * 2. Exponential backoff for failing/down servers
 * 3. Individual server policies (e.g. FreeTSA 15s rate-limit cooldown)
 * 4. Fair round-robin rotation queue ("who's next")
 * 5. Telemetry for ready vs disabled/cooldown servers
 */
export class EndpointCircuitBreaker {
  private health: Map<string, EndpointHealth> = new Map();
  private policies: Map<string, ServerPolicy> = new Map();
  private queuePointers: Map<string, number> = new Map();
  readonly baseBackoffMs: number;
  readonly maxBackoffMs: number;

  constructor(options: { baseBackoffMs?: number; maxBackoffMs?: number; policies?: ServerPolicy[] } = {}) {
    this.baseBackoffMs = options.baseBackoffMs ?? 5000;   // 5s initial backoff
    this.maxBackoffMs = options.maxBackoffMs ?? 300000;   // 5m max backoff
    const initialPolicies = options.policies || DEFAULT_SERVER_POLICIES;
    for (const p of initialPolicies) {
      this.policies.set(p.url, p);
    }
  }

  getPolicy(url: string): ServerPolicy {
    return this.policies.get(url) || {
      url,
      name: url,
      tier: 'L1_CRYPTO_PRIMARY',
      minIntervalMs: 1000
    };
  }

  setPolicy(policy: ServerPolicy): void {
    this.policies.set(policy.url, policy);
  }

  isAvailable(url: string, now = Date.now()): boolean {
    const entry = this.health.get(url);
    if (!entry) return true;
    return now >= entry.nextAvailableTime;
  }

  getServerStatus(url: string, now = Date.now()): 'READY' | 'COOLDOWN' | 'BACKOFF' {
    const entry = this.health.get(url);
    if (!entry || now >= entry.nextAvailableTime) {
      return 'READY';
    }
    if (entry.consecutiveFailures > 0) {
      return 'BACKOFF';
    }
    return 'COOLDOWN';
  }

  recordRequest(url: string, now = Date.now()): void {
    const policy = this.getPolicy(url);
    const prev = this.health.get(url) || { consecutiveFailures: 0, nextAvailableTime: 0 };
    this.health.set(url, {
      ...prev,
      url,
      name: policy.name,
      lastRequestTime: now,
      // Enforce server policy rate cooldown
      nextAvailableTime: Math.max(prev.nextAvailableTime, now + policy.minIntervalMs)
    });
  }

  recordSuccess(url: string, now = Date.now()): void {
    const policy = this.getPolicy(url);
    const prev = this.health.get(url);
    const cooldownUntil = (prev?.lastRequestTime || 0) + policy.minIntervalMs;
    this.health.set(url, {
      url,
      name: policy.name,
      consecutiveFailures: 0,
      lastSuccessTime: now,
      lastRequestTime: prev?.lastRequestTime,
      // Clear failure backoff; retain policy rate cooldown only if cooldownUntil > now
      nextAvailableTime: cooldownUntil > now ? cooldownUntil : 0
    });
  }

  recordFailure(url: string, error: string, now = Date.now()): number {
    const policy = this.getPolicy(url);
    const prev = this.health.get(url) || { consecutiveFailures: 0, nextAvailableTime: 0 };
    const consecutiveFailures = prev.consecutiveFailures + 1;
    // Exponential backoff: base * 2^(failures - 1)
    const backoffMs = Math.min(
      this.maxBackoffMs,
      this.baseBackoffMs * Math.pow(2, consecutiveFailures - 1)
    );
    this.health.set(url, {
      url,
      name: policy.name,
      consecutiveFailures,
      nextAvailableTime: now + backoffMs,
      lastError: error,
      lastRequestTime: prev.lastRequestTime,
      lastSuccessTime: prev.lastSuccessTime
    });
    return backoffMs;
  }

  getHealth(url: string): EndpointHealth | undefined {
    return this.health.get(url);
  }

  reset(): void {
    this.health.clear();
    this.queuePointers.clear();
  }

  /**
   * Return ordered candidate queue starting with "who's next".
   */
  getQueue(urls: string[], queueKey = 'default'): string[] {
    if (urls.length === 0) return [];
    const ptr = (this.queuePointers.get(queueKey) || 0) % urls.length;
    return [...urls.slice(ptr), ...urls.slice(0, ptr)];
  }

  /**
   * Return servers currently on cooldown or in failure backoff.
   */
  getDisabledEndpoints(urls: string[], now = Date.now()): ServerStatusSnapshot[] {
    return urls
      .filter(u => !this.isAvailable(u, now))
      .map(u => {
        const h = this.health.get(u)!;
        const status = this.getServerStatus(u, now);
        return {
          url: u,
          name: this.getPolicy(u).name,
          status,
          consecutiveFailures: h.consecutiveFailures,
          remainingCooldownMs: Math.max(0, h.nextAvailableTime - now),
          lastError: h.lastError
        };
      });
  }

  /**
   * Return servers currently READY to serve requests immediately.
   */
  getReadyEndpoints(urls: string[], now = Date.now()): ServerStatusSnapshot[] {
    return urls
      .filter(u => this.isAvailable(u, now))
      .map(u => {
        const h = this.health.get(u);
        return {
          url: u,
          name: this.getPolicy(u).name,
          status: 'READY',
          consecutiveFailures: h?.consecutiveFailures || 0,
          remainingCooldownMs: 0
        };
      });
  }

  /**
   * Fair rotating endpoint selection.
   * Cycles through the array in round-robin order, picking healthy/available endpoints,
   * skipping those in failure backoff or policy cooldown, and advancing the queue pointer.
   */
  selectRotatingEndpoints(urls: string[], count = 1, queueKey = 'default', now = Date.now()): string[] {
    if (urls.length === 0) return [];
    const len = urls.length;
    const currentPtr = (this.queuePointers.get(queueKey) || 0) % len;
    const selected: string[] = [];

    // 1. Scan in round-robin order starting at currentPtr for available endpoints
    let checkIdx = currentPtr;
    for (let i = 0; i < len && selected.length < count; i++) {
      const candidate = urls[checkIdx];
      if (this.isAvailable(candidate, now)) {
        selected.push(candidate);
      }
      checkIdx = (checkIdx + 1) % len;
    }

    // 2. If not enough available endpoints, pick those with shortest remaining cooldown
    if (selected.length < count) {
      const remaining = urls.filter(u => !selected.includes(u));
      remaining.sort((a, b) => {
        const ta = this.health.get(a)?.nextAvailableTime || 0;
        const tb = this.health.get(b)?.nextAvailableTime || 0;
        return ta - tb;
      });
      for (const candidate of remaining) {
        if (selected.length >= count) break;
        selected.push(candidate);
      }
    }

    // Advance queue pointer for the next request
    this.queuePointers.set(queueKey, (currentPtr + 1) % len);

    return selected;
  }

  /**
   * Prioritized selection (used for targeted or non-rotating requests).
   */
  selectEndpoints(urls: string[], maxCount = urls.length, now = Date.now()): string[] {
    return this.selectRotatingEndpoints(urls, maxCount, 'legacy', now);
  }
}

export const globalCircuitBreaker = new EndpointCircuitBreaker();

/**
 * Helper to encode ASN.1 DER length octets.
 */
export function encodeDerLength(len: number): Buffer {
  if (len < 128) {
    return Buffer.from([len]);
  }
  const octets: number[] = [];
  let temp = len;
  while (temp > 0) {
    octets.unshift(temp & 0xff);
    temp >>= 8;
  }
  return Buffer.from([0x80 | octets.length, ...octets]);
}

/**
 * Helper to wrap elements in an ASN.1 DER SEQUENCE (tag 0x30).
 */
export function encodeDerSequence(items: Buffer[]): Buffer {
  const body = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), encodeDerLength(body.length), body]);
}

/**
 * Helper to decode ASN.1 DER length octets from a buffer at a given offset.
 * Returns the parsed length and the number of octets consumed by the length header.
 */
export function decodeDerLength(buf: Buffer, offset: number): { length: number; headerLength: number } {
  if (offset >= buf.length) {
    throw new Error('Offset out of bounds reading DER length');
  }
  const first = buf[offset];
  if (first < 0x80) {
    return { length: first, headerLength: 1 };
  }
  const octetCount = first & 0x7f;
  if (offset + 1 + octetCount > buf.length) {
    throw new Error('Malformed DER length: exceeds buffer bounds');
  }
  let len = 0;
  for (let i = 0; i < octetCount; i++) {
    len = (len << 8) | buf[offset + 1 + i];
  }
  return { length: len, headerLength: 1 + octetCount };
}

export const PKI_STATUS_TEXT: Record<number, string> = {
  0: 'granted',
  1: 'grantedWithMods',
  2: 'rejection',
  3: 'waiting',
  4: 'revocationWarning',
  5: 'revocationNotification'
};

export interface ValidateTimeStampRespOptions {
  expectedDigest?: Buffer;
  expectedNonce?: Buffer | bigint;
}

export interface ValidationResultRFC3161 {
  valid: boolean;
  status: number;
  statusText: string;
  error?: string;
  genTime?: string;
}

/**
 * Parse the RFC 3161 PKIStatusInfo integer code from TimeStampResp.
 * RFC 3161 Â§2.4.2:
 *   TimeStampResp ::= SEQUENCE {
 *      status            PKIStatusInfo,
 *      timeStampToken    TimeStampToken     OPTIONAL
 *   }
 *   PKIStatusInfo ::= SEQUENCE {
 *      status        PKIStatus,
 *      statusString  PKIFreeText     OPTIONAL,
 *      failInfo      PKIFailureInfo  OPTIONAL
 *   }
 */
export function parsePkiStatus(respBuffer: Buffer): { status: number; statusText: string } {
  if (!respBuffer || respBuffer.length < 5) {
    throw new Error('Response buffer too short for RFC 3161 TimeStampResp');
  }
  if (respBuffer[0] !== 0x30) {
    throw new Error(`Expected SEQUENCE tag (0x30) at start of TimeStampResp, got 0x${respBuffer[0].toString(16)}`);
  }
  const topLen = decodeDerLength(respBuffer, 1);
  const statusInfoOffset = 1 + topLen.headerLength;
  if (statusInfoOffset >= respBuffer.length || respBuffer[statusInfoOffset] !== 0x30) {
    throw new Error(`Expected PKIStatusInfo SEQUENCE (0x30) at offset ${statusInfoOffset}`);
  }
  const statusInfoLen = decodeDerLength(respBuffer, statusInfoOffset + 1);
  const statusIntOffset = statusInfoOffset + 1 + statusInfoLen.headerLength;
  if (statusIntOffset >= respBuffer.length || respBuffer[statusIntOffset] !== 0x02) {
    throw new Error(`Expected INTEGER tag (0x02) for PKIStatus at offset ${statusIntOffset}`);
  }
  const statusIntLen = decodeDerLength(respBuffer, statusIntOffset + 1);
  const valOffset = statusIntOffset + 1 + statusIntLen.headerLength;
  if (valOffset + statusIntLen.length > respBuffer.length) {
    throw new Error('Truncated PKIStatus integer value in DER buffer');
  }
  let status = 0;
  for (let i = 0; i < statusIntLen.length; i++) {
    status = (status << 8) | respBuffer[valOffset + i];
  }
  return {
    status,
    statusText: PKI_STATUS_TEXT[status] || `unknown_status_${status}`
  };
}

/**
 * In-band RFC 3161 TimeStampResp validator.
 * Enforces:
 * 1. PKIStatusInfo is granted (0) or grantedWithMods (1)
 * 2. TimeStampToken presence
 * 3. MessageImprint digest equality (asserts TSA stamped the exact requested file hash)
 * 4. Cryptographic nonce echo match (asserts replay attack protection)
 */
export function validateTimeStampResp(respBuffer: Buffer, options: ValidateTimeStampRespOptions = {}): ValidationResultRFC3161 {
  let status = -1, statusText = 'parse_error';
  try {
    if (!respBuffer.length || respBuffer.length > 512 * 1024 || asn1js.fromBER(toArrayBuffer(respBuffer)).offset !== respBuffer.length) throw new Error('Invalid or oversized response');
    ({ status, statusText } = parsePkiStatus(respBuffer));
    if (![0, 1].includes(status)) throw new Error(`RFC 3161 PKIStatus rejected: ${status} (${statusText})`);
    const resp = pkijs.TimeStampResp.fromBER(toArrayBuffer(respBuffer));
    if (!resp.timeStampToken || resp.timeStampToken.contentType !== '1.2.840.113549.1.7.2') throw new Error('Missing CMS timestamp token');
    const signed = new pkijs.SignedData({ schema: resp.timeStampToken.content });
    if (signed.encapContentInfo.eContentType !== '1.2.840.113549.1.9.16.1.4') throw new Error('Expected TSTInfo');
    const bytes = Buffer.from(signed.encapContentInfo.eContent!.getValue());
    if (asn1js.fromBER(toArrayBuffer(bytes)).offset !== bytes.length) throw new Error('Trailing TSTInfo data');
    const info = pkijs.TSTInfo.fromBER(toArrayBuffer(bytes));
    if (options.expectedDigest && (options.expectedDigest.length !== 32 || info.messageImprint.hashAlgorithm.algorithmId !== '2.16.840.1.101.3.4.2.1' || !Buffer.from(info.messageImprint.hashedMessage.valueBlock.valueHexView).equals(options.expectedDigest))) throw new Error('TimeStampToken does not contain expected message imprint digest');
    if (options.expectedNonce !== undefined) {
      const expected = Buffer.isBuffer(options.expectedNonce) ? BigInt('0x' + (options.expectedNonce.toString('hex') || '0')) : options.expectedNonce;
      const nonce = info.nonce ? BigInt('0x' + (Buffer.from(info.nonce.valueBlock.valueHexView).toString('hex') || '0')) : undefined;
      if (nonce !== expected) throw new Error('TimeStampToken nonce does not match request nonce');
    }
    return { valid: true, status, statusText, genTime: info.genTime.toISOString() };
  } catch (error: any) { return { valid: false, status, statusText, error: error.message }; }
}

export interface TimestampTokenVerificationResult {
  verified: boolean;
  signerVerified?: boolean;
  trusted?: boolean;
  trust?: 'ANCHORED' | 'INTEGRITY_ONLY';
  signerSubject?: string;
  genTime?: string;
  error?: string;
}

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(buf.byteLength);
  const view = new Uint8Array(ab);
  view.set(buf);
  return ab;
}

/**
 * Cryptographically verifies an RFC 3161 TimeStampToken or TimeStampResp buffer using PKI.js.
 * Validates CMS SignedData signature over signedAttrs (including 0x31 SET OF re-encoding),
 * confirms message-digest matches the encapsulated TSTInfo, and asserts the stamped
 * document digest matches documentBytes.
 */
export async function verifyTimeStampToken(
  tsrBuffer: Buffer,
  documentBytes: Buffer,
  options: { trustAnchors?: string[]; expectedDigest?: Buffer } = {}
): Promise<TimestampTokenVerificationResult> {
  try {
    if (!tsrBuffer.length || tsrBuffer.length > 512 * 1024) throw new Error('Timestamp input exceeds size limit');
    const parsed = asn1js.fromBER(toArrayBuffer(tsrBuffer));
    if (parsed.offset !== tsrBuffer.length) throw new Error('Invalid or trailing timestamp DER');
    let signed: pkijs.SignedData;
    const children = (parsed.result as asn1js.Sequence).valueBlock.value;
    if (!Array.isArray(children)) throw new Error('Invalid timestamp structure');
    if (children[0] instanceof asn1js.ObjectIdentifier) {
      const ci = new pkijs.ContentInfo({ schema: parsed.result });
      if (ci.contentType !== '1.2.840.113549.1.7.2') throw new Error('Expected CMS SignedData');
      signed = new pkijs.SignedData({ schema: ci.content });
    } else {
      const resp = new pkijs.TimeStampResp({ schema: parsed.result });
      if (![0, 1].includes(resp.status.status) || !resp.timeStampToken || resp.timeStampToken.contentType !== '1.2.840.113549.1.7.2') throw new Error('Timestamp response not granted or missing token');
      signed = new pkijs.SignedData({ schema: resp.timeStampToken.content });
    }
    if (signed.signerInfos.length !== 1 || signed.encapContentInfo.eContentType !== '1.2.840.113549.1.9.16.1.4') throw new Error('Expected one TSA signer and TSTInfo content');
    const content = signed.encapContentInfo.eContent;
    if (!(content instanceof asn1js.OctetString)) throw new Error('Expected primitive DER TSTInfo octets');
    const tstBytes = Buffer.from(content.getValue());
    if (asn1js.fromBER(toArrayBuffer(tstBytes)).offset !== tstBytes.length) throw new Error('Trailing TSTInfo bytes');
    const info = pkijs.TSTInfo.fromBER(toArrayBuffer(tstBytes));
    if (info.version !== 1 || info.messageImprint.hashAlgorithm.algorithmId !== '2.16.840.1.101.3.4.2.1') throw new Error('Timestamp requires v1 SHA-256 imprint');
    const expected = options.expectedDigest || crypto.createHash('sha256').update(documentBytes).digest();
    if (expected.length !== 32 || info.messageImprint.hashedMessage.valueBlock.valueHexView.length !== 32) throw new Error('SHA-256 imprint must be 32 bytes');
    if (!Buffer.from(info.messageImprint.hashedMessage.valueBlock.valueHexView).equals(expected)) throw new Error('TSTInfo verification is failed: imprint mismatch');
    const signer = signed.signerInfos[0];
    const certificates = (signed.certificates || []).filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate);
    const cert = certificates.find(c => {
      if (signer.sid instanceof pkijs.IssuerAndSerialNumber) return c.issuer.isEqual(signer.sid.issuer) && c.serialNumber.isEqual(signer.sid.serialNumber);
      const sid: any = signer.sid;
      const value = sid.idBlock.isConstructed ? sid.valueBlock.value[0].valueBlock.valueHexView : sid.valueBlock.valueHexView;
      return crypto.createHash('sha1').update(Buffer.from(c.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)).digest().equals(Buffer.from(value));
    });
    if (!cert || !signer.signedAttrs) throw new Error('Missing TSA certificate or signed attributes');
    const attributes = signer.signedAttrs.attributes;
    const attr = (oid: string) => {
      const matches = attributes.filter(a => a.type === oid);
      if (matches.length !== 1 || matches[0].values.length !== 1) throw new Error('Missing or duplicate timestamp attribute ' + oid);
      return matches[0].values[0];
    };
    const type = attr('1.2.840.113549.1.9.3');
    if (!(type instanceof asn1js.ObjectIdentifier) || type.valueBlock.toString() !== signed.encapContentInfo.eContentType) throw new Error('Signed content type mismatch');
    const hashes: Record<string, string> = { '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' };
    const hash = hashes[signer.digestAlgorithm.algorithmId];
    if (!hash) throw new Error('Unsupported timestamp digest algorithm');
    const digest = attr('1.2.840.113549.1.9.4');
    if (!(digest instanceof asn1js.OctetString) || !Buffer.from(digest.valueBlock.valueHexView).equals(crypto.createHash(hash).update(tstBytes).digest())) throw new Error('Signed content digest mismatch');
    const certBytes = Buffer.from(cert.toSchema(true).toBER(false));
    const x509 = new crypto.X509Certificate(certBytes);
    const sigAlg = signer.signatureAlgorithm.algorithmId;
    const allowedSignatureAlgorithms: Record<string, string[]> = {
      rsa: ['1.2.840.113549.1.1.1', { sha256: '1.2.840.113549.1.1.11', sha384: '1.2.840.113549.1.1.12', sha512: '1.2.840.113549.1.1.13' }[hash]!],
      ec: [{ sha256: '1.2.840.10045.4.3.2', sha384: '1.2.840.10045.4.3.3', sha512: '1.2.840.10045.4.3.4' }[hash]!]
    };
    if (!allowedSignatureAlgorithms[x509.publicKey.asymmetricKeyType || '']?.includes(sigAlg)) throw new Error('Unsupported timestamp signature algorithm');
    const attrs = Buffer.from(signer.signedAttrs.encodedValue);
    if (!attrs.length) throw new Error('Missing signed attribute encoding');
    attrs[0] = 0x31;
    if (!crypto.verify(hash, attrs, x509.publicKey, Buffer.from(signer.signature.valueBlock.valueHexView))) throw new Error('Timestamp CMS signature failed');
    if (!Number.isFinite(info.genTime.getTime()) || info.genTime < cert.notBefore.value || info.genTime > cert.notAfter.value) throw new Error('TSA certificate invalid at token generation time');
    const eku = cert.extensions?.filter(e => e.extnID === '2.5.29.37');
    if (!eku || eku.length !== 1 || !eku[0].critical) throw new Error('TSA requires critical timestamping EKU');
    const usage = pkijs.ExtKeyUsage.fromBER(toArrayBuffer(Buffer.from(eku[0].extnValue.valueBlock.valueHexView)));
    if (usage.keyPurposes.length !== 1 || usage.keyPurposes[0] !== '1.3.6.1.5.5.7.3.8') throw new Error('TSA EKU must be timestamping only');
    const keyUsage = cert.extensions?.filter(e => e.extnID === '2.5.29.15') || [];
    if (keyUsage.length > 1) throw new Error('Duplicate TSA key usage');
    if (keyUsage.length) {
      const ku = asn1js.fromBER(toArrayBuffer(Buffer.from(keyUsage[0].extnValue.valueBlock.valueHexView))).result as asn1js.BitString;
      if (!(ku instanceof asn1js.BitString) || !(ku.valueBlock.valueHexView[0] & 0xc0)) throw new Error('TSA key usage forbids signatures');
    }
    const anchored = options.trustAnchors !== undefined;
    const essV2 = attributes.filter(a => a.type === '1.2.840.113549.1.9.16.2.47');
    // Legacy ESSCertID is accepted only for integrity-only checks. Anchored release policy requires v2.
    const ess = attr(essV2.length ? '1.2.840.113549.1.9.16.2.47' : '1.2.840.113549.1.9.16.2.12');
    const certIds = (ess as asn1js.Sequence).valueBlock.value[0] as asn1js.Sequence;
    const fields = (certIds.valueBlock.value[0] as asn1js.Sequence).valueBlock.value;
    let certHashAlgorithm = essV2.length ? 'sha256' : 'sha1';
    let index = 0;
    if (fields[0] instanceof asn1js.Sequence) {
      if (!essV2.length) throw new Error('Malformed ESSCertID');
      certHashAlgorithm = hashes[new pkijs.AlgorithmIdentifier({ schema: fields[index++] }).algorithmId];
    }
    const certHash = fields[index++];
    if (!certHashAlgorithm || !(certHash instanceof asn1js.OctetString) || !Buffer.from(certHash.valueBlock.valueHexView).equals(crypto.createHash(certHashAlgorithm).update(certBytes).digest())) throw new Error('ESS certificate hash mismatch');
    if (fields[index]) {
      const issuer = new pkijs.IssuerSerial({ schema: fields[index++] });
      if (!issuer.serialNumber.isEqual(cert.serialNumber) || !issuer.issuer.names.some(n => n.type === 4 && n.value.isEqual(cert.issuer))) throw new Error('ESS issuer/serial mismatch');
    }
    if (index !== fields.length) throw new Error('Malformed ESS certificate identifier');
    if (anchored) {
      if (!essV2.length || !options.trustAnchors?.length) throw new Error('Anchored timestamp requires ESSCertIDv2 and explicit trust anchors');
      const trustedCerts = options.trustAnchors.map(pem => {
        if (!/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----\s*$/.test(pem)) throw new Error('Malformed trust anchor PEM');
        return pkijs.Certificate.fromBER(toArrayBuffer(new crypto.X509Certificate(pem).raw));
      });
      const chain = new pkijs.CertificateChainValidationEngine({ trustedCerts, certs: [...certificates.filter(c => c !== cert), cert], checkDate: info.genTime });
      const result = await chain.verify({ passedWhenNotRevValues: true });
      if (!result.result) throw new Error('TSA chain validation failed: ' + result.resultMessage);
    }
    return { verified: true, signerVerified: true, trusted: anchored, trust: anchored ? 'ANCHORED' : 'INTEGRITY_ONLY', signerSubject: x509.subject, genTime: info.genTime.toISOString() };
  } catch (err: any) { return { verified: false, trusted: false, error: err?.message || String(err) }; }
}

/**
 * Build an RFC 3161 TimeStampReq ASN.1 DER structure.
 * RFC 3161 Â§2.4.1:
 *   TimeStampReq ::= SEQUENCE {
 *      version          INTEGER { v1(1) },
 *      messageImprint   MessageImprint,
 *      nonce            INTEGER OPTIONAL,
 *      certReq          BOOLEAN DEFAULT FALSE
 *   }
 */
export function buildTimeStampReq(sha256Digest: Buffer, options: { certReq?: boolean; nonce?: Buffer | bigint } = {}): Buffer {
  if (sha256Digest.length !== 32) {
    throw new Error(`TimeStampReq requires a 32-byte SHA-256 digest, received ${sha256Digest.length} bytes`);
  }

  const version = Buffer.from([0x02, 0x01, 0x01]); // INTEGER 1

  // AlgorithmIdentifier for SHA-256 (OID: 2.16.840.1.101.3.4.2.1) + NULL parameters
  const sha256Oid = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
  const nullParams = Buffer.from([0x05, 0x00]);
  const algId = encodeDerSequence([sha256Oid, nullParams]);

  // MessageImprint
  const octetDigest = Buffer.concat([Buffer.from([0x04, 0x20]), sha256Digest]);
  const messageImprint = encodeDerSequence([algId, octetDigest]);

  const elements = [version, messageImprint];

  // Nonce (comes before certReq in RFC 3161 Â§2.4.1)
  if (options.nonce !== undefined) {
    let nonceBuf: Buffer;
    if (Buffer.isBuffer(options.nonce)) {
      nonceBuf = options.nonce;
    } else {
      let hex = options.nonce.toString(16);
      if (hex.length % 2 !== 0) hex = '0' + hex;
      nonceBuf = Buffer.from(hex, 'hex');
    }
    // Ensure positive integer in DER (prepend 0x00 if highest bit is set)
    if (nonceBuf.length > 0 && (nonceBuf[0] & 0x80)) {
      nonceBuf = Buffer.concat([Buffer.from([0x00]), nonceBuf]);
    }
    elements.push(Buffer.concat([Buffer.from([0x02]), encodeDerLength(nonceBuf.length), nonceBuf]));
  }

  // certReq: true
  if (options.certReq !== false) {
    elements.push(Buffer.from([0x01, 0x01, 0xff]));
  }

  return encodeDerSequence(elements);
}

/**
 * Extract GeneralizedTime (tag 0x18) from ASN.1 DER TimeStampResp buffer.
 * Returns ISO 8601 formatted string or null if not found.
 */
export function extractGenTime(tsrBuffer: Buffer): string | null {
  for (let i = 0; i < tsrBuffer.length - 16; i++) {
    if (tsrBuffer[i] === 0x18) {
      const len = tsrBuffer[i + 1];
      if (len >= 13 && len <= 24 && i + 2 + len <= tsrBuffer.length) {
        const str = tsrBuffer.slice(i + 2, i + 2 + len).toString('ascii');
        // Matches YYYYMMDDHHMMSS...Z
        if (/^\d{14}/.test(str)) {
          const year = str.slice(0, 4);
          const month = str.slice(4, 6);
          const day = str.slice(6, 8);
          const hour = str.slice(8, 10);
          const min = str.slice(10, 12);
          const sec = str.slice(12, 14);
          return `${year}-${month}-${day}T${hour}:${min}:${sec}Z`;
        }
      }
    }
  }
  return null;
}

/**
 * Execute HTTP POST query to an RFC 3161 TSA endpoint.
 */
export function queryTsa(tsaUrl: string, tsqBuffer: Buffer, timeoutMs = 5000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const url = new URL(tsaUrl);
    if (!['http:', 'https:'].includes(url.protocol) || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) return reject(new Error('Invalid TSA URL or timeout'));
    const req = (url.protocol === 'https:' ? https : http).request(url, { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query', 'Content-Length': tsqBuffer.length } });
    const timer = setTimeout(() => req.destroy(new Error('TSA absolute deadline exceeded')), timeoutMs);
    const fail = (error: Error) => { clearTimeout(timer); reject(error); };
    req.on('error', fail);
    req.on('response', res => {
      const chunks: Buffer[] = []; let size = 0;
      res.on('error', fail);
      res.on('aborted', () => fail(new Error('TSA response aborted')));
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 512 * 1024) { res.destroy(); req.destroy(new Error('TSA response exceeds size limit')); }
        else chunks.push(Buffer.from(chunk));
      });
      res.on('end', () => {
        clearTimeout(timer);
        if (res.statusCode !== 200) reject(new Error('TSA HTTP status ' + res.statusCode));
        else resolve(Buffer.concat(chunks));
      });
    });
    req.end(tsqBuffer);
  });
}

/**
 * Probe a single TSA server and return a structured telemetry record.
 * Automatically performs in-band RFC 3161 verification on successful responses:
 * - Checks PKIStatus is granted (0) or grantedWithMods (1)
 * - Verifies TimeStampToken exists
 * - Asserts messageImprint digest matches expectedDigest (if provided)
 * - Asserts returned nonce matches expectedNonce (if provided)
 */
export async function probeTsa(
  tsaUrl: string,
  tsqBuffer: Buffer,
  tier: 'L1_CRYPTO_PRIMARY' | 'L2_CRYPTO_FALLBACK',
  timeoutMs = 4000,
  expectedDigest?: Buffer,
  expectedNonce?: Buffer | bigint,
  circuitBreaker: EndpointCircuitBreaker = globalCircuitBreaker
): Promise<TSAProbeResult> {
  // Fast path: if circuit breaker has this endpoint in backoff, skip network query
  if (!circuitBreaker.isAvailable(tsaUrl)) {
    const health = circuitBreaker.getHealth(tsaUrl);
    const waitRemaining = Math.max(0, (health?.nextAvailableTime || 0) - Date.now());
    const status = circuitBreaker.getServerStatus(tsaUrl);
    return {
      tier,
      method: 'RFC3161',
      server: tsaUrl,
      status: 'ERROR',
      error: `Endpoint in ${status.toLowerCase()} (${Math.round(waitRemaining / 1000)}s remaining): ${health?.lastError || 'circuit breaker active'}`
    };
  }

  circuitBreaker.recordRequest(tsaUrl);

  try {
    const data = await queryTsa(tsaUrl, tsqBuffer, timeoutMs);
    if (data && data.length > 32) {
      const validation = validateTimeStampResp(data, { expectedDigest, expectedNonce });
      if (!validation.valid) {
        circuitBreaker.recordFailure(tsaUrl, validation.error || 'RFC 3161 response validation failed');
        return {
          tier,
          method: 'RFC3161',
          server: tsaUrl,
          status: 'ERROR',
          error: validation.error || 'RFC 3161 response validation failed'
        };
      }
      circuitBreaker.recordSuccess(tsaUrl);
      const verification = await verifyTimeStampToken(data, Buffer.alloc(0), { expectedDigest });
      if (!verification.verified || !verification.genTime) throw new Error(verification.error || 'Timestamp time missing');
      const genTime = verification.genTime;
      return {
        tier,
        method: 'RFC3161',
        server: tsaUrl,
        status: 'SUCCESS',
        timestamp_iso: genTime,
        token_b64: data.toString('base64'),
        token_bytes: data
      };
    }
    circuitBreaker.recordFailure(tsaUrl, 'Empty or invalid response from TSA');
    return {
      tier,
      method: 'RFC3161',
      server: tsaUrl,
      status: 'ERROR',
      error: 'Empty or invalid response from TSA'
    };
  } catch (err: any) {
    const isTimeout = /timed? out/i.test(err?.message || '');
    circuitBreaker.recordFailure(tsaUrl, err?.message || String(err));
    return {
      tier,
      method: 'RFC3161',
      server: tsaUrl,
      status: isTimeout ? 'TIMEOUT' : 'ERROR',
      error: err?.message || String(err)
    };
  }
}

const HTTP_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const HTTP_DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const HTTP_DAYS_LONG = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const IMF_FIXDATE = /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/;
const RFC850_DATE = /^(Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{2}):(\d{2}):(\d{2}) GMT$/;
const ASCTIME_DATE = /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([ \d]\d) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/;

/**
 * Parse an RFC 7231 section 7.1.1.1 HTTP-date: IMF-fixdate, or the obsolete RFC 850 and asctime
 * forms a recipient must still accept. The grammar is case-sensitive, the day name must agree
 * with the date, and the date must exist (no 31 February, no 24:00:00, no leap second).
 * Returns epoch milliseconds, or null for anything else - including ISO-8601 and bare numbers
 * that `new Date(...)` would happily accept.
 */
export function parseHttpDate(value: string, now: number = Date.now()): number | null {
  if (typeof value !== 'string') return null;
  let dayName: string | undefined;
  let day: number, month: number, year: number, hh: number, mm: number, ss: number;
  let long = false;
  let m = IMF_FIXDATE.exec(value);
  if (m) {
    dayName = m[1]; day = +m[2]!; month = HTTP_MONTHS.indexOf(m[3]!); year = +m[4]!;
    hh = +m[5]!; mm = +m[6]!; ss = +m[7]!;
  } else if ((m = RFC850_DATE.exec(value))) {
    long = true;
    dayName = m[1]; day = +m[2]!; month = HTTP_MONTHS.indexOf(m[3]!);
    year = 2000 + +m[4]!;
    // RFC 7231: a two-digit year more than 50 years in the future means the past century.
    if (year > new Date(now).getUTCFullYear() + 50) year -= 100;
    hh = +m[5]!; mm = +m[6]!; ss = +m[7]!;
  } else if ((m = ASCTIME_DATE.exec(value))) {
    dayName = m[1]; month = HTTP_MONTHS.indexOf(m[2]!); day = +m[3]!.trim();
    hh = +m[4]!; mm = +m[5]!; ss = +m[6]!; year = +m[7]!;
  } else {
    return null;
  }
  if (hh > 23 || mm > 59 || ss > 59 || day < 1) return null;
  const d = new Date(0);
  d.setUTCFullYear(year, month, day);
  d.setUTCHours(hh, mm, ss, 0);
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month || d.getUTCDate() !== day) return null;
  const expected = (long ? HTTP_DAYS_LONG : HTTP_DAYS)[d.getUTCDay()];
  if (dayName !== expected) return null;
  return d.getTime();
}

/** Identity of a network time source for de-duplication: scheme, path, case and trailing dot ignored. */
function normalizeNetworkHost(host: string): string {
  return host.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\/.*$/, '').replace(/\.+$/, '');
}

function uniqueNetworkHosts(hosts: string[]): string[] {
  const seen = new Set<string>();
  return hosts.filter(h => {
    const key = normalizeNetworkHost(h);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Probe network time via HTTP Date header. The header must be an RFC 7231 HTTP-date.
 */
export function probeNetworkTime(host: string, timeoutMs = 3000): Promise<TSAProbeResult> {
  return new Promise((resolve) => {
    const req = https.request(`https://${host}`, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Moonglade-DTA/2.0' },
      timeout: timeoutMs
    }, (res) => {
      const dateStr = res.headers['date'];
      if (typeof dateStr === 'string') {
        const ms = parseHttpDate(dateStr);
        if (ms !== null) {
          resolve({
            tier: 'L3_NETWORK_CONSENSUS',
            method: 'HTTP_DATE',
            server: host,
            status: 'SUCCESS',
            timestamp_iso: new Date(ms).toISOString()
          });
          return;
        }
      }
      resolve({
        tier: 'L3_NETWORK_CONSENSUS',
        method: 'HTTP_DATE',
        server: host,
        status: 'ERROR',
        error: 'No valid Date header returned'
      });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({
        tier: 'L3_NETWORK_CONSENSUS',
        method: 'HTTP_DATE',
        server: host,
        status: 'TIMEOUT',
        error: `Network probe to ${host} timed out`
      });
    });
    req.on('error', (err) => {
      resolve({
        tier: 'L3_NETWORK_CONSENSUS',
        method: 'HTTP_DATE',
        server: host,
        status: 'ERROR',
        error: err.message
      });
    });
    req.end();
  });
}

/**
 * Evaluates whether successful L3 network probes form a Byzantine-tolerant quorum.
 * Requirements:
 * 1. At least 2 successful HTTP Date probes (or >= quorumThreshold).
 * 2. Absolute time drift between min and max probe timestamps is within maxDriftMs (default: 3000ms).
 * Returns the median timestamp and participating servers if quorum is reached, otherwise null.
 */
export function resolveNetworkConsensus(
  probes: TSAProbeResult[],
  quorumThreshold = 2,
  maxDriftMs = 3000
): { consensusTime: string; server: string } | null {
  // Configuration fails closed. Only a number >= 1 can lower or raise the default quorum of 2, and a
  // fraction rounds UP; 0, negatives, NaN and non-numbers leave the default, and Infinity can never be
  // met. A single host therefore reaches L3 only when the caller asks for exactly 1.
  let quorum = 2;
  if (typeof quorumThreshold === 'number' && quorumThreshold >= 1) {
    if (!Number.isFinite(quorumThreshold)) return null;
    quorum = Math.ceil(quorumThreshold);
  }
  // A NaN, negative, infinite or non-numeric drift limit must not disable the drift check.
  const driftLimit = typeof maxDriftMs === 'number' && Number.isFinite(maxDriftMs) && maxDriftMs >= 0 ? maxDriftMs : 3000;
  // A quorum counts distinct sources. The same host listed twice (or spelled two ways) is one
  // participant, so repeating a server cannot manufacture agreement; its first answer is kept.
  const distinct = new Map<string, TSAProbeResult>();
  for (const p of probes) {
    if (p.tier !== 'L3_NETWORK_CONSENSUS' || p.status !== 'SUCCESS' || !p.timestamp_iso) continue;
    if (typeof p.server !== 'string') continue;
    const key = normalizeNetworkHost(p.server);
    if (key && !distinct.has(key)) distinct.set(key, p);
  }
  const successful = [...distinct.values()];

  if (successful.length < quorum) {
    return null;
  }

  const times = successful
    .map(p => ({
      server: p.server,
      iso: p.timestamp_iso!,
      ms: new Date(p.timestamp_iso!).getTime()
    }))
    .filter(t => !isNaN(t.ms));

  if (times.length < quorum) {
    return null;
  }

  times.sort((a, b) => a.ms - b.ms);

  const minTime = times[0]!.ms;
  const maxTime = times[times.length - 1]!.ms;
  const drift = Math.abs(maxTime - minTime);

  if (drift > driftLimit) {
    return null;
  }

  // Median selection
  const mid = Math.floor(times.length / 2);
  const median = times[mid]!;
  const serverList = times.map(t => t.server).join('+');

  return {
    consensusTime: median.iso,
    server: `consensus(${serverList})`
  };
}

/**
 * Execute Concurrent Multi-Source Degrading Timestamping Architecture (DTA) fan-out.
 * Default pattern: simultaneously seeks 1 probe from each tier (L1, L2, L3, L4).
 * If specifiedServer or specifiedTier is requested, executes targeted query instead.
 */
export async function concurrentDegradingTimestamp(
  sha256Digest: Buffer,
  options: DTAOptions = {}
): Promise<DTAResult> {
  const cb = options.circuitBreaker || globalCircuitBreaker;
  const timeoutMs = options.timeoutMs || 4000;
  const nonce = options.nonce || crypto.randomBytes(8);
  const tsq = buildTimeStampReq(sha256Digest, { certReq: options.certReq !== false, nonce });

  const hostProbe: TSAProbeResult = {
    tier: 'L4_HOST_UNAUTHENTICATED',
    method: 'KERNEL_UTC',
    server: 'localhost',
    status: 'SUCCESS',
    timestamp_iso: new Date().toISOString()
  };

  // Case 1: Specifically requested server
  if (options.specifiedServer) {
    const s = options.specifiedServer;
    if (s.startsWith('http://') || s.startsWith('https://')) {
      const tier: 'L1_CRYPTO_PRIMARY' | 'L2_CRYPTO_FALLBACK' =
        DEFAULT_FALLBACK_TSAS.includes(s) ? 'L2_CRYPTO_FALLBACK' : 'L1_CRYPTO_PRIMARY';
      const probe = await probeTsa(s, tsq, tier, timeoutMs, sha256Digest, nonce, cb);
      const allProbes = [probe, hostProbe];
      if (probe.status === 'SUCCESS') {
        return {
          tier: 'INTEGRITY_ONLY',
          tsa: probe.server,
          tsa_time: probe.timestamp_iso!,
          token_b64: probe.token_b64,
          token_bytes: probe.token_bytes,
          probes: allProbes
        };
      }
      return {
        tier: 'L4_HOST_UNAUTHENTICATED',
        tsa: 'localhost',
        tsa_time: hostProbe.timestamp_iso!,
        probes: allProbes
      };
    } else {
      // One host cannot form a quorum. It is L3 only if the caller explicitly lowers the
      // threshold to 1; otherwise the probe is kept as evidence and the result is L4.
      const probe = await probeNetworkTime(s, timeoutMs);
      const allProbes = [probe, hostProbe];
      const single = resolveNetworkConsensus([probe], options.quorumThreshold ?? 2, options.maxDriftMs ?? 3000);
      if (single) {
        return {
          tier: 'L3_NETWORK_CONSENSUS',
          tsa: single.server,
          tsa_time: single.consensusTime,
          probes: allProbes
        };
      }
      return {
        tier: 'L4_HOST_UNAUTHENTICATED',
        tsa: 'localhost',
        tsa_time: hostProbe.timestamp_iso!,
        probes: allProbes
      };
    }
  }

  // Case 2: Specifically requested tier
  if (options.specifiedTier === 'L4_HOST_UNAUTHENTICATED') {
    return {
      tier: 'L4_HOST_UNAUTHENTICATED',
      tsa: 'localhost',
      tsa_time: hostProbe.timestamp_iso!,
      probes: [hostProbe]
    };
  }

  const probesPerTier = options.probesPerTier ?? options.maxParallelProbes ?? 1;
  const rotate = options.rotate !== false; // Default: true fair rotation

  const primaryPool = options.primaryEndpoints || DEFAULT_PRIMARY_TSAS;
  const fallbackPool = options.fallbackEndpoints || DEFAULT_FALLBACK_TSAS;
  const networkHosts = uniqueNetworkHosts(options.networkEndpoints || DEFAULT_NETWORK_HOSTS);
  const networkProbes = options.probesPerTier ?? options.maxParallelProbes ?? Math.min(3, networkHosts.length);

  const probePromises: Promise<TSAProbeResult>[] = [];

  if (!options.specifiedTier || options.specifiedTier === 'L1_CRYPTO_PRIMARY') {
    const selectedPrimary = rotate
      ? cb.selectRotatingEndpoints(primaryPool, probesPerTier, 'L1_PRIMARY')
      : cb.selectEndpoints(primaryPool, probesPerTier);
    probePromises.push(...selectedPrimary.map(url => probeTsa(url, tsq, 'L1_CRYPTO_PRIMARY', timeoutMs, sha256Digest, nonce, cb)));
  }

  if (!options.specifiedTier || options.specifiedTier === 'L2_CRYPTO_FALLBACK') {
    const selectedFallback = rotate
      ? cb.selectRotatingEndpoints(fallbackPool, probesPerTier, 'L2_FALLBACK')
      : cb.selectEndpoints(fallbackPool, probesPerTier);
    probePromises.push(...selectedFallback.map(url => probeTsa(url, tsq, 'L2_CRYPTO_FALLBACK', timeoutMs, sha256Digest, nonce, cb)));
  }

  if (!options.specifiedTier || options.specifiedTier === 'L3_NETWORK_CONSENSUS') {
    const selectedNetwork = rotate
      ? cb.selectRotatingEndpoints(networkHosts, networkProbes, 'L3_NETWORK')
      : cb.selectEndpoints(networkHosts, networkProbes);
    probePromises.push(...selectedNetwork.map(host => probeNetworkTime(host, Math.min(timeoutMs, 3000))));
  }

  const results = await Promise.all(probePromises);
  const allProbes = [...results, hostProbe];

  // Selection precedence: L1_CRYPTO_PRIMARY > L2_CRYPTO_FALLBACK > L3_NETWORK_CONSENSUS > L4_HOST_UNAUTHENTICATED
  const successfulL1 = results.find(p => p.tier === 'L1_CRYPTO_PRIMARY' && p.status === 'SUCCESS');
  if (successfulL1) {
    return {
      tier: 'INTEGRITY_ONLY',
      tsa: successfulL1.server,
      tsa_time: successfulL1.timestamp_iso!,
      token_b64: successfulL1.token_b64,
      token_bytes: successfulL1.token_bytes,
      probes: allProbes
    };
  }

  const successfulL2 = results.find(p => p.tier === 'L2_CRYPTO_FALLBACK' && p.status === 'SUCCESS');
  if (successfulL2) {
    return {
      tier: 'INTEGRITY_ONLY',
      tsa: successfulL2.server,
      tsa_time: successfulL2.timestamp_iso!,
      token_b64: successfulL2.token_b64,
      token_bytes: successfulL2.token_bytes,
      probes: allProbes
    };
  }

  const consensus = resolveNetworkConsensus(results, options.quorumThreshold ?? 2, options.maxDriftMs ?? 3000);
  if (consensus) {
    return {
      tier: 'L3_NETWORK_CONSENSUS',
      tsa: consensus.server,
      tsa_time: consensus.consensusTime,
      probes: allProbes
    };
  }

  return {
    tier: 'L4_HOST_UNAUTHENTICATED',
    tsa: 'localhost',
    tsa_time: hostProbe.timestamp_iso!,
    probes: allProbes
  };
}
