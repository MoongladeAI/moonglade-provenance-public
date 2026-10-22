import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { merkleRoot, inclusionProof, InclusionProof, ArtifactMap, MERKLE_ALGORITHM } from './merkle';
import { concurrentDegradingTimestamp, DTAResult, DTAOptions, verifyTimeStampToken } from './timestamp';
import { ArtifactEnvelope } from './artifactEnvelope';
import { formatBadge } from './badge';

/**
 * Moonglade Provenance Engine (TypeScript Implementation)
 * Provides Ed25519 micro-signatures, RFC 3161 timestamps, and Merkle root macro-provenance.
 */

export interface ProvenanceSidecar {
  standard: string;
  artifact: string;
  claims?: Record<string, any>;
  claims_sha256?: string;
  attestations: Array<{
    method: string;
    signer?: string;
    scope?: string;
    sha256?: string;
    target_sha256?: string;
    claims_sha256?: string;
    created?: string;
    git_commit?: string;
    signature?: string;
    tier?: string;
    tsa?: string;
    tsa_time?: string;
    token_b64?: string;
    probes?: any[];
  }>;
  sha256_at_last_write: string;
  updated: string;
  status?: 'provisional' | 'canonical' | 'revoked';
  generator?: { agent: string; model?: string; session?: string };
  parents?: string[];
  envelope?: ArtifactEnvelope;
}

export interface VerificationResult {
  verified: boolean;
  status?: 'VERIFIED' | 'INDETERMINATE';
  documentSignatureVerified?: boolean;
  timestampStatus?: 'ABSENT' | 'INVALID' | 'INTEGRITY_ONLY' | 'ANCHORED';
  signer?: string;
  timestamp?: string;
  timestampTier?: string;
  timestampVerified?: boolean;
  timestampSigner?: string;
  error?: string;
  /** How many signature attestations were checked. Zero means an empty bundle. */
  attestationsChecked?: number;
  /** Methods present that this version cannot verify. Reported, never ignored. */
  unknownMethods?: string[];
  /**
   * The scope covered by the verified signature. Returned so a caller can compare it
   * with the location or namespace it expected: the signature binds the scope string,
   * but nothing in this library binds that string to where the file actually is.
   * A caller that does not compare it has not enforced scope.
   */
  scope?: string;
  /** Standard markdown provenance badge representation of this artifact verdict. */
  badge?: string;
  claims?: Record<string, any>;
  claimsSha256?: string;
}

export const TEXT_EXTENSIONS = new Set([
  'md', 'markdown', 'txt', 'text', 'json', 'csv', 'tsv',
  'html', 'htm', 'xml', 'yaml', 'yml', 'js', 'ts', 'jsx', 'tsx', 'css',
  'py', 'rs', 'go', 'c', 'cpp', 'h', 'hpp', 'sh', 'bat', 'ps1', 'sql'
]);

export const BINARY_EXTENSIONS = new Set([
  'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'ico',
  'mp4', 'mov', 'avi', 'mkv', 'webm', 'mp3', 'wav', 'flac', 'ogg',
  'zip', 'tar', 'gz', 'bz2', '7z', 'rar', 'wasm', 'bin', 'exe', 'dll', 'so', 'dylib', 'onnx'
]);

/**
 * Checks if a filename or byte buffer represents text rather than binary data.
 */
export function isTextContent(filename: string, bytes: Buffer | Uint8Array): boolean {
  const ext = path.extname(filename).replace(/^\./, '').toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) {
    return false;
  }
  if (TEXT_EXTENSIONS.has(ext)) {
    return true;
  }
  // If extension unknown, sample first 1024 bytes for null bytes (binary indicator)
  const sample = bytes.subarray(0, Math.min(bytes.length, 1024));
  for (let i = 0; i < sample.length; i++) {
    if (sample[i] === 0x00) {
      return false;
    }
  }
  return true;
}

/**
 * Deterministic JSON Canonicalization Scheme (RFC 8785 subset for generic claims, draft -03 section 3.3).
 * Sorts object keys lexicographically by UTF-16 code units with no whitespace. Numbers must be safe
 * integers; floats, NaN, Infinity and lone surrogates are rejected, exactly as in the Python and Rust engines.
 */
export function canonicalizeJson(value: any): string {
  const seen = new Set<object>();
  const string = (v: string): string => {
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const next = v.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('Lone surrogate in JSON');
      } else if (c >= 0xdc00 && c <= 0xdfff) throw new Error('Lone surrogate in JSON');
    }
    return JSON.stringify(v);
  };
  const visit = (v: any, depth: number): string => {
    if (depth > 64) throw new Error('JSON nesting exceeds 64');
    if (v === null) return 'null';
    if (typeof v === 'string') return string(v);
    if (typeof v === 'boolean') return JSON.stringify(v);
    if (typeof v === 'number') {
      // Draft -03 section 3.3: IEEE 754 integers within +-(2^53-1), judged by value, so 1.0 and 1e2 are
      // accepted (as 1 and 100) and 1.5, 2^53, NaN and Infinity are not. -0 is emitted as 0.
      if (!Number.isSafeInteger(v)) throw new Error('Claims numbers must be safe integers');
      return JSON.stringify(v);
    }
    if (typeof v !== 'object') throw new Error('Unsupported JSON value');
    if (seen.has(v)) throw new Error('Cyclic JSON');
    if (!Array.isArray(v) && Object.getPrototypeOf(v) !== Object.prototype && Object.getPrototypeOf(v) !== null) throw new Error('JSON requires plain objects');
    if (Reflect.ownKeys(v).some(k => typeof k === 'symbol')) throw new Error('Symbol JSON key');
    for (const d of Object.values(Object.getOwnPropertyDescriptors(v))) {
      if (d.get || d.set) throw new Error('JSON accessors are unsupported');
    }
    seen.add(v);
    let result: string;
    if (Array.isArray(v)) {
      if (Object.keys(v).length !== v.length) throw new Error('Sparse or decorated JSON array');
      result = '[' + Array.from(v, item => visit(item, depth + 1)).join(',') + ']';
    } else result = '{' + Object.keys(v).sort().map(k => string(k) + ':' + visit(v[k], depth + 1)).join(',') + '}';
    seen.delete(v);
    return result;
  };
  return visit(value, 0);
}

export interface VerificationPolicy {
  expectedScope?: string;
  requiredSigners?: string[];
  timestampTrustAnchors?: string[];
}

export const BUNDLE_V2 = 'Moonglade Provenance Attestation Bundle v2';
export const BUNDLE_V3 = 'Moonglade Provenance Attestation Bundle v3';
export const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const MAX_SIDECAR_BYTES = 1024 * 1024;

/** Reject links and oversized inputs. This local tool assumes no concurrent hostile filesystem writer. */
export async function readRegularFile(file: string, limit: number): Promise<Buffer> {
  const resolved = path.resolve(file);
  let cursor = path.parse(resolved).root;
  for (const part of resolved.slice(cursor.length).split(path.sep)) {
    cursor = path.join(cursor, part);
    if ((await fs.lstat(cursor)).isSymbolicLink()) throw new Error('Symbolic links are unsupported');
  }
  const handle = await fs.open(resolved, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error('Input is not a bounded regular file');
    const buffer = Buffer.alloc(Math.min(stat.size + 1, limit + 1));
    let length = 0;
    while (length < buffer.length) {
      const read = await handle.read(buffer, length, buffer.length - length, null);
      if (!read.bytesRead) break;
      length += read.bytesRead;
    }
    if (length > stat.size || length > limit) throw new Error('Input grew while reading');
    return buffer.subarray(0, length);
  } finally { await handle.close(); }
}

export async function writeSidecar(file: string, value: ProvenanceSidecar): Promise<void> {
  try { if (!(await fs.lstat(file)).isFile() || (await fs.lstat(file)).isSymbolicLink()) throw new Error('Unsafe sidecar target'); }
  catch (error: any) { if (error.code !== 'ENOENT') throw error; }
  await fs.writeFile(file, JSON.stringify(value, null, 2), 'utf8');
}

export function validateSidecar(sidecar: any): asserts sidecar is ProvenanceSidecar {
  if (!sidecar || typeof sidecar !== 'object' || Array.isArray(sidecar) ||
      ![BUNDLE_V2, BUNDLE_V3].includes(sidecar.standard) ||
      typeof sidecar.artifact !== 'string' || !sidecar.artifact ||
      !/^[a-f0-9]{64}$/.test(sidecar.sha256_at_last_write) ||
      !Array.isArray(sidecar.attestations) || !sidecar.attestations.length || sidecar.attestations.length > 64 ||
      sidecar.attestations.some((a: any) => !a || typeof a !== 'object' || Array.isArray(a) || typeof a.method !== 'string')) {
    throw new Error('Unsupported bundle or malformed sidecar');
  }
  if (sidecar.status === 'revoked') throw new Error('Revoked sidecar');
  const v3 = sidecar.standard === BUNDLE_V3;
  if (v3) {
    if (!sidecar.claims || typeof sidecar.claims !== 'object' || Array.isArray(sidecar.claims) ||
        !/^[a-f0-9]{64}$/.test(sidecar.claims_sha256)) throw new Error('Missing or malformed v3 claims');
    const digest = crypto.createHash('sha256').update(canonicalizeJson(sidecar.claims)).digest('hex');
    if (digest !== sidecar.claims_sha256) throw new Error('Claims hash mismatch');
  } else if (sidecar.claims !== undefined || sidecar.claims_sha256 !== undefined) throw new Error('Claims require v3');
  if (sidecar.attestations.some((a: any) => a.method.startsWith('moonglade-ed25519-') && a.method !== (v3 ? 'moonglade-ed25519-v3' : 'moonglade-ed25519-v2'))) throw new Error('Bundle and attestation versions differ');
}

export class ProvenanceEngine {
  /**
   * Canonicalizes an in-memory buffer according to Moonglade Provenance rules.
   * Text documents: strips UTF-8 BOM, normalizes CRLF to LF, and applies Unicode NFC.
   * Binary documents (PDFs, images, binaries): preserves exact byte fidelity.
   */
  static canonicalizeBytes(raw: Buffer, filename: string = 'document.txt'): Buffer {
    if (!isTextContent(filename, raw)) {
      return raw;
    }
    let text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
    // Strip UTF-8 Byte Order Mark (BOM) if present
    if (text.charCodeAt(0) === 0xFEFF) {
      text = text.slice(1);
    }
    // Normalize CRLF to LF and apply Unicode NFC
    const normalized = text.replace(/\r\n/g, '\n').normalize('NFC');
    return Buffer.from(normalized, 'utf8');
  }

  /**
   * Canonicalize a file's bytes deterministically:
   * For text documents, normalize CRLF to LF, strip UTF-8 BOM, and apply Unicode NFC.
   * For binary documents (PDFs, images, binaries), preserve byte-exact fidelity.
   *
   * This exists so a git checkout on Windows does not invalidate text signatures
   * in the repository, while ensuring binary structures (like PDF xref tables)
   * remain completely untouched.
   */
  static async canonicalizeFile(filePath: string): Promise<Buffer> {
    const raw = await readRegularFile(filePath, MAX_ARTIFACT_BYTES);
    return this.canonicalizeBytes(raw, filePath);
  }

  /**
   * Generates an Ed25519 keypair for testing/local identities if none exists.
   */
  static generateEd25519KeyPair() {
    return crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
  }

  /**
   * The bytes that are actually signed.
   *
   * Until v2 the signature covered the document bytes alone, which meant the
   * scope, the signer identity and the timestamp were unauthenticated JSON
   * sitting beside it. Anyone could rewrite the scope in a sidecar and the
   * signature still verified - so the stated property, that a signature made
   * for one scope will not verify under another, was not true here.
   *
   * v2 signs a structured claim instead. Three properties matter:
   *
   *   1. Domain separation - the version string is inside the payload, so a
   *      signature over one payload type cannot be replayed as another.
   *   2. Field binding - scope, artifact hash and signer are all covered.
   *   3. Unambiguous framing - newlines delimit fields, and fields are
   *      validated to contain none, so a crafted scope cannot smuggle in a
   *      forged signer line.
   */
  static readonly PAYLOAD_VERSION = 'moonglade-provenance/v2';
  static readonly PAYLOAD_VERSION_V3 = 'moonglade-provenance/v3';

  static buildSigningPayload(fields: { scope: string; sha256: string; signer: string }): Buffer {
    for (const [k, v] of Object.entries(fields)) {
      if (typeof v !== 'string' || v.length === 0) {
        throw new Error(`signing payload: ${k} must be a non-empty string`);
      }
      if (/[\x00-\x1f\x7f]/.test(v)) {
        throw new Error(`signing payload: ${k} must not contain control characters`);
      }
    }
    const body = [
      this.PAYLOAD_VERSION,
      `scope:${fields.scope}`,
      `sha256:${fields.sha256}`,
      `signer:${fields.signer}`,
      ''
    ].join('\n');
    return Buffer.from(body, 'utf8');
  }

  static buildSigningPayloadV3(fields: {
    scope: string;
    targetSha256: string;
    signer: string;
    claimsSha256: string;
  }): Buffer {
    for (const [k, v] of Object.entries(fields)) {
      if (typeof v !== 'string' || v.length === 0) {
        throw new Error(`signing payload v3: ${k} must be a non-empty string`);
      }
      if (/[\x00-\x1f\x7f]/.test(v)) {
        throw new Error(`signing payload v3: ${k} must not contain control characters`);
      }
    }
    const body = [
      this.PAYLOAD_VERSION_V3,
      `scope:${fields.scope}`,
      `target-sha256:${fields.targetSha256}`,
      `signer:${fields.signer}`,
      `claims-sha256:${fields.claimsSha256}`,
      ''
    ].join('\n');
    return Buffer.from(body, 'utf8');
  }

  /**
   * Build the attestation scope for an artifact.
   *
   * Scope isolation is the stated security property: a signature made for one
   * scope must not be presentable for another. Until 2026-08-30 this used
   * `path.basename(filePath)`, which gave every README.md in the tree the same
   * scope - a collision in any repository with repeated filenames, which is all
   * of them.
   *
   * It is now the path relative to `vaultRoot`, matching the Python
   * implementation's `namespace_for()`.
   *
   * Separators are forced to POSIX. `path.relative` yields backslashes on
   * Windows and forward slashes elsewhere, so without this the same file signed
   * on two machines would carry two different scopes. That is the same class of
   * defect canonicalizeFile exists to prevent for line endings, and it would be
   * careless to fix one and not the other.
   */
  static scopeFor(filePath: string, vaultRoot?: string, explicit?: string): string {
    if (explicit) return `moonglade:vault:${explicit}`;
    const root = vaultRoot ?? path.dirname(path.resolve(filePath));
    const rel = path.relative(root, path.resolve(filePath));
    if (path.isAbsolute(rel) || rel === '..' || rel.startsWith('..' + path.sep)) throw new Error('Artifact is outside scope root');
    const safe = rel || path.basename(filePath);
    return `moonglade:vault:${safe.split(path.sep).join('/')}`;
  }

  /**
   * Sign a document and generate the .provenance.json sidecar.
   * Supports both v2 standard bundles and v3 extended bundles with generic claims.
   */
  static async sealDocument(
    filePath: string,
    privateKeyPem: string,
    signerIdentity: string,
    gitCommit: string = 'unknown',
    opts: {
      vaultRoot?: string;
      scope?: string;
      timestamp?: boolean | DTAOptions;
      claims?: Record<string, any>;
      version?: 'v2' | 'v3';
    } = {}
  ): Promise<ProvenanceSidecar> {
    if (crypto.createPrivateKey(privateKeyPem).asymmetricKeyType !== 'ed25519') throw new Error('Expected Ed25519 private key');
    if (opts.version !== undefined && !['v2', 'v3'].includes(opts.version)) throw new Error('Unsupported signing version');
    const canonicalBytes = await this.canonicalizeFile(filePath);
    
    // Hash
    const hash = crypto.createHash('sha256').update(canonicalBytes).digest('hex');
    const digestBuffer = crypto.createHash('sha256').update(canonicalBytes).digest();
    
    const scope = this.scopeFor(filePath, opts.vaultRoot, opts.scope);

    const isV3 = Boolean(opts.claims !== undefined || opts.version === 'v3');
    const attestations: ProvenanceSidecar['attestations'] = [];
    let claimsHash: string | undefined;

    if (isV3) {
      const claims = opts.claims || {};
      const claimsJson = canonicalizeJson(claims);
      claimsHash = crypto.createHash('sha256').update(claimsJson, 'utf8').digest('hex');
      const payload = this.buildSigningPayloadV3({
        scope,
        targetSha256: hash,
        signer: signerIdentity,
        claimsSha256: claimsHash
      });
      const signature = crypto.sign(null, payload, privateKeyPem).toString('base64');
      attestations.push({
        method: "moonglade-ed25519-v3",
        signer: signerIdentity,
        scope,
        sha256: hash,
        target_sha256: hash,
        claims_sha256: claimsHash,
        created: new Date().toISOString(),
        git_commit: gitCommit,
        signature
      });
    } else {
      // Sign the structured claim, not the raw bytes - see buildSigningPayload.
      const payload = this.buildSigningPayload({ scope, sha256: hash, signer: signerIdentity });
      const signature = crypto.sign(null, payload, privateKeyPem).toString('base64');
      attestations.push({
        method: "moonglade-ed25519-v2",
        signer: signerIdentity,
        scope,
        sha256: hash,
        created: new Date().toISOString(),
        git_commit: gitCommit,
        signature
      });
    }

    if (opts.timestamp) {
      const dtaOpts = typeof opts.timestamp === 'object' ? opts.timestamp : {};
      const dta = await concurrentDegradingTimestamp(digestBuffer, dtaOpts);
      if (dta.token_b64) attestations.push({
        method: "rfc3161",
        tier: dta.tier,
        tsa: dta.tsa,
        tsa_time: dta.tsa_time,
        token_b64: dta.token_b64,
        probes: dta.probes
      });
    }
    
    const sidecar: ProvenanceSidecar = {
      standard: isV3 ? "Moonglade Provenance Attestation Bundle v3" : "Moonglade Provenance Attestation Bundle v2",
      artifact: path.basename(filePath),
      ...(isV3 ? { claims: opts.claims || {}, claims_sha256: claimsHash } : {}),
      attestations,
      sha256_at_last_write: hash,
      updated: new Date().toISOString()
    };
    
    validateSidecar(sidecar);
    const sidecarPath = `${filePath}.provenance.json`;
    await writeSidecar(sidecarPath, sidecar);
    
    return sidecar;
  }

  /**
   * Countersign an existing document and append the attestation to the sidecar.
   */
  static async countersignDocument(
    filePath: string,
    privateKeyPem: string,
    signerIdentity: string,
    gitCommit: string = 'unknown',
    opts: { vaultRoot?: string; scope?: string; verificationKeys?: string | Record<string, string>; policy?: VerificationPolicy } = {}
  ): Promise<ProvenanceSidecar> {
    const sidecarPath = `${filePath}.provenance.json`;
    if (crypto.createPrivateKey(privateKeyPem).asymmetricKeyType !== 'ed25519') throw new Error('Expected Ed25519 private key');
    if (!opts.verificationKeys) throw new Error('Cannot countersign without verificationKeys');
    const validation = await this.verifyDocument(filePath, opts.verificationKeys, opts.policy);
    if (!validation.verified) throw new Error('Cannot countersign: ' + validation.error);
    const sidecarData = (await readRegularFile(sidecarPath, MAX_SIDECAR_BYTES)).toString('utf8');
    const sidecar: ProvenanceSidecar = JSON.parse(sidecarData);

    const canonicalBytes = await this.canonicalizeFile(filePath);
    const hash = crypto.createHash('sha256').update(canonicalBytes).digest('hex');

    if (hash !== sidecar.sha256_at_last_write) {
      throw new Error('Cannot countersign: document has been mutated since sealing.');
    }

    const scope = opts.scope ? this.scopeFor(filePath, opts.vaultRoot, opts.scope) : validation.scope!;
    if (scope !== validation.scope) throw new Error('Countersigner scope differs');
    const isV3 = sidecar.standard === BUNDLE_V3;

    if (isV3) {
      const claimsHash = sidecar.claims_sha256 || crypto.createHash('sha256').update(canonicalizeJson(sidecar.claims || {}), 'utf8').digest('hex');
      const payload = this.buildSigningPayloadV3({
        scope,
        targetSha256: hash,
        signer: signerIdentity,
        claimsSha256: claimsHash
      });
      const signature = crypto.sign(null, payload, privateKeyPem).toString('base64');
      sidecar.attestations.push({
        method: "moonglade-ed25519-v3",
        signer: signerIdentity,
        scope,
        sha256: hash,
        target_sha256: hash,
        claims_sha256: claimsHash,
        created: new Date().toISOString(),
        git_commit: gitCommit,
        signature
      });
    } else {
      const payload = this.buildSigningPayload({ scope, sha256: hash, signer: signerIdentity });
      const signature = crypto.sign(null, payload, privateKeyPem).toString('base64');
      sidecar.attestations.push({
        method: "moonglade-ed25519-v2",
        signer: signerIdentity,
        scope,
        sha256: hash,
        created: new Date().toISOString(),
        git_commit: gitCommit,
        signature
      });
    }

    sidecar.updated = new Date().toISOString();
    await writeSidecar(sidecarPath, sidecar);
    return sidecar;
  }

  /**
   * Attest RFC 3161 timestamping for an artifact via Concurrent Multi-Source DTA.
   */
  static async attestTimestamp(
    filePath: string,
    opts: DTAOptions = {}
  ): Promise<DTAResult> {
    const canonicalBytes = await this.canonicalizeFile(filePath);
    const digestBuffer = crypto.createHash('sha256').update(canonicalBytes).digest();
    const dta = await concurrentDegradingTimestamp(digestBuffer, opts);

    if (!dta.token_b64) return dta;
    // If sidecar exists, attach or update the rfc3161 attestation
    const sidecarPath = `${filePath}.provenance.json`;
    try {
      const sidecarData = await fs.readFile(sidecarPath, 'utf8');
      const sidecar: ProvenanceSidecar = JSON.parse(sidecarData);
      if (Array.isArray(sidecar.attestations)) {
        const existingIdx = sidecar.attestations.findIndex(a => a.method === 'rfc3161');
        const tsAtt = {
          method: "rfc3161",
          tier: dta.tier,
          tsa: dta.tsa,
          tsa_time: dta.tsa_time,
          token_b64: dta.token_b64,
          probes: dta.probes
        };
        if (existingIdx >= 0) {
          sidecar.attestations[existingIdx] = tsAtt;
        } else {
          sidecar.attestations.push(tsAtt);
        }
        sidecar.updated = new Date().toISOString();
        await writeSidecar(sidecarPath, sidecar);
      }
    } catch {
      // Sidecar does not exist or unreadable, still return DTAResult
    }

    return dta;
  }

  /**
   * Verify a document against its sidecar.
   * Supports both v2 and v3 attestation bundles.
   */
  static async verifyDocument(
    filePath: string,
    publicKeyPem: string | Record<string, string>,
    policy: VerificationPolicy = {}
  ): Promise<VerificationResult> {
    let documentSignatureVerified = false;
    let timestampStatus: VerificationResult['timestampStatus'] = 'ABSENT';
    try {
      const sidecarPath = `${filePath}.provenance.json`;
      const sidecarData = new TextDecoder('utf-8', { fatal: true }).decode(await readRegularFile(sidecarPath, MAX_SIDECAR_BYTES));
      const sidecar: ProvenanceSidecar = JSON.parse(sidecarData);
      validateSidecar(sidecar);
      
      const canonicalBytes = await this.canonicalizeFile(filePath);
      const currentHash = crypto.createHash('sha256').update(canonicalBytes).digest('hex');
      
      if (currentHash !== sidecar.sha256_at_last_write) {
        return { verified: false, error: "Hash mismatch: Document has been mutated since sealing." };
      }
      
      const attestations = Array.isArray(sidecar.attestations) ? sidecar.attestations : [];

      const SUPPORTED_V2 = 'moonglade-ed25519-v2';
      const SUPPORTED_V3 = 'moonglade-ed25519-v3';
      const signatures = attestations.filter(a => a.method === SUPPORTED_V2 || a.method === SUPPORTED_V3);
      const unknownMethods = Array.from(new Set(
        attestations.filter(a => a.method !== SUPPORTED_V2 && a.method !== SUPPORTED_V3 && a.method !== 'rfc3161').map(a => a.method)
      ));

      if (signatures.length === 0) {
        return {
          verified: false,
          error: 'No moonglade-ed25519-v2 or v3 attestation in the bundle. An ssh-ed25519 (SSHSIG) attestation must be verified with ssh-keygen -Y verify, not by this package.',
          attestationsChecked: 0,
          unknownMethods
        };
      }

      if (unknownMethods.length) return { verified: false, status: 'INDETERMINATE', unknownMethods, error: 'Unsupported attestation method; use ssh-keygen -Y verify for SSHSIG outside this package' };
      if (sidecar.artifact !== path.basename(filePath)) return { verified: false, error: 'Artifact filename mismatch' };
      if (policy.requiredSigners && (!Array.isArray(policy.requiredSigners) || policy.requiredSigners.some(s => typeof s !== 'string' || !s))) throw new Error('Invalid required signer policy');
      for (const signer of policy.requiredSigners || []) {
        if (!signatures.some(a => a.signer === signer)) return { verified: false, error: 'Missing required signer: ' + signer };
      }
      // If claims are present in sidecar, verify their canonical hash
      if (sidecar.claims !== undefined && sidecar.claims_sha256 !== undefined) {
        const computedClaimsHash = crypto.createHash('sha256').update(canonicalizeJson(sidecar.claims), 'utf8').digest('hex');
        if (computedClaimsHash !== sidecar.claims_sha256) {
          return {
            verified: false,
            error: 'Claims hash mismatch: claims payload has been mutated.',
            attestationsChecked: signatures.length,
            unknownMethods
          };
        }
      }

      // Every signature must hold. A good signature does not redeem a forged sibling.
      for (const att of signatures) {
        if (att.scope !== signatures[0].scope || (policy.expectedScope !== undefined && att.scope !== policy.expectedScope)) return { verified: false, error: 'Scope mismatch' };
        if (typeof att.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(att.signature)) return { verified: false, error: 'Invalid Ed25519 signature encoding' };
        if (!att.signature || !att.signer || !att.scope || (!att.sha256 && !att.target_sha256)) {
          return {
            verified: false,
            error: 'Incomplete signature attestation block.',
            attestationsChecked: signatures.length,
            unknownMethods
          };
        }
        const targetHash = att.target_sha256 || att.sha256;
        if (targetHash !== currentHash) {
          return {
            verified: false,
            error: `Attestation for scope "${att.scope}" records a different hash.`,
            attestationsChecked: signatures.length,
            unknownMethods
          };
        }

        let payload: Buffer;
        if (att.method === SUPPORTED_V3) {
          if (!att.claims_sha256) {
            return {
              verified: false,
              error: 'Missing claims_sha256 in v3 attestation.',
              attestationsChecked: signatures.length,
              unknownMethods
            };
          }
          if (sidecar.claims_sha256 && att.claims_sha256 !== sidecar.claims_sha256) {
            return {
              verified: false,
              error: 'Attestation claims_sha256 does not match bundle claims_sha256.',
              attestationsChecked: signatures.length,
              unknownMethods
            };
          }
          payload = ProvenanceEngine.buildSigningPayloadV3({
            scope: att.scope,
            targetSha256: targetHash!,
            signer: att.signer,
            claimsSha256: att.claims_sha256
          });
        } else {
          payload = ProvenanceEngine.buildSigningPayload({
            scope: att.scope,
            sha256: targetHash!,
            signer: att.signer
          });
        }

        const keyForSigner = typeof publicKeyPem === 'object'
          ? (Object.prototype.hasOwnProperty.call(publicKeyPem, att.signer) ? publicKeyPem[att.signer] : undefined)
          : publicKeyPem;

        if (!keyForSigner) {
          return {
            verified: false,
            error: `No public key provided for signer "${att.signer}".`,
            attestationsChecked: signatures.length,
            unknownMethods
          };
        }

        if (crypto.createPublicKey(keyForSigner).asymmetricKeyType !== 'ed25519') return { verified: false, status: 'INDETERMINATE', error: 'Expected Ed25519 public key' };
        const ok = crypto.verify(
          null, payload, keyForSigner, Buffer.from(att.signature, 'base64')
        );
        if (!ok) {
          return {
            verified: false,
            error: `Signature validation failed for signer "${att.signer}".`,
            attestationsChecked: signatures.length,
            unknownMethods
          };
        }
      }

      documentSignatureVerified = true;
      const timestamps = attestations.filter(a => a.method === 'rfc3161');
      if (timestamps.length) timestampStatus = 'INVALID';
      if (timestamps.length > 1) throw new Error('Multiple timestamp attestations are unsupported');
      let timestampVerified: boolean | undefined;
      let timestampSigner: string | undefined;
      let timestamp: string | undefined;
      let timestampTier: string | undefined;
      if (timestamps.length) {
        const token = timestamps[0].token_b64;
        if (typeof token !== 'string' || !token.length || token.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(token)) throw new Error('Timestamp token missing or invalid');
        const tsRes = await verifyTimeStampToken(Buffer.from(token, 'base64'), canonicalBytes, { trustAnchors: policy.timestampTrustAnchors });
        if (!tsRes.verified) throw new Error('Timestamp token verification failed: ' + tsRes.error);
        timestampVerified = tsRes.trusted === true;
        timestampSigner = tsRes.signerSubject;
        timestamp = tsRes.genTime;
        timestampTier = tsRes.trusted ? 'ANCHORED' : 'INTEGRITY_ONLY';
        timestampStatus = tsRes.trusted ? 'ANCHORED' : 'INTEGRITY_ONLY';
      }

      const badge = formatBadge('SEALED', {
        signer: signatures[0].signer,
        hash: currentHash,
        tier: timestampTier
      });

      return {
        verified: true,
        status: 'VERIFIED',
        documentSignatureVerified, timestampStatus,
        signer: signatures[0].signer,
        scope: signatures[0].scope,
        timestamp,
        timestampTier,
        timestampVerified,
        timestampSigner,
        attestationsChecked: signatures.length,
        unknownMethods,
        badge,
        claims: sidecar.claims,
        claimsSha256: sidecar.claims_sha256
      };
    } catch (e: any) {
      return { verified: false, documentSignatureVerified, timestampStatus, error: `Verification error: ${e.message}` };
    }
  }
}

/**
 * Vault Macro-Provenance: Merkle Tree Hash Registry
 */
export class ProvenanceVault {
  // `salt` is retained for API compatibility but no longer participates in the
  // root. RFC 6962 domain separation supersedes it, and a salted root cannot be
  // verified by a third party who does not know the salt - which defeats the
  // purpose of publishing one.
  constructor(public rootPath: string, public salt: string = "moonglade-v1") {}

  private async walk(dir: string, fileList: string[] = [], depth = 0): Promise<string[]> {
    if (depth > 64 || fileList.length > 100000) throw new Error('Vault scan limit exceeded');
    if ((await fs.lstat(dir)).isSymbolicLink()) throw new Error('Symbolic links are unsupported in vault scans');
    const files = await fs.readdir(dir);
    for (const file of files) {
      const filepath = path.join(dir, file);
      const stat = await fs.lstat(filepath);
      if (stat.isSymbolicLink()) throw new Error('Symbolic links are unsupported in vault scans');
      if (stat.isDirectory()) {
        if (!file.startsWith('.') && file !== 'node_modules') {
          await this.walk(filepath, fileList, depth + 1);
        }
      } else {
        fileList.push(filepath);
      }
    }
    return fileList.sort(); // Deterministic ordering
  }

  /**
   * Hash every file under the root and build a real Merkle tree over them.
   *
   * Until v2 this returned a flat SHA-256 over the concatenated hashes. That
   * detected change and nothing else - it could not produce an inclusion proof,
   * which is the only reason to use a tree. See merkle.ts.
   *
   * Paths are POSIX-normalised before hashing, so a vault scanned on Windows and
   * on Linux yields the same root. Without that the two would silently disagree,
   * which is the same defect canonicalizeFile prevents for line endings.
   */
  async scanAndAudit(): Promise<{
    merkleRoot: string;
    algorithm: string;
    fileCount: number;
    artifacts: ArtifactMap;
  }> {
    const files = await this.walk(this.rootPath);
    const artifacts: ArtifactMap = Object.create(null);

    for (const file of files) {
      const bytes = await readRegularFile(file, MAX_ARTIFACT_BYTES);
      const rel = path.relative(this.rootPath, file).split(path.sep).join('/');
      artifacts[rel] = { sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
    }

    return {
      merkleRoot: merkleRoot(artifacts),
      algorithm: MERKLE_ALGORITHM,
      fileCount: files.length,
      artifacts
    };
  }

  /** Audit path for one artifact, by its POSIX path relative to the root. */
  async proveInclusion(relPath: string): Promise<InclusionProof | null> {
    const { artifacts } = await this.scanAndAudit();
    return inclusionProof(artifacts, relPath);
  }
}

// RFC 6962 Merkle tree and inclusion proofs.
export * from './merkle';

// RFC 3161 and Concurrent Degrading Timestamping Architecture (DTA).
export * from './timestamp';

// Model Context Protocol (MCP) Server.
export * from './mcp';

// Artifact generation observer and provisional signer.
export * from './artifactHook';

// Shared identity and evidence contract for all Moonglade artifact types.
export * from './artifactEnvelope';

// Standalone zero-dependency install and environment verification suite.
export * from './self-test';

// Standard Artifact Provenance Badges.
export * from './badge';
