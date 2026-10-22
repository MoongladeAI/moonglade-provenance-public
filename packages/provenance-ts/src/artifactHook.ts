import * as fs from 'fs/promises';
import * as path from 'path';
import { ProvenanceEngine, ProvenanceSidecar, readRegularFile, MAX_ARTIFACT_BYTES, writeSidecar } from './index';
import { createArtifactEnvelope } from './artifactEnvelope';

export type ArtifactAction = 'observe' | 'seal-provisional';

export interface ArtifactHookOptions {
  action?: ArtifactAction;
  vaultRoot?: string;
  privateKeyPem?: string;
  signerIdentity?: string;
  generator?: { agent: string; model?: string; session?: string };
  parents?: string[];
  gitCommit?: string;
}

export interface ArtifactHookResult {
  path: string;
  action: ArtifactAction;
  skipped: boolean;
  reason?: string;
  sidecar?: ProvenanceSidecar;
}

export interface ArtifactMoveResult {
  artifactPath: string;
  attestationPath: string;
  attestationMoved: boolean;
}

const UNSAFE_NAMES = new Set(['.env', '.env.local', 'id_rsa', 'id_ed25519', 'id_dsa', 'id_ecdsa', '.npmrc', 'credentials', 'secrets.json']);
const UNSAFE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__']);

function isUnsafe(filePath: string): string | undefined {
  const parts = path.resolve(filePath).split(path.sep);
  if (parts.some(part => UNSAFE_DIRS.has(part))) return 'path is inside an excluded directory';
  if (UNSAFE_NAMES.has(path.basename(filePath).toLowerCase())) return 'filename is excluded';
  if (/\.(pem|key|p12|pfx|asc|kdbx)$/i.test(filePath)) return 'private-key or certificate material is excluded';
  return undefined;
}

export async function processArtifact(filePath: string, opts: ArtifactHookOptions = {}): Promise<ArtifactHookResult> {
  const resolved = path.resolve(filePath);
  const unsafe = isUnsafe(resolved);
  if (unsafe) return { path: resolved, action: opts.action ?? 'observe', skipped: true, reason: unsafe };

  const action = opts.action ?? 'observe';
  if (action === 'observe') {
    const bytes = await readRegularFile(resolved, MAX_ARTIFACT_BYTES);
    const hash = (await import('crypto')).createHash('sha256').update(bytes).digest('hex');
    const envelope = createArtifactEnvelope({ artifact_type: 'other', canonical_bytes: `sha256:${hash}`, created_at: new Date().toISOString(), parents: [], attestations: [], status: 'observed', evidence: { integrity: 'valid', signature: 'none', timestamp: 'none', scope: 'unknown' }, bytes });
    return { path: resolved, action, skipped: false, sidecar: {
      standard: 'Moonglade Provenance Observation v1', artifact: path.basename(resolved), attestations: [],
      sha256_at_last_write: hash, updated: new Date().toISOString(), envelope
    }};
  }

  if (!opts.privateKeyPem || !opts.signerIdentity) throw new Error('seal-provisional requires privateKeyPem and signerIdentity');
  const sidecar = await ProvenanceEngine.sealDocument(resolved, opts.privateKeyPem, opts.signerIdentity, opts.gitCommit ?? 'unknown', { vaultRoot: opts.vaultRoot, timestamp: false });
  (sidecar as any).status = 'provisional';
  (sidecar as any).generator = opts.generator ?? { agent: 'unknown' };
  (sidecar as any).parents = opts.parents ?? [];
  (sidecar as any).envelope = createArtifactEnvelope({ artifact_type: 'other', canonical_bytes: `sha256:${sidecar.sha256_at_last_write}`, created_at: sidecar.updated, parents: opts.parents ?? [], attestations: sidecar.attestations.map(a => ({ method: a.method, signer: a.signer, status: a.method === 'moonglade-ed25519-v2' ? 'provisional' : 'indeterminate', signature: a.signature })), status: 'signed', evidence: { integrity: 'valid', signature: 'provisional', timestamp: 'none', scope: 'valid' }, generator: opts.generator, bytes: await readRegularFile(resolved, MAX_ARTIFACT_BYTES) });
  await writeSidecar(`${resolved}.provenance.json`, sidecar);
  return { path: resolved, action, skipped: false, sidecar };
}

/** Move an artifact and its adjacent attestation as one atomic logical unit. */
export async function moveArtifactWithAttestation(sourcePath: string, destinationPath: string): Promise<ArtifactMoveResult> {
  const source = path.resolve(sourcePath);
  const destination = path.resolve(destinationPath);
  const sourceAttestation = `${source}.provenance.json`;
  const destinationAttestation = `${destination}.provenance.json`;
  for (const file of [destination, destinationAttestation]) {
    try { await fs.lstat(file); throw new Error('Move destination already exists'); }
    catch (error: any) { if (error.code !== 'ENOENT') throw error; }
  }
  try { await fs.lstat(sourceAttestation); throw new Error('Attested move refused: copy and explicitly reseal at the destination before retiring the source'); }
  catch (error: any) { if (error.code !== 'ENOENT') throw error; }
  await readRegularFile(source, MAX_ARTIFACT_BYTES);
  // Exclusive link creation avoids rename-overwrite races. Cross-device moves fail safely.
  await fs.link(source, destination);
  try { await fs.unlink(source); }
  catch (error) { await fs.unlink(destination); throw error; }
  return { artifactPath: destination, attestationPath: destinationAttestation, attestationMoved: false };
}
