import * as crypto from 'crypto';

export const ARTIFACT_ENVELOPE_FORMAT = 'moonglade-artifact-envelope-v1';
export type ArtifactType = 'markdown' | 'image' | '3d-scene' | 'memory' | 'model-output' | 'release' | 'other';
export type ArtifactLifecycle = 'unverified' | 'observed' | 'signed' | 'published' | 'revoked';

export interface ArtifactEvidence {
  integrity: 'unknown' | 'valid' | 'failed';
  signature: 'none' | 'provisional' | 'valid' | 'failed';
  timestamp: 'none' | 'indeterminate' | 'valid' | 'failed';
  scope: 'unknown' | 'valid' | 'failed';
}

export interface ArtifactEnvelope {
  format: typeof ARTIFACT_ENVELOPE_FORMAT;
  artifact_id: string;
  artifact_type: ArtifactType;
  canonical_bytes: string;
  source_uri?: string;
  scope?: string;
  created_at: string;
  parents: string[];
  attestations: Array<{ method: string; signer?: string; fingerprint?: string; status?: string; signature?: string }>;
  status: ArtifactLifecycle;
  evidence: ArtifactEvidence;
  generator?: { agent?: string; model?: string; session?: string };
}

export function artifactId(canonicalBytes: Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalBytes).digest('hex')}`;
}

export function createArtifactEnvelope(input: Omit<ArtifactEnvelope, 'format' | 'artifact_id'> & { bytes: Buffer }): ArtifactEnvelope {
  const { bytes, ...rest } = input;
  return { format: ARTIFACT_ENVELOPE_FORMAT, artifact_id: artifactId(bytes), ...rest };
}

export function validateArtifactEnvelope(value: unknown): value is ArtifactEnvelope {
  if (!value || typeof value !== 'object') return false;
  const v = value as Partial<ArtifactEnvelope>;
  return v.format === ARTIFACT_ENVELOPE_FORMAT && typeof v.artifact_id === 'string' && /^sha256:[0-9a-f]{64}$/.test(v.artifact_id)
    && typeof v.canonical_bytes === 'string' && typeof v.created_at === 'string'
    && Array.isArray(v.parents) && Array.isArray(v.attestations)
    && ['unverified', 'observed', 'signed', 'published', 'revoked'].includes(v.status ?? '')
    && !!v.evidence && ['unknown', 'valid', 'failed'].includes(v.evidence.integrity ?? '')
    && ['none', 'provisional', 'valid', 'failed'].includes(v.evidence.signature ?? '')
    && ['none', 'indeterminate', 'valid', 'failed'].includes(v.evidence.timestamp ?? '')
    && ['unknown', 'valid', 'failed'].includes(v.evidence.scope ?? '');
}
