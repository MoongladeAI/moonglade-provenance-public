import * as fs from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { ProvenanceEngine, readRegularFile, MAX_SIDECAR_BYTES, validateSidecar } from './index';

export type ProvenanceBadgeStatus =
  | 'HASH_ONLY'
  | 'SEALED'
  | 'LIVING'
  | 'SCRATCH'
  | 'MUTATED'
  | 'INVALID_SIGNATURE'
  | 'NOT_FOUND';

export interface BadgeColorDefinition {
  hex: string;
  ansi: string;
  bgHex: string;
  bgAnsi: string;
  resetAnsi: string;
}

export const BADGE_COLORS: Record<ProvenanceBadgeStatus, BadgeColorDefinition> = {
  HASH_ONLY: { hex: '#d97706', ansi: '\x1b[1;33m', bgHex: 'rgba(217,119,6,0.15)', bgAnsi: '\x1b[43;30m', resetAnsi: '\x1b[0m' },
  SEALED: {
    hex: '#2ea44f',
    ansi: '\x1b[1;32m',
    bgHex: 'rgba(46,164,79,0.15)',
    bgAnsi: '\x1b[42;30m',
    resetAnsi: '\x1b[0m'
  },
  LIVING: {
    hex: '#0969da',
    ansi: '\x1b[1;34m',
    bgHex: 'rgba(9,105,218,0.15)',
    bgAnsi: '\x1b[44;37m',
    resetAnsi: '\x1b[0m'
  },
  SCRATCH: {
    hex: '#d97706',
    ansi: '\x1b[1;33m',
    bgHex: 'rgba(217,119,6,0.15)',
    bgAnsi: '\x1b[43;30m',
    resetAnsi: '\x1b[0m'
  },
  MUTATED: {
    hex: '#cf222e',
    ansi: '\x1b[1;31m',
    bgHex: 'rgba(207,34,46,0.15)',
    bgAnsi: '\x1b[41;37m',
    resetAnsi: '\x1b[0m'
  },
  INVALID_SIGNATURE: {
    hex: '#cf222e',
    ansi: '\x1b[1;31m',
    bgHex: 'rgba(207,34,46,0.15)',
    bgAnsi: '\x1b[41;37m',
    resetAnsi: '\x1b[0m'
  },
  NOT_FOUND: {
    hex: '#6e7781',
    ansi: '\x1b[90m',
    bgHex: 'rgba(110,119,129,0.15)',
    bgAnsi: '\x1b[47;30m',
    resetAnsi: '\x1b[0m'
  }
};

export function getStatusColor(status: ProvenanceBadgeStatus): BadgeColorDefinition {
  return BADGE_COLORS[status] || BADGE_COLORS.NOT_FOUND;
}

export interface BadgeOptions {
  format?: 'text' | 'markdown' | 'markdown-link' | 'shields-url' | 'html' | 'json';
  color?: boolean | 'ansi' | 'html';
  shortHashLen?: number;
  style?: 'short' | 'detailed';
  targetUrl?: string;
  publicKeyPem?: string;
  requiredScope?: string;
}

export interface BadgeInfo {
  status: ProvenanceBadgeStatus;
  badgeText: string;
  ansiText?: string;
  html?: string;
  colorHex: string;
  markdown: string;
  shieldsUrl: string;
  filePath: string;
  artifactName: string;
  signer?: string;
  shortHash?: string;
  fullHash?: string;
  tier?: string;
  timestamp?: string;
  error?: string;
}

/**
 * Clean signer identifier for badge display (e.g. 'Synthetic (Fixture)...' -> 'Synthetic').
 */
export function extractShortSigner(signer?: string): string | undefined {
  if (!signer) return undefined;
  const match = signer.match(/^([^<(\s]+)/);
  return match ? match[1] : signer;
}

/**
 * Generate a Shields.io badge URL for a given status.
 */
export function getShieldsBadgeUrl(
  status: ProvenanceBadgeStatus,
  details?: { signer?: string; shortHash?: string }
): string {
  let label = 'provenance';
  let message = 'unknown';
  let color = 'lightgrey';

  switch (status) {
    case 'HASH_ONLY': return 'https://img.shields.io/badge/provenance-hash%20only-d97706?style=flat-square';
    case 'SEALED': {
      const parts = ['sealed'];
      if (details?.signer) parts.push(encodeURIComponent(details.signer));
      if (details?.shortHash) parts.push(details.shortHash);
      message = parts.join('%20%C2%B7%20'); // URL-encoded middle dot
      color = '2ea44f'; // Green
      break;
    }
    case 'LIVING':
      message = 'unsealed%20%C2%B7%20living';
      color = '0969da'; // Blue
      break;
    case 'SCRATCH':
      message = 'ephemeral%20%C2%B7%20scratch';
      color = 'd97706'; // Amber
      break;
    case 'MUTATED':
      message = 'mutated%20%C2%B7%20mismatch';
      color = 'cf222e'; // Red
      break;
    case 'INVALID_SIGNATURE':
      message = 'invalid%20signature';
      color = 'cf222e'; // Red
      break;
    case 'NOT_FOUND':
      message = 'not%20found';
      color = 'grey';
      break;
  }

  return `https://img.shields.io/badge/${label}-${message}-${color}?style=flat-square`;
}

/**
 * Format an ANSI color-coded badge string for terminal display.
 */
export function formatAnsiBadge(
  status: ProvenanceBadgeStatus,
  details?: { signer?: string; hash?: string; tier?: string },
  options: BadgeOptions = {}
): string {
  const colorDef = getStatusColor(status);
  const plain = formatBadge(status, details, { ...options, color: false });
  // Match the inner bracketed text: e.g. "🛡️ [SEALED · Synthetic · 9df0af4d]"
  const match = plain.match(/^(\S+)\s*\[(.*)\]$/);
  if (!match) {
    return `${colorDef.ansi}${plain}${colorDef.resetAnsi}`;
  }
  const emoji = match[1];
  const inner = match[2];
  return `${emoji} [${colorDef.ansi}${inner}${colorDef.resetAnsi}]`;
}

/**
 * Format an inline HTML badge element for web apps, Astro, or rich markdown docs.
 */
export function formatHtmlBadge(
  status: ProvenanceBadgeStatus,
  details?: { signer?: string; hash?: string; tier?: string },
  options: BadgeOptions = {}
): string {
  const colorDef = getStatusColor(status);
  const plain = formatBadge(status, details, { ...options, format: 'text', color: false });
  const match = plain.match(/^(\S+)\s*\[(.*)\]$/);
  if (!match) {
    return `<span class="provenance-badge provenance-badge-${status.toLowerCase()}" style="color:${colorDef.hex};font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:0.85em;">${plain}</span>`;
  }
  const emoji = match[1];
  const innerText = match[2].replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  return `${emoji} <span class="provenance-badge-status" style="color:${colorDef.hex};font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:0.85em;">[${innerText}]</span>`;
}

/**
 * Format a badge string given status and metadata.
 */
export function formatBadge(
  status: ProvenanceBadgeStatus,
  details?: { signer?: string; hash?: string; tier?: string },
  options: BadgeOptions = {}
): string {
  if (options.color === true || options.color === 'ansi' || options.format === 'text' && options.color) {
    return formatAnsiBadge(status, details, { ...options, color: false });
  }
  if (options.color === 'html' || options.format === 'html') {
    return formatHtmlBadge(status, details, options);
  }

  const shortHashLen = options.shortHashLen ?? 8;
  const shortHash = details?.hash ? details.hash.slice(0, shortHashLen) : undefined;
  const shortSigner = options.style === 'short'
    ? undefined
    : extractShortSigner(details?.signer);

  switch (status) {
    case 'HASH_ONLY': return '⚠️ [HASH-ONLY · UNVERIFIED]';
    case 'SEALED': {
      const parts: string[] = ['SEALED'];
      if (shortSigner) parts.push(shortSigner);
      if (shortHash) parts.push(shortHash);
      return `🛡️ [${parts.join(' · ')}]`;
    }
    case 'LIVING':
      return '📝 [UNSEALED · LIVING]';
    case 'SCRATCH':
      return '⚡ [EPHEMERAL · SCRATCH]';
    case 'MUTATED':
      return '🚨 [MUTATED · HASH MISMATCH]';
    case 'INVALID_SIGNATURE':
      return '🚨 [INVALID SIGNATURE]';
    case 'NOT_FOUND':
      return '❌ [NOT FOUND]';
  }
}

/**
 * Format a complete markdown link with the badge adjacent.
 */
export function formatMarkdownLink(
  filePath: string,
  badgeInfo: BadgeInfo,
  options: { label?: string; urlPrefix?: string; targetUrl?: string } = {}
): string {
  const label = options.label || path.basename(filePath);
  let fileUrl = options.targetUrl;
  if (!fileUrl) {
    const normalized = path.resolve(filePath).replace(/\\/g, '/');
    fileUrl = options.urlPrefix
      ? `${options.urlPrefix}/${path.basename(filePath)}`
      : `file:///${normalized.startsWith('/') ? normalized.slice(1) : normalized}`;
  }

  return `[${label}](${fileUrl}) ${badgeInfo.badgeText}`;
}

/**
 * Inspect an artifact and its sidecar to produce a complete Provenance BadgeInfo.
 */
export async function getArtifactBadge(
  filePath: string,
  options: BadgeOptions = {}
): Promise<BadgeInfo> {
  const resolved = path.resolve(filePath);
  const artifactName = path.basename(resolved);
  const isScratch = resolved.includes(`${path.sep}scratch${path.sep}`) ||
    resolved.includes('/scratch/') ||
    resolved.includes(`${path.sep}tmp${path.sep}`) ||
    resolved.includes('/tmp/');

  if (!fsSync.existsSync(resolved)) {
    const badgeText = formatBadge('NOT_FOUND', {}, options);
    const colorDef = getStatusColor('NOT_FOUND');
    const ansiText = formatAnsiBadge('NOT_FOUND', {}, options);
    const html = formatHtmlBadge('NOT_FOUND', {}, options);
    return {
      status: 'NOT_FOUND',
      badgeText,
      ansiText,
      html,
      colorHex: colorDef.hex,
      markdown: `[${artifactName}] ${badgeText}`,
      shieldsUrl: getShieldsBadgeUrl('NOT_FOUND'),
      filePath: resolved,
      artifactName,
      error: `File not found: ${resolved}`
    };
  }

  // Canonicalize and compute SHA-256 hash
  const canonicalBytes = await ProvenanceEngine.canonicalizeFile(resolved);
  const currentHash = crypto.createHash('sha256').update(canonicalBytes).digest('hex');
  const shortHash = currentHash.slice(0, options.shortHashLen ?? 8);

  // Locate companion sidecar
  let sidecarPath = `${resolved}.provenance.json`;
  if (!fsSync.existsSync(sidecarPath)) {
    // Special check for package.json -> package.provenance.json in same directory
    if (artifactName === 'package.json') {
      const alt = path.join(path.dirname(resolved), 'package.provenance.json');
      if (fsSync.existsSync(alt)) {
        sidecarPath = alt;
      }
    }
  }

  // Case 1: No sidecar present
  if (!fsSync.existsSync(sidecarPath)) {
    const status: ProvenanceBadgeStatus = isScratch ? 'SCRATCH' : 'LIVING';
    const badgeText = formatBadge(status, { hash: currentHash }, options);
    const colorDef = getStatusColor(status);
    const ansiText = formatAnsiBadge(status, { hash: currentHash }, options);
    const html = formatHtmlBadge(status, { hash: currentHash }, options);
    const badgeInfo: BadgeInfo = {
      status,
      badgeText,
      ansiText,
      html,
      colorHex: colorDef.hex,
      markdown: '',
      shieldsUrl: getShieldsBadgeUrl(status, { shortHash }),
      filePath: resolved,
      artifactName,
      shortHash,
      fullHash: currentHash
    };
    badgeInfo.markdown = formatMarkdownLink(resolved, badgeInfo, { targetUrl: options.targetUrl });
    return badgeInfo;
  }

  // Case 2: Sidecar present - parse and verify
  try {
    const sidecarRaw = (await readRegularFile(sidecarPath, MAX_SIDECAR_BYTES)).toString('utf8');
    const sidecar = JSON.parse(sidecarRaw);
    validateSidecar(sidecar);

    // Hash check
    if (sidecar.sha256_at_last_write && sidecar.sha256_at_last_write !== currentHash) {
      const badgeText = formatBadge('MUTATED', { hash: currentHash }, options);
      const colorDef = getStatusColor('MUTATED');
      const ansiText = formatAnsiBadge('MUTATED', { hash: currentHash }, options);
      const html = formatHtmlBadge('MUTATED', { hash: currentHash }, options);
      const badgeInfo: BadgeInfo = {
        status: 'MUTATED',
        badgeText,
        ansiText,
        html,
        colorHex: colorDef.hex,
        markdown: '',
        shieldsUrl: getShieldsBadgeUrl('MUTATED', { shortHash }),
        filePath: resolved,
        artifactName,
        shortHash,
        fullHash: currentHash,
        error: `Sidecar recorded hash ${sidecar.sha256_at_last_write.slice(0, 12)}... does not match computed hash ${shortHash}...`
      };
      badgeInfo.markdown = formatMarkdownLink(resolved, badgeInfo, { targetUrl: options.targetUrl });
      return badgeInfo;
    }

    // Extract signer information
    const firstAtt = sidecar.attestations?.[0] || sidecar.envelope?.attestations?.[0];
    const rawSigner = firstAtt?.signer || sidecar.generator?.agent;
    const cleanSigner = extractShortSigner(rawSigner);
    let verifiedTimestamp: string | undefined;
    let verifiedTier: string | undefined;

    // Cryptographic signature check if public key provided
    if (options.publicKeyPem) {
      const verifyRes = await ProvenanceEngine.verifyDocument(resolved, options.publicKeyPem, { expectedScope: options.requiredScope });
      verifiedTimestamp = verifyRes.timestamp;
      verifiedTier = verifyRes.timestampTier;
      if (!verifyRes.verified) {
        const badgeText = formatBadge('INVALID_SIGNATURE', { hash: currentHash, signer: cleanSigner }, options);
        const colorDef = getStatusColor('INVALID_SIGNATURE');
        const ansiText = formatAnsiBadge('INVALID_SIGNATURE', { hash: currentHash, signer: cleanSigner }, options);
        const html = formatHtmlBadge('INVALID_SIGNATURE', { hash: currentHash, signer: cleanSigner }, options);
        const badgeInfo: BadgeInfo = {
          status: 'INVALID_SIGNATURE',
          badgeText,
          ansiText,
          html,
          colorHex: colorDef.hex,
          markdown: '',
          shieldsUrl: getShieldsBadgeUrl('INVALID_SIGNATURE', { signer: cleanSigner, shortHash }),
          filePath: resolved,
          artifactName,
          signer: rawSigner,
          shortHash,
          fullHash: currentHash,
          error: verifyRes.error
        };
        badgeInfo.markdown = formatMarkdownLink(resolved, badgeInfo, { targetUrl: options.targetUrl });
        return badgeInfo;
      }
    }

    const status: ProvenanceBadgeStatus = options.publicKeyPem ? 'SEALED' : 'HASH_ONLY';
    const badgeText = formatBadge(status, { hash: currentHash, signer: cleanSigner }, options);
    const colorDef = getStatusColor(status);
    const ansiText = formatAnsiBadge(status, { hash: currentHash, signer: cleanSigner }, options);
    const html = formatHtmlBadge(status, { hash: currentHash, signer: cleanSigner }, options);
    const badgeInfo: BadgeInfo = {
      status: status,
      badgeText,
      ansiText,
      html,
      colorHex: colorDef.hex,
      markdown: '',
      shieldsUrl: getShieldsBadgeUrl(status, { signer: cleanSigner, shortHash }),
      filePath: resolved,
      artifactName,
      signer: rawSigner,
      shortHash,
      fullHash: currentHash,
      tier: verifiedTier,
      timestamp: verifiedTimestamp
    };
    badgeInfo.markdown = formatMarkdownLink(resolved, badgeInfo, { targetUrl: options.targetUrl });
    return badgeInfo;
  } catch (err: any) {
    const badgeText = formatBadge('MUTATED', { hash: currentHash }, options);
    const colorDef = getStatusColor('MUTATED');
    const ansiText = formatAnsiBadge('MUTATED', { hash: currentHash }, options);
    const html = formatHtmlBadge('MUTATED', { hash: currentHash }, options);
    const badgeInfo: BadgeInfo = {
      status: 'MUTATED',
      badgeText,
      ansiText,
      html,
      colorHex: colorDef.hex,
      markdown: '',
      shieldsUrl: getShieldsBadgeUrl('MUTATED', { shortHash }),
      filePath: resolved,
      artifactName,
      shortHash,
      fullHash: currentHash,
      error: `Failed to parse sidecar: ${err.message}`
    };
    badgeInfo.markdown = formatMarkdownLink(resolved, badgeInfo, { targetUrl: options.targetUrl });
    return badgeInfo;
  }
}
