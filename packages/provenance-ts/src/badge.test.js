const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  formatBadge,
  formatMarkdownLink,
  getShieldsBadgeUrl,
  getArtifactBadge,
  ProvenanceEngine
} = require('../dist/index.js');

describe('Provenance Badge Module', () => {
  describe('formatBadge', () => {
    test('formats SEALED badge with signer and hash', () => {
      const badge = formatBadge('SEALED', { signer: 'Synthetic (Fixture)', hash: '9df0af4d29d0' });
      expect(badge).toBe('🛡️ [SEALED · Synthetic · 9df0af4d]');
    });

    test('formats SEALED badge in short style without signer', () => {
      const badge = formatBadge('SEALED', { signer: 'Synthetic', hash: '9df0af4d29d0' }, { style: 'short' });
      expect(badge).toBe('🛡️ [SEALED · 9df0af4d]');
    });

    test('formats LIVING, SCRATCH, MUTATED, and NOT_FOUND badges', () => {
      expect(formatBadge('LIVING')).toBe('📝 [UNSEALED · LIVING]');
      expect(formatBadge('SCRATCH')).toBe('⚡ [EPHEMERAL · SCRATCH]');
      expect(formatBadge('MUTATED')).toBe('🚨 [MUTATED · HASH MISMATCH]');
      expect(formatBadge('INVALID_SIGNATURE')).toBe('🚨 [INVALID SIGNATURE]');
      expect(formatBadge('NOT_FOUND')).toBe('❌ [NOT FOUND]');
    });

    test('formats ANSI color-coded badges when color is enabled', () => {
      const ansiSealed = formatBadge('SEALED', { signer: 'Synthetic', hash: '9df0af4d' }, { color: true });
      expect(ansiSealed).toContain('\x1b[1;32mSEALED · Synthetic · 9df0af4d\x1b[0m');

      const ansiLiving = formatBadge('LIVING', {}, { color: 'ansi' });
      expect(ansiLiving).toContain('\x1b[1;34mUNSEALED · LIVING\x1b[0m');

      const ansiMutated = formatBadge('MUTATED', {}, { color: true });
      expect(ansiMutated).toContain('\x1b[1;31mMUTATED · HASH MISMATCH\x1b[0m');

      const ansiScratch = formatBadge('SCRATCH', {}, { color: true });
      expect(ansiScratch).toContain('\x1b[1;33mEPHEMERAL · SCRATCH\x1b[0m');
    });

    test('formats inline HTML badge when html format is requested', () => {
      const htmlSealed = formatBadge('SEALED', { signer: 'Synthetic', hash: '9df0af4d' }, { format: 'html' });
      expect(htmlSealed).toContain('🛡️ <span class="provenance-badge-status"');
      expect(htmlSealed).toContain('#2ea44f');
      expect(htmlSealed).toContain('[SEALED · Synthetic · 9df0af4d]');

      const htmlMutated = formatBadge('MUTATED', {}, { color: 'html' });
      expect(htmlMutated).toContain('🚨 <span class="provenance-badge-status"');
      expect(htmlMutated).toContain('#cf222e');
      expect(htmlMutated).toContain('[MUTATED · HASH MISMATCH]');
    });
  });

  describe('getShieldsBadgeUrl', () => {
    test('generates valid shields.io URLs', () => {
      const sealedUrl = getShieldsBadgeUrl('SEALED', { signer: 'Synthetic', shortHash: '9df0af4d' });
      expect(sealedUrl).toContain('img.shields.io/badge/provenance-sealed');
      expect(sealedUrl).toContain('2ea44f');

      const livingUrl = getShieldsBadgeUrl('LIVING');
      expect(livingUrl).toContain('0969da');

      const mutatedUrl = getShieldsBadgeUrl('MUTATED');
      expect(mutatedUrl).toContain('cf222e');
    });
  });

  describe('formatMarkdownLink', () => {
    test('formats clickable markdown link with adjacent badge', () => {
      const badgeInfo = {
        status: 'SEALED',
        badgeText: '🛡️ [SEALED · Synthetic · 9df0af4d]',
        markdown: '',
        shieldsUrl: '',
        filePath: 'd:/Repos/README.md',
        artifactName: 'README.md'
      };
      const link = formatMarkdownLink('d:/Repos/README.md', badgeInfo);
      expect(link).toContain('[README.md](file:///');
      expect(link).toContain('🛡️ [SEALED · Synthetic · 9df0af4d]');
    });
  });

  describe('getArtifactBadge (filesystem integration)', () => {
    test('reports intentional unsealed release documentation', async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const readmePath = path.join(repoRoot, 'README.md');
      const badgeInfo = await getArtifactBadge(readmePath);

      expect(badgeInfo.status).toBe('LIVING');
      expect(badgeInfo.badgeText).toContain('UNSEALED');
      expect(badgeInfo.signer).toBeUndefined();
      expect(badgeInfo.shortHash).toBeDefined();
      expect(badgeInfo.markdown).toContain('[README.md](');
    });

    test('returns NOT_FOUND for non-existent file', async () => {
      const badgeInfo = await getArtifactBadge('/non/existent/file.md');
      expect(badgeInfo.status).toBe('NOT_FOUND');
      expect(badgeInfo.badgeText).toBe('❌ [NOT FOUND]');
    });

    test('identifies living workspace file without sidecar', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'provenance-test-living-'));
      const testFile = path.join(tempDir, 'active_code.ts');
      fs.writeFileSync(testFile, 'export const x = 1;', 'utf8');

      try {
        const badgeInfo = await getArtifactBadge(testFile);
        expect(['LIVING', 'SCRATCH']).toContain(badgeInfo.status);
        expect(badgeInfo.badgeText).toBe(badgeInfo.status === 'LIVING' ? '📝 [UNSEALED · LIVING]' : '⚡ [EPHEMERAL · SCRATCH]');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    test('identifies ephemeral scratch file in scratch directory', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'provenance-test-scratch-'));
      const scratchDir = path.join(tempDir, 'scratch');
      fs.mkdirSync(scratchDir);
      const scratchFile = path.join(scratchDir, 'one_off.py');
      fs.writeFileSync(scratchFile, 'print("scratch")', 'utf8');

      try {
        const badgeInfo = await getArtifactBadge(scratchFile);
        expect(badgeInfo.status).toBe('SCRATCH');
        expect(badgeInfo.badgeText).toBe('⚡ [EPHEMERAL · SCRATCH]');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    test('fails closed with MUTATED when content is modified after sidecar creation', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'provenance-test-mutated-'));
      const targetFile = path.join(tempDir, 'document.md');
      fs.writeFileSync(targetFile, '# Original Document\n', 'utf8');

      const sidecarPath = targetFile + '.provenance.json';
      const sidecar = {
        standard: 'Moonglade Provenance Attestation Bundle v2',
        artifact: 'document.md',
        sha256_at_last_write: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
        attestations: []
      };
      fs.writeFileSync(sidecarPath, JSON.stringify(sidecar), 'utf8');

      try {
        const badgeInfo = await getArtifactBadge(targetFile);
        expect(badgeInfo.status).toBe('MUTATED');
        expect(badgeInfo.badgeText).toBe('🚨 [MUTATED · HASH MISMATCH]');
        expect(badgeInfo.error).toBeDefined();
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });
});
